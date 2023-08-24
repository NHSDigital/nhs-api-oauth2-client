"""
Created 22/08/2023

Tests for API-M Authentication helper classes
"""

import unittest
from pathlib import Path
from unittest.mock import Mock, patch
import json

import jwt
import requests_mock
from freezegun import freeze_time
from requests import Response
from requests.exceptions import ConnectionError as RequestsConnectionError
from parameterized import parameterized
from nhs_api_oauth2_client.authenticators.base_authenticator import (
    BaseAPIMAuthenticator,
)
from nhs_api_oauth2_client.models import Credentials, TokenSet
from nhs_api_oauth2_client.exceptions import (
    RequestError,
    InvalidRequestError,
    PublicKeyError,
)

from tests.utilities import get_resource

PUBLIC_KEY = get_resource("keys/local-1.pem.pub")
PRIVATE_KEY = get_resource("keys/local-1.pem")

class InheritedBaseAPIMAuthenticator(BaseAPIMAuthenticator):
    """Inherited class for unit-testing"""

    def authenticate(self) -> TokenSet:
        """Mock authenticate"""
        return super().authenticate()


class BaseAPIMAuthenticatorTest(unittest.TestCase):
    """Tests for the BaseAPIMAuthenticator class"""

    def setUp(self) -> None:
        self.mock_credentials = Credentials(
            base_url="https://api.service.nhs.uk/oauth2",
            api_key="test_api_key",
            api_secret="test_api_secret",
            private_key=PRIVATE_KEY,
            private_key_id="local-1",
        )

        self.authenticator = InheritedBaseAPIMAuthenticator(self.mock_credentials)

    def test_authenticate_raises_notimplementederror(self):
        """Test authenticate raises NotImplementedError"""

        with self.assertRaises(NotImplementedError) as error:
            self.authenticator.authenticate()

        self.assertIsInstance(error.exception, NotImplementedError)

    @freeze_time("2023-08-24")
    @patch(
        "nhs_api_oauth2_client.authenticators.base_authenticator.uuid4",
        lambda: "mock-uuid4",
    )
    def test_create_client_assertion(self):
        """
        Test _create_client_assertion creates client JWT with the correct
        values and private key details
        """

        expected_headers = {"alg": "RS512", "kid": "local-1", "typ": "JWT"}

        expected_payload = {
            "iss": "test_api_key",
            "sub": "test_api_key",
            "aud": "https://api.service.nhs.uk/oauth2/token",
            "jti": "mock-uuid4",
            "exp": 1692835500,
        }

        token = self.authenticator._create_client_assertion()

        decoded_headers = jwt.get_unverified_header(token)

        decoded_token = jwt.decode(
            token,
            key=PUBLIC_KEY,
            algorithms=["RS512"],
            audience="https://api.service.nhs.uk/oauth2/token",
            options={"verify_exp": False},
        )

        self.assertDictEqual(expected_headers, decoded_headers)
        self.assertDictEqual(expected_payload, decoded_token)

    @freeze_time("2023-08-24")
    @requests_mock.Mocker()
    def test_call_token_endpoint_happy_app_restricted(
        self, mocker: requests_mock.Mocker
    ):
        """
        Test _call_token_endpoint calls OAuth2 token endpoint and returns an
        access token for the application-restricted pattern
        """

        token_mock = mocker.post(
            url="https://api.service.nhs.uk/oauth2/token",
            status_code=200,
            json={
                "access_token": "mock_access_token",
                "expires_in": "599",
                "token_type": "Bearer",
            },
        )

        token = self.authenticator._call_token_endpoint(mock_key="mock_value")

        self.assertTrue(token_mock.called_once)

        self.assertEqual(token_mock.last_request.path, "/oauth2/token")
        self.assertEqual(token_mock.last_request.text, "mock_key=mock_value")
        self.assertEqual(token_mock.last_request.timeout, 30)

        self.assertIsInstance(token, TokenSet)

        self.assertEqual(token.access_token.token_type, "Bearer")
        self.assertEqual(token.access_token.access_token, "mock_access_token")
        self.assertEqual(token.access_token.issued_at, 1692835200)
        self.assertEqual(token.access_token.expires_in, 599)
        self.assertFalse(token.access_token.expired)

        self.assertIsNone(token.refresh_token)

    @freeze_time("2023-08-24")
    @requests_mock.Mocker()
    def test_call_token_endpoint_happy_user_restricted(
        self, mocker: requests_mock.Mocker
    ):
        """
        Test _call_token_endpoint calls OAuth2 token endpoint and returns an
        access token for the application-restricted pattern
        """
        token_mock = mocker.post(
            url="https://api.service.nhs.uk/oauth2/token",
            status_code=200,
            json={
                "access_token": "mock_access_token",
                "expires_in": "599",
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "refresh_count": "0",
                "refresh_token": "mock_refresh_token",
                "refresh_token_expires_in": "43199",
                "token_type": "Bearer",
            },
        )

        token = self.authenticator._call_token_endpoint(mock_key="mock_value")

        self.assertTrue(token_mock.called_once)
        self.assertEqual(token_mock.last_request.path, "/oauth2/token")
        self.assertEqual(token_mock.last_request.text, "mock_key=mock_value")
        self.assertEqual(token_mock.last_request.timeout, 30)

        self.assertIsInstance(token, TokenSet)

        self.assertEqual(token.access_token.token_type, "Bearer")
        self.assertEqual(token.access_token.access_token, "mock_access_token")
        self.assertEqual(token.access_token.issued_at, 1692835200)
        self.assertEqual(token.access_token.expires_in, 599)
        self.assertFalse(token.access_token.expired)

        self.assertEqual(token.refresh_token.token_type, "Bearer")
        self.assertEqual(token.refresh_token.refresh_token, "mock_refresh_token")
        self.assertEqual(token.refresh_token.issued_at, 1692835200)
        self.assertEqual(token.refresh_token.expires_in, 43199)
        self.assertFalse(token.refresh_token.expired)

    @parameterized.expand(
        [
            (400, "grant_type is missing"),
            (400, "grant_type is invalid"),
            (
                400,
                "Missing or invalid client_assertion_type - must be 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'",
            ),
            (400, "Missing client_assertion"),
            (400, "Malformed JWT in client_assertion"),
            (400, "Missing 'kid' header in client_assertion JWT"),
            (
                401,
                "Invalid 'kid' header in client_assertion JWT - no matching public key",
            ),
            (400, "Invalid 'typ' header in client_assertion JWT - must be 'JWT'"),
            (400, "Missing 'alg' header in client_assertion JWT"),
            (
                400,
                "Invalid 'alg' header in client_assertion JWT - unsupported JWT algorithm - must be 'RS512'",
            ),
            (401, "Invalid 'iss'/'sub' claims in client_assertion JWT"),
            (400, "Missing or non-matching 'iss'/'sub' claims in client_assertion JWT"),
            (400, "Missing 'jti' claim in client_assertion JWT"),
            (400, "Non-unique 'jti' claim in client_assertion JWT"),
            (
                400,
                "Invalid 'jti' claim in client_assertion JWT - must be a unique string value such as a GUID",
            ),
            (401, "Missing or invalid 'aud' claim in client_assertion JWT"),
            (400, "Missing 'exp' claim in client_assertion JWT"),
            (400, "Invalid 'exp' claim in client_assertion JWT - JWT has expired"),
            (
                400,
                "Invalid 'exp' claim in client_assertion JWT - more than 5 minutes in future",
            ),
            (400, "Invalid 'exp' claim in client_assertion JWT - must be an integer"),
            (401, "JWT signature verification failed"),
            (
                403,
                "You need to register a public key to use this authentication method - please contact support to configure",
            ),
            (403, "The JWKS endpoint for your client_assertion can not be reached"),
            (400, "Missing subject_token"),
            (400, "subject_token is invalid"),
            (400, "Missing 'kid' header in subject_token JWT"),
            (401, "Invalid 'kid' header in subject_token JWT - no matching public key"),
            (400, "Invalid 'typ' header in subject_token JWT - must be 'JWT'"),
            (400, "Missing 'alg' header in subject_token JWT"),
            (400, "Missing 'iss' claim in subject_token JWT"),
            (400, "Missing aud claim in subject_token"),
            (400, "Missing 'exp' claim in subject_token JWT"),
            (400, "Invalid 'exp' claim in subject_token JWT - JWT has expired"),
            (400, "Invalid 'exp' claim in subject_token JWT - must be an integer"),
        ],
    )
    @requests_mock.Mocker()
    def test_call_token_endpont_invalid_response(
        self, status_code: int, error_message: str, mocker: requests_mock.Mocker
    ):
        """
        Test that _call_token_endpoint writes a log and raises an
        AuthenticationError on a RequestException being raised
        """
        mocker.post(
            url="https://api.service.nhs.uk/oauth2/token",
            status_code=status_code,
            json={
                "error": "invalid_request",
                "error_description": error_message,
                "message_id": "rrt-9008934617930251634-a-geu2-9503-12530957-1",
            },
        )

        with self.assertRaises(InvalidRequestError) as error:
            self.authenticator._call_token_endpoint(some_key="some_value")

        self.assertEqual(error.exception.status_code, status_code)
        self.assertEqual(error.exception.error_code, "invalid_request")
        self.assertEqual(error.exception.error_message, error_message)
        self.assertEqual(
            error.exception.message_id, "rrt-9008934617930251634-a-geu2-9503-12530957-1"
        )

        expected_error_message = f"{status_code} error response was encountered - invalid_request : {error_message} : MessageID=rrt-9008934617930251634-a-geu2-9503-12530957-1"

        self.assertEqual(error.exception.args[0], expected_error_message)

    @parameterized.expand(
        [
            (401, "JWT signature verification failed"),
            (
                403,
                "You need to register a public key to use this authentication method - please contact support to configure",
            ),
            (
                403,
                "The JWKS endpoint for your client_assertion can not be reached",
            ),
        ]
    )
    @requests_mock.Mocker()
    def test_call_token_endpont_public_key_error(
        self,
        status_code: int,
        error_message: str,
        mocker: requests_mock.Mocker,
    ):
        """
        Test that _call_token_endpoint writes a log and raises an
        AuthenticationError on a RequestException being raised
        """

        mocker.post(
            url="https://api.service.nhs.uk/oauth2/token",
            status_code=status_code,
            json={
                "error": "public_key error",
                "error_description": error_message,
                "message_id": "rrt-9008934617930251634-a-geu2-9503-12530957-1",
            },
        )

        with self.assertRaises(PublicKeyError) as error:
            self.authenticator._call_token_endpoint(some_key="some_value")

        self.assertEqual(error.exception.status_code, status_code)
        self.assertEqual(error.exception.error_code, "public_key error")
        self.assertEqual(error.exception.error_message, error_message)
        self.assertEqual(
            error.exception.message_id, "rrt-9008934617930251634-a-geu2-9503-12530957-1"
        )

        expected_error_message = f"{status_code} error response was encountered - public_key error : {error_message} : MessageID=rrt-9008934617930251634-a-geu2-9503-12530957-1"

        self.assertEqual(error.exception.args[0], expected_error_message)

    @requests_mock.Mocker()
    def test_call_token_endpont_request_exception(self, mocker: requests_mock.Mocker):
        """
        Test that _call_token_endpoint writes a log and raises an
        AuthenticationError on a RequestException being raised
        """
        mocker.post(
            url="https://api.service.nhs.uk/oauth2/token",
            exc=RequestsConnectionError("Connection dropped"),
        )

        with self.assertRaises(RequestError) as error:
            self.authenticator._call_token_endpoint(some_key="some_value")


        self.assertEqual(error.exception.status_code, "unknown")
        self.assertEqual(error.exception.error_code, "unknown")
        self.assertEqual(error.exception.error_message, "Connection dropped")
        self.assertEqual(error.exception.message_id, "unknown")


    @freeze_time("2023-08-24")
    @requests_mock.Mocker()
    def test_call_token_endpont_generic_exception(self, mocker: requests_mock.Mocker):
        """
        Test that _call_token_endpoint writes a log and raises an
        AuthenticationError on a RequestException being raised
        """

        mocker.post(
            url="https://api.service.nhs.uk/oauth2/token",
            exc=Exception("JSON Decode Error"),
        )

        with self.assertRaises(RequestError) as error:
            self.authenticator._call_token_endpoint(some_key="some_value")

        self.assertEqual(error.exception.status_code, "unknown")
        self.assertEqual(error.exception.error_code, "unknown")
        self.assertEqual(error.exception.error_message, "JSON Decode Error")
        self.assertEqual(error.exception.message_id, "unknown")

    def test_raise_from_request_invalid_request(self):
        """
        Test that _raise_from_request raises an InvalidRequestError if
        invalid_request is returned in the response
        """

        response = Response()
        response.status_code = 400
        response._content = json.dumps({
            "error": "invalid_request",
            "error_description": "something went wrong",
            "message_id": "rrt-9008934617930251634-a-geu2-9503-12530957-1",
        }).encode("utf-8")

        with self.assertRaises(InvalidRequestError) as error:
            self.authenticator._raise_from_response(response)

        self.assertEqual(error.exception.status_code, 400)
        self.assertEqual(error.exception.error_code, "invalid_request")
        self.assertEqual(error.exception.error_message, "something went wrong")
        self.assertEqual(error.exception.message_id, "rrt-9008934617930251634-a-geu2-9503-12530957-1")


    def test_raise_from_request_public_key_error(self):
        """
        Test that _raise_from_request raises an PublicKeyError if
        public_key error is returned in the response
        """

        response = Response()
        response.status_code = 401
        response._content = json.dumps({
            "error": "public_key error",
            "error_description": "JWT signature verification failed",
            "message_id": "rrt-9008934617930251634-a-geu2-9503-12530957-1",
        }).encode("utf-8")

        with self.assertRaises(PublicKeyError) as error:
            self.authenticator._raise_from_response(response)

        self.assertEqual(error.exception.status_code, 401)
        self.assertEqual(error.exception.error_code, "public_key error")
        self.assertEqual(error.exception.error_message, "JWT signature verification failed")
        self.assertEqual(error.exception.message_id, "rrt-9008934617930251634-a-geu2-9503-12530957-1")

    def test_raise_from_request_other_error(self):
        """
        Test that _raise_from_request raises an RequestError if
        any other error is returned in the response
        """

        response = Response()
        response.status_code = 401
        response._content = json.dumps({
            "error": "internal_server_error",
            "error_description": "Something went wrong",
            "message_id": "rrt-9008934617930251634-a-geu2-9503-12530957-1",
        }).encode("utf-8")

        with self.assertRaises(RequestError) as error:
            self.authenticator._raise_from_response(response)

        self.assertEqual(error.exception.status_code, 401)
        self.assertEqual(error.exception.error_code, "internal_server_error")
        self.assertEqual(error.exception.error_message, "Something went wrong")
        self.assertEqual(error.exception.message_id, "rrt-9008934617930251634-a-geu2-9503-12530957-1")

    def test_raise_from_request_no_error_code(self):
        """
        Test that _raise_from_request raises an RequestError if
        no error code is returned in the response
        """

        response = Response()
        response.status_code = 401
        response._content = json.dumps({}).encode("utf-8")

        with self.assertRaises(RequestError) as error:
            self.authenticator._raise_from_response(response)

        self.assertEqual(error.exception.status_code, 401)
        self.assertEqual(error.exception.error_code, "unknown")
        self.assertEqual(error.exception.error_message, 'Invalid body: {}')
        self.assertIsNone(error.exception.message_id)

    def test_raise_from_request_invalid_json(self):
        """
        Test that _raise_from_request raises an RequestError if
        the body is not valid JSON
        """

        response = Response()
        response.status_code = 401
        response._content = "{'iamnot: ''valid json';}".encode("utf-8")

        with self.assertRaises(RequestError) as error:
            self.authenticator._raise_from_response(response)

        self.assertEqual(error.exception.status_code, 401)
        self.assertEqual(error.exception.error_code, "unknown")
        self.assertEqual(error.exception.error_message, "Invalid body: {'iamnot: ''valid json';}")
        self.assertIsNone(error.exception.message_id)


# class ApplicationRestrictedAuthenticatorTest(unittest.TestCase):
#     """
#     Tests for the ApplicationRestrictedAuthenticator class
#     """

#     def setUp(self) -> None:
#         self.mock_log_object = FlaskSessionMockLogObject()
#         self.mock_credentials = APIMAuthenticationCredentials(
#             base_url="https://api.service.nhs.uk/oauth2",
#             api_key="test_api_key",
#             api_secret="test_api_secret",
#             private_key=PRIVATE_KEY,
#             private_key_id="local-1"
#         )

#         self.authenticator = ApplicationRestrictedAuthenticator(
#             logger=self.mock_log_object,
#             credentials=self.mock_credentials
#         )

#     @patch("ncrs.utilities.apimauthentication.requests.post")
#     @patch("ncrs.utilities.apimauthentication.uuid4", lambda: "mock-uuid4")
#     @patch("ncrs.utilities.apimauthentication.time", lambda: 1692700000)
#     def test_get_access_token_new_access_token(self, post_mock: Mock):
#         """
#         Test get_access_token returns a new access token if no token is cached
#         """
#         self.authenticator._session.get_token = Mock(return_value=None)
#         self.authenticator._session.set_token = Mock()

#         mock_response = Response()
#         mock_response.status_code = 200
#         mock_response.raw = BytesIO(json.dumps({
#             'access_token': 'mock_new_access_token',
#             'expires_in': '599',
#             'token_type': 'Bearer'
#         }).encode("utf-8"))
#         post_mock.return_value = mock_response

#         token = self.authenticator.get_access_token()

#         self.assertEqual(token, "mock_new_access_token")
#         self.assertTrue(self.mock_log_object.was_value_logged(
#             "NCRSAPIM0001",
#             "pattern",
#             "ApplicationRestricted"
#         ))

#         self.assertFalse(self.mock_log_object.was_logged("NCRSAPIM0002"))
#         self.assertTrue(self.mock_log_object.was_logged("NCRSAPIM0007a"))

#         post_mock.assert_called_once_with(
#             url="https://api.service.nhs.uk/oauth2/token",
#             data={
#                 'grant_type': 'client_credentials',
#                 'client_assertion_type':
#                     'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
#                 'client_assertion': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiIsImtpZCI6ImxvY2FsLTEifQ.eyJpc3MiOiJ0ZXN0X2FwaV9rZXkiLCJzdWIiOiJ0ZXN0X2FwaV9rZXkiLCJhdWQiOiJodHRwczovL2FwaS5zZXJ2aWNlLm5ocy51ay9vYXV0aDIvdG9rZW4iLCJqdGkiOiJtb2NrLXV1aWQ0IiwiZXhwIjoxNjkyNzAwMzAwfQ.CWMAcJ8LfWbsDieqlNbNcCHO0s3y70pMmEb9hLdiaBrHhW1x-9rDXxvbmfxDwQFcZIm9GfH_ubtXKGV1wPbHtOj1VnGe2Nb74-ddvOfOJMxgFeDR5KTkvWsrUZQW0Ljrtq9c7PHSm0bjbBT81QvswJ6Ztk_q903l2-5aWa_5_hfFoZqi5CV-1l0un7SP7CqF5jQSi9H6UGAFL68fFozwE2ohr7warhHfKHm4SIKFq3fkUDrZ2k3nrlkLSBZRW4FfTBnJg77Q2eLnfORnx-BIEbzE_3EtfPtqzaSSyWf-MLAeEqBZnHEiBtFm7CZURTjP_v-iyzEz0UMljYZGg4I2lUBTQ80gKgpi6QxjygU-Byc47HZ11kfHZ_tvWU6KR_sw41XLCOlH6sW-xzU4OvuYZeaOCPvQTjNmU_wKeXl1x9oxA8GcIaDiF436LIosNHPMmTCvY_WpdpNjHul8eoWsUqhouw_41EYIoScodgzLrfaf7AXp-37xJzMpuaR46TRAPtzNNMPk6BohE1AUE1m6AGtSW57hzP9l4PD741DUDAqQf12dFlV-aUcallYmA3nb99Z9xBqDLNlF25vhnSFNGWxUO7bOMh2rSjG8Yn2i6tXkP7vgFuJQkQOIRahNP5kJp8rmhSo7z5-yyXO9drP2rZUTDbNwcGn9be33TsOslRw'  # noqa: E501  pylint: disable=line-too-long
#             },
#             headers={
#                 "Content-Type": "application/x-www-form-urlencoded"
#             },
#             timeout=30
#         )

#         self.assertTrue(self.mock_log_object.was_logged("NCRSAPIM0008"))

#     def test_get_access_token_cached_access_token(self):
#         """
#         Test get_access_token returns the cached access token if present
#         """
#         mock_token = BearerToken(
#             token_type="Bearer",
#             access_token="mock_cached_access_token",
#             issued_time=time(),
#             expires_in=599,
#         )

#         self.authenticator._session.get_token = Mock(return_value=mock_token)

#         token = self.authenticator.get_access_token()

#         self.assertEqual(token, "mock_cached_access_token")

#         self.assertTrue(self.mock_log_object.was_value_logged(
#             "NCRSAPIM0001",
#             "pattern",
#             "ApplicationRestricted"
#         ))

#         self.assertTrue(self.mock_log_object.was_logged("NCRSAPIM0002"))
#         self.assertFalse(self.mock_log_object.was_logged("NCRSAPIM0007a"))
#         self.assertFalse(self.mock_log_object.was_logged("NCRSAPIM0008"))


# class UserRestrictedAuthenticatorTest(unittest.TestCase):
#     """
#     Tests for the UserRestrictedAuthenticator class
#     """

#     def setUp(self) -> None:
#         self.mock_log_object = FlaskSessionMockLogObject()
#         self.mock_credentials = APIMAuthenticationCredentials(
#             base_url="https://api.service.nhs.uk/oauth2",
#             api_key="test_api_key",
#             api_secret="test_api_secret",
#             private_key=PRIVATE_KEY,
#             private_key_id="local-1"
#         )

#         self.authenticator = UserRestrictedAuthenticator(
#             logger=self.mock_log_object,
#             credentials=self.mock_credentials,
#             subject_token="mock_subject_token"
#         )

#     @patch("ncrs.utilities.apimauthentication.requests.post")
#     @patch("ncrs.utilities.apimauthentication.uuid4", lambda: "mock-uuid4")
#     @patch("ncrs.utilities.apimauthentication.time", lambda: 1692700000)
#     def test_get_access_token_new_access_token(self, post_mock: Mock):
#         """
#         Test get_access_token returns a new access token if no token is cached
#         """
#         self.authenticator._session.get_token = Mock(return_value=None)
#         self.authenticator._session.set_token = Mock()

#         mock_response = Response()
#         mock_response.status_code = 200
#         mock_response.raw = BytesIO(json.dumps({
#             "access_token": "mock_new_access_token",
#             "expires_in": "599",
#             "issued_token_type":
#                 "urn:ietf:params:oauth:token-type:access_token",
#             "refresh_count": "0",
#             "refresh_token": "mock_new_refresh_token",
#             "refresh_token_expires_in": "43199",
#             "token_type": "Bearer"
#         }).encode("utf-8"))

#         post_mock.return_value = mock_response

#         token = self.authenticator.get_access_token()

#         self.assertEqual(token, "mock_new_access_token")
#         self.assertTrue(self.mock_log_object.was_value_logged(
#             "NCRSAPIM0001",
#             "pattern",
#             "UserRestricted"
#         ))

#         self.assertFalse(self.mock_log_object.was_logged("NCRSAPIM0002"))
#         self.assertTrue(self.mock_log_object.was_logged("NCRSAPIM0007b"))

#         post_mock.assert_called_once_with(
#             url="https://api.service.nhs.uk/oauth2/token",
#             data={
#                 "subject_token": "mock_subject_token",
#                 "client_assertion": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiIsImtpZCI6ImxvY2FsLTEifQ.eyJpc3MiOiJ0ZXN0X2FwaV9rZXkiLCJzdWIiOiJ0ZXN0X2FwaV9rZXkiLCJhdWQiOiJodHRwczovL2FwaS5zZXJ2aWNlLm5ocy51ay9vYXV0aDIvdG9rZW4iLCJqdGkiOiJtb2NrLXV1aWQ0IiwiZXhwIjoxNjkyNzAwMzAwfQ.CWMAcJ8LfWbsDieqlNbNcCHO0s3y70pMmEb9hLdiaBrHhW1x-9rDXxvbmfxDwQFcZIm9GfH_ubtXKGV1wPbHtOj1VnGe2Nb74-ddvOfOJMxgFeDR5KTkvWsrUZQW0Ljrtq9c7PHSm0bjbBT81QvswJ6Ztk_q903l2-5aWa_5_hfFoZqi5CV-1l0un7SP7CqF5jQSi9H6UGAFL68fFozwE2ohr7warhHfKHm4SIKFq3fkUDrZ2k3nrlkLSBZRW4FfTBnJg77Q2eLnfORnx-BIEbzE_3EtfPtqzaSSyWf-MLAeEqBZnHEiBtFm7CZURTjP_v-iyzEz0UMljYZGg4I2lUBTQ80gKgpi6QxjygU-Byc47HZ11kfHZ_tvWU6KR_sw41XLCOlH6sW-xzU4OvuYZeaOCPvQTjNmU_wKeXl1x9oxA8GcIaDiF436LIosNHPMmTCvY_WpdpNjHul8eoWsUqhouw_41EYIoScodgzLrfaf7AXp-37xJzMpuaR46TRAPtzNNMPk6BohE1AUE1m6AGtSW57hzP9l4PD741DUDAqQf12dFlV-aUcallYmA3nb99Z9xBqDLNlF25vhnSFNGWxUO7bOMh2rSjG8Yn2i6tXkP7vgFuJQkQOIRahNP5kJp8rmhSo7z5-yyXO9drP2rZUTDbNwcGn9be33TsOslRw",  # noqa: E501  pylint: disable=line-too-long
#                 "subject_token_type":
#                     "urn:ietf:params:oauth:token-type:id_token",
#                 "client_assertion_type":
#                     "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
#                 "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"
#             },
#             headers={
#                 "Content-Type": "application/x-www-form-urlencoded"
#             },
#             timeout=30
#         )

#         self.assertTrue(self.mock_log_object.was_logged("NCRSAPIM0008"))

#     def test_get_access_token_cached_access_token(self):
#         """
#         Test get_access_token returns the cached access token if present
#         """
#         mock_token = BearerToken(
#             token_type="Bearer",
#             access_token="mock_cached_access_token",
#             issued_time=time(),
#             expires_in=599,
#             refresh_token="mock_cached_refresh_token",
#             refresh_token_expires_in=43199
#         )

#         self.authenticator._session.get_token = Mock(return_value=mock_token)

#         token = self.authenticator.get_access_token()

#         self.assertEqual(token, "mock_cached_access_token")
#         self.assertTrue(self.mock_log_object.was_value_logged(
#             "NCRSAPIM0001",
#             "pattern",
#             "UserRestricted"
#         ))

#         self.assertTrue(self.mock_log_object.was_logged("NCRSAPIM0002"))
#         self.assertFalse(self.mock_log_object.was_logged("NCRSAPIM0008"))

#     @patch("ncrs.utilities.apimauthentication.requests.post")
#     @patch("ncrs.utilities.apimauthentication.uuid4", lambda: "mock-uuid4")
#     @patch("ncrs.utilities.apimauthentication.time", lambda: 1692700000)
#     @patch("ncrs.domain.session.apimtokens.time", lambda: 1692700000)
#     def test_get_access_token_renew_access_token(self, post_mock: Mock):
#         """
#         Test get_access_token returns a renewed access token if a valid
#         refresh token is present
#         """
#         mock_token = BearerToken(
#             token_type="Bearer",
#             access_token="mock_old_access_token",
#             issued_time=1692699400,
#             expires_in=599,
#             refresh_token="mock_refresh_token",
#             refresh_token_expires_in=43199
#         )

#         self.authenticator._session.get_token = Mock(return_value=mock_token)
#         self.authenticator._session.set_token = Mock()

#         mock_response = Response()
#         mock_response.status_code = 200
#         mock_response.raw = BytesIO(json.dumps({
#             "access_token": "mock_renewed_access_token",
#             "expires_in": "599",
#             "issued_token_type":
#                 "urn:ietf:params:oauth:token-type:access_token",
#             "refresh_count": "0",
#             "refresh_token": "mock_renewed_refresh_token",
#             "refresh_token_expires_in": "43199",
#             "token_type": "Bearer"
#         }).encode("utf-8"))

#         post_mock.return_value = mock_response

#         token = self.authenticator.get_access_token()

#         self.assertEqual(token, "mock_renewed_access_token")
#         self.assertTrue(self.mock_log_object.was_value_logged(
#             "NCRSAPIM0001",
#             "pattern",
#             "UserRestricted"
#         ))

#         self.assertFalse(self.mock_log_object.was_logged("NCRSAPIM0002"))
#         self.assertTrue(self.mock_log_object.was_logged("NCRSAPIM0007c"))

#         post_mock.assert_called_once_with(
#             url="https://api.service.nhs.uk/oauth2/token",
#             data={
#                 "grant_type": "refresh_token",
#                 "refresh_token": "mock_refresh_token",
#                 "client_id": "test_api_key",
#                 "client_secret": "test_api_secret"
#             },
#             headers={
#                 "Content-Type": "application/x-www-form-urlencoded"
#             },
#             timeout=30
#         )

#         self.assertTrue(self.mock_log_object.was_logged("NCRSAPIM0008"))


if __name__ == "__main__":
    unittest.main()
