"""
Created 24/08/2023

Base API-M Authenticator
"""
from abc import ABC, abstractmethod
from math import floor
from time import time
from uuid import uuid4
from typing import NoReturn

import jwt
import requests

from nhs_api_oauth2_client.exceptions import (
    RequestError,
    InvalidRequestError,
    PublicKeyError,
)
from nhs_api_oauth2_client.models import Credentials, TokenSet


class BaseAPIMAuthenticator(ABC):
    """
    Base API-M Authenticator

    To be inherited and expanded by child classes
    """

    # pylint:disable=too-few-public-methods

    def __init__(self, credentials: Credentials):
        self._credentials = credentials

    @abstractmethod
    def authenticate(self) -> TokenSet:
        """
        Get a valid access token for calling an API-M API

        To be implemented by child classes
        """
        raise NotImplementedError()
        

    def _create_client_assertion(self) -> str:
        """
        Creates a new client assertion JWT used for authenticating the
        application against the API-M identity service
        """
        client_assertion = jwt.encode(
            headers={"kid": self._credentials.private_key_id},
            payload={
                "iss": self._credentials.api_key,
                "sub": self._credentials.api_key,
                "aud": self._oauth2_token_url,
                "jti": str(uuid4()),
                "exp": int(time()) + 300,
            },
            algorithm="RS512",
            key=self._credentials.private_key,
        )

        return client_assertion

    def _call_token_endpoint(self, **body) -> TokenSet:
        """
        Make a request to the API-M OAuth Token endpoint to retrieve a
        new access token
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        try:
            response = requests.post(
                url=self._oauth2_token_url, data=body, headers=headers, timeout=30
            )

        except Exception as exception:
            raise RequestError(
                status_code="unknown",
                error_code="unknown",
                error_message=str(exception),
                message_id="unknown"
            ) from exception

        if not response.ok:
            self._raise_from_response(response)

        return TokenSet.from_response(response.json())

    @staticmethod
    def _raise_from_response(response: requests.Response) -> NoReturn:
        """
        Raise a RequestError exception from the response returned from API-M
        """
        try:
            body = response.json()
            error_code = body.get("error")

        except Exception:
            raise RequestError(
                status_code=response.status_code,
                error_code="unknown",
                error_message=f"Invalid body: {response.text}",
                message_id=None
            )
    
        if not error_code:
            raise RequestError(
                status_code=response.status_code,
                error_code="unknown",
                error_message=f"Invalid body: {response.text}",
                message_id=body.get("message_id")
            )

        match error_code:
            case "invalid_request":
                raise InvalidRequestError(
                    status_code=response.status_code,
                    error_code=error_code,
                    error_message=body.get("error_description"),
                    message_id=body.get("message_id"),
                )

            case "public_key error":
                raise PublicKeyError(
                    status_code=response.status_code,
                    error_code=error_code,
                    error_message=body.get("error_description"),
                    message_id=body.get("message_id"),
                )
            
            case _:
                raise RequestError(
                    status_code=response.status_code,
                    error_code=error_code,
                    error_message=body.get("error_description"),
                    message_id=body.get("message_id")
                )
        
        

    @property
    def _oauth2_token_url(self) -> str:
        """The API-M Identity Service OAuth2 Token URL"""

        return f"{self._credentials.base_url}/token"
