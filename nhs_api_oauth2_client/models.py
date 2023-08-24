from __future__ import annotations

from typing import Literal, Optional, Dict
from pydantic import BaseModel
from time import time
from math import floor


class BaseToken(BaseModel):
    token_type: Literal["Bearer"] = "Bearer"
    issued_at: int
    expires_in: int

    @property
    def expired(self) -> bool:
        """
        Returns True if the token is within 15 seconds of its expiry time.
        """
        expiry_time_buffer = 15  # Buffer time in seconds

        current_time = time()
        expiry_time = self.issued_at + self.expires_in - expiry_time_buffer

        return current_time >= expiry_time


class AccessToken(BaseToken):
    access_token: str


class RefreshToken(BaseToken):
    refresh_token: str
    refresh_count: int


class TokenSet(BaseModel):
    access_token: AccessToken
    refresh_token: Optional[RefreshToken]

    @staticmethod
    def from_response(response: Dict[str]) -> Credentials:
        """
        Converts the response from the /oauth2/token endpoint into a TokenSet
        """
        issue_time = floor(time())

        token_set = TokenSet(
            access_token=AccessToken(
                issued_at=issue_time,
                access_token=response["access_token"],
                expires_in=response["expires_in"],
            ),
            refresh_token=None,
        )

        if refresh_token := response.get("refresh_token"):
            token_set.refresh_token = RefreshToken(
                issued_at=issue_time,
                refresh_token=refresh_token,
                refresh_count=response["refresh_count"],
                expires_in=response["refresh_token_expires_in"],
            )

        return token_set


class Credentials(BaseModel):
    """Model to hold API-M App credentials"""

    base_url: str  # The base URL of the API-M authentication service
    api_key: str  # API-M App API Key
    api_secret: str  # API-M App API Secret
    private_key: str  # Private key associated with the app's public key
    private_key_id: str  # The ID of the public/private keypair
