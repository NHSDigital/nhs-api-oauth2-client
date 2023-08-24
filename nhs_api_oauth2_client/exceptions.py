from typing import Optional, Literal


class RequestError(Exception):
    """"""
    def __init__(
        self,
        status_code: int,
        error_code: str,
        error_message: str,
        message_id: Optional[str],
    ) -> None:
        super().__init__(
            f"{status_code} error response was encountered - {error_code} : {error_message} : MessageID={message_id}"
        )
        self.status_code = status_code
        self.error_code = error_code
        self.error_message = error_message
        self.message_id = message_id


class InvalidRequestError(RequestError):
    """"""


class PublicKeyError(RequestError):
    """"""
