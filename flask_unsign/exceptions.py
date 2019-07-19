class FlaskUnsignException(Exception):
    """Base exception for all custom errors"""


class DecodeError(FlaskUnsignException):
    """Raised when the application failed to decode a given cookie."""


class SigningError(FlaskUnsignException):
    """Raised whe signing the data fails"""
