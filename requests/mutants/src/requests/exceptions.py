"""
requests.exceptions
~~~~~~~~~~~~~~~~~~~

This module contains the set of Requests' exceptions.
"""
from urllib3.exceptions import HTTPError as BaseHTTPError

from .compat import JSONDecodeError as CompatJSONDecodeError
from inspect import signature as _mutmut_signature
from typing import Annotated
from typing import Callable
from typing import ClassVar


MutantDict = Annotated[dict[str, Callable], "Mutant"]


def _mutmut_trampoline(orig, mutants, call_args, call_kwargs, self_arg = None):
    """Forward call to original or mutated function, depending on the environment"""
    import os
    mutant_under_test = os.environ['MUTANT_UNDER_TEST']
    if mutant_under_test == 'fail':
        from mutmut.__main__ import MutmutProgrammaticFailException
        raise MutmutProgrammaticFailException('Failed programmatically')      
    elif mutant_under_test == 'stats':
        from mutmut.__main__ import record_trampoline_hit
        record_trampoline_hit(orig.__module__ + '.' + orig.__name__)
        result = orig(*call_args, **call_kwargs)
        return result
    prefix = orig.__module__ + '.' + orig.__name__ + '__mutmut_'
    if not mutant_under_test.startswith(prefix):
        result = orig(*call_args, **call_kwargs)
        return result
    mutant_name = mutant_under_test.rpartition('.')[-1]
    if self_arg:
        # call to a class method where self is not bound
        result = mutants[mutant_name](self_arg, *call_args, **call_kwargs)
    else:
        result = mutants[mutant_name](*call_args, **call_kwargs)
    return result


class RequestException(IOError):
    """There was an ambiguous exception that occurred while handling your
    request.
    """

    def xǁRequestExceptionǁ__init____mutmut_orig(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop("request", None)
        if response is not None and not self.request and hasattr(response, "request"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)

    def xǁRequestExceptionǁ__init____mutmut_1(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = None
        self.response = response
        self.request = kwargs.pop("request", None)
        if response is not None and not self.request and hasattr(response, "request"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)

    def xǁRequestExceptionǁ__init____mutmut_2(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop(None, None)
        self.response = response
        self.request = kwargs.pop("request", None)
        if response is not None and not self.request and hasattr(response, "request"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)

    def xǁRequestExceptionǁ__init____mutmut_3(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop(None)
        self.response = response
        self.request = kwargs.pop("request", None)
        if response is not None and not self.request and hasattr(response, "request"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)

    def xǁRequestExceptionǁ__init____mutmut_4(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop("response", )
        self.response = response
        self.request = kwargs.pop("request", None)
        if response is not None and not self.request and hasattr(response, "request"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)

    def xǁRequestExceptionǁ__init____mutmut_5(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop("XXresponseXX", None)
        self.response = response
        self.request = kwargs.pop("request", None)
        if response is not None and not self.request and hasattr(response, "request"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)

    def xǁRequestExceptionǁ__init____mutmut_6(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop("RESPONSE", None)
        self.response = response
        self.request = kwargs.pop("request", None)
        if response is not None and not self.request and hasattr(response, "request"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)

    def xǁRequestExceptionǁ__init____mutmut_7(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = None
        self.request = kwargs.pop("request", None)
        if response is not None and not self.request and hasattr(response, "request"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)

    def xǁRequestExceptionǁ__init____mutmut_8(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = response
        self.request = None
        if response is not None and not self.request and hasattr(response, "request"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)

    def xǁRequestExceptionǁ__init____mutmut_9(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop(None, None)
        if response is not None and not self.request and hasattr(response, "request"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)

    def xǁRequestExceptionǁ__init____mutmut_10(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop(None)
        if response is not None and not self.request and hasattr(response, "request"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)

    def xǁRequestExceptionǁ__init____mutmut_11(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop("request", )
        if response is not None and not self.request and hasattr(response, "request"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)

    def xǁRequestExceptionǁ__init____mutmut_12(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop("XXrequestXX", None)
        if response is not None and not self.request and hasattr(response, "request"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)

    def xǁRequestExceptionǁ__init____mutmut_13(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop("REQUEST", None)
        if response is not None and not self.request and hasattr(response, "request"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)

    def xǁRequestExceptionǁ__init____mutmut_14(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop("request", None)
        if response is not None and not self.request or hasattr(response, "request"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)

    def xǁRequestExceptionǁ__init____mutmut_15(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop("request", None)
        if response is not None or not self.request and hasattr(response, "request"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)

    def xǁRequestExceptionǁ__init____mutmut_16(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop("request", None)
        if response is None and not self.request and hasattr(response, "request"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)

    def xǁRequestExceptionǁ__init____mutmut_17(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop("request", None)
        if response is not None and self.request and hasattr(response, "request"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)

    def xǁRequestExceptionǁ__init____mutmut_18(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop("request", None)
        if response is not None and not self.request and hasattr(None, "request"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)

    def xǁRequestExceptionǁ__init____mutmut_19(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop("request", None)
        if response is not None and not self.request and hasattr(response, None):
            self.request = self.response.request
        super().__init__(*args, **kwargs)

    def xǁRequestExceptionǁ__init____mutmut_20(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop("request", None)
        if response is not None and not self.request and hasattr("request"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)

    def xǁRequestExceptionǁ__init____mutmut_21(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop("request", None)
        if response is not None and not self.request and hasattr(response, ):
            self.request = self.response.request
        super().__init__(*args, **kwargs)

    def xǁRequestExceptionǁ__init____mutmut_22(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop("request", None)
        if response is not None and not self.request and hasattr(response, "XXrequestXX"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)

    def xǁRequestExceptionǁ__init____mutmut_23(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop("request", None)
        if response is not None and not self.request and hasattr(response, "REQUEST"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)

    def xǁRequestExceptionǁ__init____mutmut_24(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop("request", None)
        if response is not None and not self.request and hasattr(response, "request"):
            self.request = None
        super().__init__(*args, **kwargs)

    def xǁRequestExceptionǁ__init____mutmut_25(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop("request", None)
        if response is not None and not self.request and hasattr(response, "request"):
            self.request = self.response.request
        super().__init__(**kwargs)

    def xǁRequestExceptionǁ__init____mutmut_26(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop("request", None)
        if response is not None and not self.request and hasattr(response, "request"):
            self.request = self.response.request
        super().__init__(*args, )
    
    xǁRequestExceptionǁ__init____mutmut_mutants : ClassVar[MutantDict] = {
    'xǁRequestExceptionǁ__init____mutmut_1': xǁRequestExceptionǁ__init____mutmut_1, 
        'xǁRequestExceptionǁ__init____mutmut_2': xǁRequestExceptionǁ__init____mutmut_2, 
        'xǁRequestExceptionǁ__init____mutmut_3': xǁRequestExceptionǁ__init____mutmut_3, 
        'xǁRequestExceptionǁ__init____mutmut_4': xǁRequestExceptionǁ__init____mutmut_4, 
        'xǁRequestExceptionǁ__init____mutmut_5': xǁRequestExceptionǁ__init____mutmut_5, 
        'xǁRequestExceptionǁ__init____mutmut_6': xǁRequestExceptionǁ__init____mutmut_6, 
        'xǁRequestExceptionǁ__init____mutmut_7': xǁRequestExceptionǁ__init____mutmut_7, 
        'xǁRequestExceptionǁ__init____mutmut_8': xǁRequestExceptionǁ__init____mutmut_8, 
        'xǁRequestExceptionǁ__init____mutmut_9': xǁRequestExceptionǁ__init____mutmut_9, 
        'xǁRequestExceptionǁ__init____mutmut_10': xǁRequestExceptionǁ__init____mutmut_10, 
        'xǁRequestExceptionǁ__init____mutmut_11': xǁRequestExceptionǁ__init____mutmut_11, 
        'xǁRequestExceptionǁ__init____mutmut_12': xǁRequestExceptionǁ__init____mutmut_12, 
        'xǁRequestExceptionǁ__init____mutmut_13': xǁRequestExceptionǁ__init____mutmut_13, 
        'xǁRequestExceptionǁ__init____mutmut_14': xǁRequestExceptionǁ__init____mutmut_14, 
        'xǁRequestExceptionǁ__init____mutmut_15': xǁRequestExceptionǁ__init____mutmut_15, 
        'xǁRequestExceptionǁ__init____mutmut_16': xǁRequestExceptionǁ__init____mutmut_16, 
        'xǁRequestExceptionǁ__init____mutmut_17': xǁRequestExceptionǁ__init____mutmut_17, 
        'xǁRequestExceptionǁ__init____mutmut_18': xǁRequestExceptionǁ__init____mutmut_18, 
        'xǁRequestExceptionǁ__init____mutmut_19': xǁRequestExceptionǁ__init____mutmut_19, 
        'xǁRequestExceptionǁ__init____mutmut_20': xǁRequestExceptionǁ__init____mutmut_20, 
        'xǁRequestExceptionǁ__init____mutmut_21': xǁRequestExceptionǁ__init____mutmut_21, 
        'xǁRequestExceptionǁ__init____mutmut_22': xǁRequestExceptionǁ__init____mutmut_22, 
        'xǁRequestExceptionǁ__init____mutmut_23': xǁRequestExceptionǁ__init____mutmut_23, 
        'xǁRequestExceptionǁ__init____mutmut_24': xǁRequestExceptionǁ__init____mutmut_24, 
        'xǁRequestExceptionǁ__init____mutmut_25': xǁRequestExceptionǁ__init____mutmut_25, 
        'xǁRequestExceptionǁ__init____mutmut_26': xǁRequestExceptionǁ__init____mutmut_26
    }
    
    def __init__(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁRequestExceptionǁ__init____mutmut_orig"), object.__getattribute__(self, "xǁRequestExceptionǁ__init____mutmut_mutants"), args, kwargs, self)
        return result 
    
    __init__.__signature__ = _mutmut_signature(xǁRequestExceptionǁ__init____mutmut_orig)
    xǁRequestExceptionǁ__init____mutmut_orig.__name__ = 'xǁRequestExceptionǁ__init__'


class InvalidJSONError(RequestException):
    """A JSON error occurred."""


class JSONDecodeError(InvalidJSONError, CompatJSONDecodeError):
    """Couldn't decode the text into json"""

    def xǁJSONDecodeErrorǁ__init____mutmut_orig(self, *args, **kwargs):
        """
        Construct the JSONDecodeError instance first with all
        args. Then use it's args to construct the IOError so that
        the json specific args aren't used as IOError specific args
        and the error message from JSONDecodeError is preserved.
        """
        CompatJSONDecodeError.__init__(self, *args)
        InvalidJSONError.__init__(self, *self.args, **kwargs)

    def xǁJSONDecodeErrorǁ__init____mutmut_1(self, *args, **kwargs):
        """
        Construct the JSONDecodeError instance first with all
        args. Then use it's args to construct the IOError so that
        the json specific args aren't used as IOError specific args
        and the error message from JSONDecodeError is preserved.
        """
        CompatJSONDecodeError.__init__(None, *args)
        InvalidJSONError.__init__(self, *self.args, **kwargs)

    def xǁJSONDecodeErrorǁ__init____mutmut_2(self, *args, **kwargs):
        """
        Construct the JSONDecodeError instance first with all
        args. Then use it's args to construct the IOError so that
        the json specific args aren't used as IOError specific args
        and the error message from JSONDecodeError is preserved.
        """
        CompatJSONDecodeError.__init__(*args)
        InvalidJSONError.__init__(self, *self.args, **kwargs)

    def xǁJSONDecodeErrorǁ__init____mutmut_3(self, *args, **kwargs):
        """
        Construct the JSONDecodeError instance first with all
        args. Then use it's args to construct the IOError so that
        the json specific args aren't used as IOError specific args
        and the error message from JSONDecodeError is preserved.
        """
        CompatJSONDecodeError.__init__(self, )
        InvalidJSONError.__init__(self, *self.args, **kwargs)

    def xǁJSONDecodeErrorǁ__init____mutmut_4(self, *args, **kwargs):
        """
        Construct the JSONDecodeError instance first with all
        args. Then use it's args to construct the IOError so that
        the json specific args aren't used as IOError specific args
        and the error message from JSONDecodeError is preserved.
        """
        CompatJSONDecodeError.__init__(self, *args)
        InvalidJSONError.__init__(None, *self.args, **kwargs)

    def xǁJSONDecodeErrorǁ__init____mutmut_5(self, *args, **kwargs):
        """
        Construct the JSONDecodeError instance first with all
        args. Then use it's args to construct the IOError so that
        the json specific args aren't used as IOError specific args
        and the error message from JSONDecodeError is preserved.
        """
        CompatJSONDecodeError.__init__(self, *args)
        InvalidJSONError.__init__(*self.args, **kwargs)

    def xǁJSONDecodeErrorǁ__init____mutmut_6(self, *args, **kwargs):
        """
        Construct the JSONDecodeError instance first with all
        args. Then use it's args to construct the IOError so that
        the json specific args aren't used as IOError specific args
        and the error message from JSONDecodeError is preserved.
        """
        CompatJSONDecodeError.__init__(self, *args)
        InvalidJSONError.__init__(self, **kwargs)

    def xǁJSONDecodeErrorǁ__init____mutmut_7(self, *args, **kwargs):
        """
        Construct the JSONDecodeError instance first with all
        args. Then use it's args to construct the IOError so that
        the json specific args aren't used as IOError specific args
        and the error message from JSONDecodeError is preserved.
        """
        CompatJSONDecodeError.__init__(self, *args)
        InvalidJSONError.__init__(self, *self.args, )
    
    xǁJSONDecodeErrorǁ__init____mutmut_mutants : ClassVar[MutantDict] = {
    'xǁJSONDecodeErrorǁ__init____mutmut_1': xǁJSONDecodeErrorǁ__init____mutmut_1, 
        'xǁJSONDecodeErrorǁ__init____mutmut_2': xǁJSONDecodeErrorǁ__init____mutmut_2, 
        'xǁJSONDecodeErrorǁ__init____mutmut_3': xǁJSONDecodeErrorǁ__init____mutmut_3, 
        'xǁJSONDecodeErrorǁ__init____mutmut_4': xǁJSONDecodeErrorǁ__init____mutmut_4, 
        'xǁJSONDecodeErrorǁ__init____mutmut_5': xǁJSONDecodeErrorǁ__init____mutmut_5, 
        'xǁJSONDecodeErrorǁ__init____mutmut_6': xǁJSONDecodeErrorǁ__init____mutmut_6, 
        'xǁJSONDecodeErrorǁ__init____mutmut_7': xǁJSONDecodeErrorǁ__init____mutmut_7
    }
    
    def __init__(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁJSONDecodeErrorǁ__init____mutmut_orig"), object.__getattribute__(self, "xǁJSONDecodeErrorǁ__init____mutmut_mutants"), args, kwargs, self)
        return result 
    
    __init__.__signature__ = _mutmut_signature(xǁJSONDecodeErrorǁ__init____mutmut_orig)
    xǁJSONDecodeErrorǁ__init____mutmut_orig.__name__ = 'xǁJSONDecodeErrorǁ__init__'

    def xǁJSONDecodeErrorǁ__reduce____mutmut_orig(self):
        """
        The __reduce__ method called when pickling the object must
        be the one from the JSONDecodeError (be it json/simplejson)
        as it expects all the arguments for instantiation, not just
        one like the IOError, and the MRO would by default call the
        __reduce__ method from the IOError due to the inheritance order.
        """
        return CompatJSONDecodeError.__reduce__(self)

    def xǁJSONDecodeErrorǁ__reduce____mutmut_1(self):
        """
        The __reduce__ method called when pickling the object must
        be the one from the JSONDecodeError (be it json/simplejson)
        as it expects all the arguments for instantiation, not just
        one like the IOError, and the MRO would by default call the
        __reduce__ method from the IOError due to the inheritance order.
        """
        return CompatJSONDecodeError.__reduce__(None)
    
    xǁJSONDecodeErrorǁ__reduce____mutmut_mutants : ClassVar[MutantDict] = {
    'xǁJSONDecodeErrorǁ__reduce____mutmut_1': xǁJSONDecodeErrorǁ__reduce____mutmut_1
    }
    
    def __reduce__(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁJSONDecodeErrorǁ__reduce____mutmut_orig"), object.__getattribute__(self, "xǁJSONDecodeErrorǁ__reduce____mutmut_mutants"), args, kwargs, self)
        return result 
    
    __reduce__.__signature__ = _mutmut_signature(xǁJSONDecodeErrorǁ__reduce____mutmut_orig)
    xǁJSONDecodeErrorǁ__reduce____mutmut_orig.__name__ = 'xǁJSONDecodeErrorǁ__reduce__'


class HTTPError(RequestException):
    """An HTTP error occurred."""


class ConnectionError(RequestException):
    """A Connection error occurred."""


class ProxyError(ConnectionError):
    """A proxy error occurred."""


class SSLError(ConnectionError):
    """An SSL error occurred."""


class Timeout(RequestException):
    """The request timed out.

    Catching this error will catch both
    :exc:`~requests.exceptions.ConnectTimeout` and
    :exc:`~requests.exceptions.ReadTimeout` errors.
    """


class ConnectTimeout(ConnectionError, Timeout):
    """The request timed out while trying to connect to the remote server.

    Requests that produced this error are safe to retry.
    """


class ReadTimeout(Timeout):
    """The server did not send any data in the allotted amount of time."""


class URLRequired(RequestException):
    """A valid URL is required to make a request."""


class TooManyRedirects(RequestException):
    """Too many redirects."""


class MissingSchema(RequestException, ValueError):
    """The URL scheme (e.g. http or https) is missing."""


class InvalidSchema(RequestException, ValueError):
    """The URL scheme provided is either invalid or unsupported."""


class InvalidURL(RequestException, ValueError):
    """The URL provided was somehow invalid."""


class InvalidHeader(RequestException, ValueError):
    """The header value provided was somehow invalid."""


class InvalidProxyURL(InvalidURL):
    """The proxy URL provided is invalid."""


class ChunkedEncodingError(RequestException):
    """The server declared chunked encoding but sent an invalid chunk."""


class ContentDecodingError(RequestException, BaseHTTPError):
    """Failed to decode response content."""


class StreamConsumedError(RequestException, TypeError):
    """The content for this response was already consumed."""


class RetryError(RequestException):
    """Custom retries logic failed"""


class UnrewindableBodyError(RequestException):
    """Requests encountered an error when trying to rewind a body."""


# Warnings


class RequestsWarning(Warning):
    """Base warning for Requests."""


class FileModeWarning(RequestsWarning, DeprecationWarning):
    """A file was opened in text mode, but Requests determined its binary length."""


class RequestsDependencyWarning(RequestsWarning):
    """An imported dependency doesn't match the expected version range."""
