"""
requests._internal_utils
~~~~~~~~~~~~~~

Provides utility functions that are consumed internally by Requests
which depend on extremely few external helpers (such as compat)
"""
import re

from .compat import builtin_str

_VALID_HEADER_NAME_RE_BYTE = re.compile(rb"^[^:\s][^:\r\n]*$")
_VALID_HEADER_NAME_RE_STR = re.compile(r"^[^:\s][^:\r\n]*$")
_VALID_HEADER_VALUE_RE_BYTE = re.compile(rb"^\S[^\r\n]*$|^$")
_VALID_HEADER_VALUE_RE_STR = re.compile(r"^\S[^\r\n]*$|^$")

_HEADER_VALIDATORS_STR = (_VALID_HEADER_NAME_RE_STR, _VALID_HEADER_VALUE_RE_STR)
_HEADER_VALIDATORS_BYTE = (_VALID_HEADER_NAME_RE_BYTE, _VALID_HEADER_VALUE_RE_BYTE)
HEADER_VALIDATORS = {
    bytes: _HEADER_VALIDATORS_BYTE,
    str: _HEADER_VALIDATORS_STR,
}
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


def x_to_native_string__mutmut_orig(string, encoding="ascii"):
    """Given a string object, regardless of type, returns a representation of
    that string in the native string type, encoding and decoding where
    necessary. This assumes ASCII unless told otherwise.
    """
    if isinstance(string, builtin_str):
        out = string
    else:
        out = string.decode(encoding)

    return out


def x_to_native_string__mutmut_1(string, encoding="XXasciiXX"):
    """Given a string object, regardless of type, returns a representation of
    that string in the native string type, encoding and decoding where
    necessary. This assumes ASCII unless told otherwise.
    """
    if isinstance(string, builtin_str):
        out = string
    else:
        out = string.decode(encoding)

    return out


def x_to_native_string__mutmut_2(string, encoding="ASCII"):
    """Given a string object, regardless of type, returns a representation of
    that string in the native string type, encoding and decoding where
    necessary. This assumes ASCII unless told otherwise.
    """
    if isinstance(string, builtin_str):
        out = string
    else:
        out = string.decode(encoding)

    return out


def x_to_native_string__mutmut_3(string, encoding="ascii"):
    """Given a string object, regardless of type, returns a representation of
    that string in the native string type, encoding and decoding where
    necessary. This assumes ASCII unless told otherwise.
    """
    if isinstance(string, builtin_str):
        out = None
    else:
        out = string.decode(encoding)

    return out


def x_to_native_string__mutmut_4(string, encoding="ascii"):
    """Given a string object, regardless of type, returns a representation of
    that string in the native string type, encoding and decoding where
    necessary. This assumes ASCII unless told otherwise.
    """
    if isinstance(string, builtin_str):
        out = string
    else:
        out = None

    return out


def x_to_native_string__mutmut_5(string, encoding="ascii"):
    """Given a string object, regardless of type, returns a representation of
    that string in the native string type, encoding and decoding where
    necessary. This assumes ASCII unless told otherwise.
    """
    if isinstance(string, builtin_str):
        out = string
    else:
        out = string.decode(None)

    return out

x_to_native_string__mutmut_mutants : ClassVar[MutantDict] = {
'x_to_native_string__mutmut_1': x_to_native_string__mutmut_1, 
    'x_to_native_string__mutmut_2': x_to_native_string__mutmut_2, 
    'x_to_native_string__mutmut_3': x_to_native_string__mutmut_3, 
    'x_to_native_string__mutmut_4': x_to_native_string__mutmut_4, 
    'x_to_native_string__mutmut_5': x_to_native_string__mutmut_5
}

def to_native_string(*args, **kwargs):
    result = _mutmut_trampoline(x_to_native_string__mutmut_orig, x_to_native_string__mutmut_mutants, args, kwargs)
    return result 

to_native_string.__signature__ = _mutmut_signature(x_to_native_string__mutmut_orig)
x_to_native_string__mutmut_orig.__name__ = 'x_to_native_string'


def x_unicode_is_ascii__mutmut_orig(u_string):
    """Determine if unicode string only contains ASCII characters.

    :param str u_string: unicode string to check. Must be unicode
        and not Python 2 `str`.
    :rtype: bool
    """
    assert isinstance(u_string, str)
    try:
        u_string.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False


def x_unicode_is_ascii__mutmut_1(u_string):
    """Determine if unicode string only contains ASCII characters.

    :param str u_string: unicode string to check. Must be unicode
        and not Python 2 `str`.
    :rtype: bool
    """
    assert isinstance(u_string, str)
    try:
        u_string.encode(None)
        return True
    except UnicodeEncodeError:
        return False


def x_unicode_is_ascii__mutmut_2(u_string):
    """Determine if unicode string only contains ASCII characters.

    :param str u_string: unicode string to check. Must be unicode
        and not Python 2 `str`.
    :rtype: bool
    """
    assert isinstance(u_string, str)
    try:
        u_string.encode("XXasciiXX")
        return True
    except UnicodeEncodeError:
        return False


def x_unicode_is_ascii__mutmut_3(u_string):
    """Determine if unicode string only contains ASCII characters.

    :param str u_string: unicode string to check. Must be unicode
        and not Python 2 `str`.
    :rtype: bool
    """
    assert isinstance(u_string, str)
    try:
        u_string.encode("ASCII")
        return True
    except UnicodeEncodeError:
        return False


def x_unicode_is_ascii__mutmut_4(u_string):
    """Determine if unicode string only contains ASCII characters.

    :param str u_string: unicode string to check. Must be unicode
        and not Python 2 `str`.
    :rtype: bool
    """
    assert isinstance(u_string, str)
    try:
        u_string.encode("ascii")
        return False
    except UnicodeEncodeError:
        return False


def x_unicode_is_ascii__mutmut_5(u_string):
    """Determine if unicode string only contains ASCII characters.

    :param str u_string: unicode string to check. Must be unicode
        and not Python 2 `str`.
    :rtype: bool
    """
    assert isinstance(u_string, str)
    try:
        u_string.encode("ascii")
        return True
    except UnicodeEncodeError:
        return True

x_unicode_is_ascii__mutmut_mutants : ClassVar[MutantDict] = {
'x_unicode_is_ascii__mutmut_1': x_unicode_is_ascii__mutmut_1, 
    'x_unicode_is_ascii__mutmut_2': x_unicode_is_ascii__mutmut_2, 
    'x_unicode_is_ascii__mutmut_3': x_unicode_is_ascii__mutmut_3, 
    'x_unicode_is_ascii__mutmut_4': x_unicode_is_ascii__mutmut_4, 
    'x_unicode_is_ascii__mutmut_5': x_unicode_is_ascii__mutmut_5
}

def unicode_is_ascii(*args, **kwargs):
    result = _mutmut_trampoline(x_unicode_is_ascii__mutmut_orig, x_unicode_is_ascii__mutmut_mutants, args, kwargs)
    return result 

unicode_is_ascii.__signature__ = _mutmut_signature(x_unicode_is_ascii__mutmut_orig)
x_unicode_is_ascii__mutmut_orig.__name__ = 'x_unicode_is_ascii'
