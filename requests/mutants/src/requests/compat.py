"""
requests.compat
~~~~~~~~~~~~~~~

This module previously handled import compatibility issues
between Python 2 and Python 3. It remains for backwards
compatibility until the next major version.
"""

import importlib
import sys

# -------
# urllib3
# -------
from urllib3 import __version__ as urllib3_version

# Detect which major version of urllib3 is being used.
try:
    is_urllib3_1 = int(urllib3_version.split(".")[0]) == 1
except (TypeError, AttributeError):
    # If we can't discern a version, prefer old functionality.
    is_urllib3_1 = True
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

# -------------------
# Character Detection
# -------------------


def x__resolve_char_detection__mutmut_orig():
    """Find supported character detection libraries."""
    chardet = None
    for lib in ("chardet", "charset_normalizer"):
        if chardet is None:
            try:
                chardet = importlib.import_module(lib)
            except ImportError:
                pass
    return chardet

# -------------------
# Character Detection
# -------------------


def x__resolve_char_detection__mutmut_1():
    """Find supported character detection libraries."""
    chardet = ""
    for lib in ("chardet", "charset_normalizer"):
        if chardet is None:
            try:
                chardet = importlib.import_module(lib)
            except ImportError:
                pass
    return chardet

# -------------------
# Character Detection
# -------------------


def x__resolve_char_detection__mutmut_2():
    """Find supported character detection libraries."""
    chardet = None
    for lib in ("XXchardetXX", "charset_normalizer"):
        if chardet is None:
            try:
                chardet = importlib.import_module(lib)
            except ImportError:
                pass
    return chardet

# -------------------
# Character Detection
# -------------------


def x__resolve_char_detection__mutmut_3():
    """Find supported character detection libraries."""
    chardet = None
    for lib in ("CHARDET", "charset_normalizer"):
        if chardet is None:
            try:
                chardet = importlib.import_module(lib)
            except ImportError:
                pass
    return chardet

# -------------------
# Character Detection
# -------------------


def x__resolve_char_detection__mutmut_4():
    """Find supported character detection libraries."""
    chardet = None
    for lib in ("chardet", "XXcharset_normalizerXX"):
        if chardet is None:
            try:
                chardet = importlib.import_module(lib)
            except ImportError:
                pass
    return chardet

# -------------------
# Character Detection
# -------------------


def x__resolve_char_detection__mutmut_5():
    """Find supported character detection libraries."""
    chardet = None
    for lib in ("chardet", "CHARSET_NORMALIZER"):
        if chardet is None:
            try:
                chardet = importlib.import_module(lib)
            except ImportError:
                pass
    return chardet

# -------------------
# Character Detection
# -------------------


def x__resolve_char_detection__mutmut_6():
    """Find supported character detection libraries."""
    chardet = None
    for lib in ("chardet", "charset_normalizer"):
        if chardet is not None:
            try:
                chardet = importlib.import_module(lib)
            except ImportError:
                pass
    return chardet

# -------------------
# Character Detection
# -------------------


def x__resolve_char_detection__mutmut_7():
    """Find supported character detection libraries."""
    chardet = None
    for lib in ("chardet", "charset_normalizer"):
        if chardet is None:
            try:
                chardet = None
            except ImportError:
                pass
    return chardet

# -------------------
# Character Detection
# -------------------


def x__resolve_char_detection__mutmut_8():
    """Find supported character detection libraries."""
    chardet = None
    for lib in ("chardet", "charset_normalizer"):
        if chardet is None:
            try:
                chardet = importlib.import_module(None)
            except ImportError:
                pass
    return chardet

x__resolve_char_detection__mutmut_mutants : ClassVar[MutantDict] = {
'x__resolve_char_detection__mutmut_1': x__resolve_char_detection__mutmut_1, 
    'x__resolve_char_detection__mutmut_2': x__resolve_char_detection__mutmut_2, 
    'x__resolve_char_detection__mutmut_3': x__resolve_char_detection__mutmut_3, 
    'x__resolve_char_detection__mutmut_4': x__resolve_char_detection__mutmut_4, 
    'x__resolve_char_detection__mutmut_5': x__resolve_char_detection__mutmut_5, 
    'x__resolve_char_detection__mutmut_6': x__resolve_char_detection__mutmut_6, 
    'x__resolve_char_detection__mutmut_7': x__resolve_char_detection__mutmut_7, 
    'x__resolve_char_detection__mutmut_8': x__resolve_char_detection__mutmut_8
}

def _resolve_char_detection(*args, **kwargs):
    result = _mutmut_trampoline(x__resolve_char_detection__mutmut_orig, x__resolve_char_detection__mutmut_mutants, args, kwargs)
    return result 

_resolve_char_detection.__signature__ = _mutmut_signature(x__resolve_char_detection__mutmut_orig)
x__resolve_char_detection__mutmut_orig.__name__ = 'x__resolve_char_detection'


chardet = _resolve_char_detection()

# -------
# Pythons
# -------

# Syntax sugar.
_ver = sys.version_info

#: Python 2.x?
is_py2 = _ver[0] == 2

#: Python 3.x?
is_py3 = _ver[0] == 3

# json/simplejson module import resolution
has_simplejson = False
try:
    import simplejson as json

    has_simplejson = True
except ImportError:
    import json

if has_simplejson:
    from simplejson import JSONDecodeError
else:
    from json import JSONDecodeError

# Keep OrderedDict for backwards compatibility.
from collections import OrderedDict
from collections.abc import Callable, Mapping, MutableMapping
from http import cookiejar as cookielib
from http.cookies import Morsel
from io import StringIO

# --------------
# Legacy Imports
# --------------
from urllib.parse import (
    quote,
    quote_plus,
    unquote,
    unquote_plus,
    urldefrag,
    urlencode,
    urljoin,
    urlparse,
    urlsplit,
    urlunparse,
)
from urllib.request import (
    getproxies,
    getproxies_environment,
    parse_http_list,
    proxy_bypass,
    proxy_bypass_environment,
)

builtin_str = str
str = str
bytes = bytes
basestring = (str, bytes)
numeric_types = (int, float)
integer_types = (int,)
