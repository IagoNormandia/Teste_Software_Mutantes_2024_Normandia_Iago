"""
requests.structures
~~~~~~~~~~~~~~~~~~~

Data structures that power Requests.
"""

from collections import OrderedDict

from .compat import Mapping, MutableMapping
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


class CaseInsensitiveDict(MutableMapping):
    """A case-insensitive ``dict``-like object.

    Implements all methods and operations of
    ``MutableMapping`` as well as dict's ``copy``. Also
    provides ``lower_items``.

    All keys are expected to be strings. The structure remembers the
    case of the last key to be set, and ``iter(instance)``,
    ``keys()``, ``items()``, ``iterkeys()``, and ``iteritems()``
    will contain case-sensitive keys. However, querying and contains
    testing is case insensitive::

        cid = CaseInsensitiveDict()
        cid['Accept'] = 'application/json'
        cid['aCCEPT'] == 'application/json'  # True
        list(cid) == ['Accept']  # True

    For example, ``headers['content-encoding']`` will return the
    value of a ``'Content-Encoding'`` response header, regardless
    of how the header name was originally stored.

    If the constructor, ``.update``, or equality comparison
    operations are given keys that have equal ``.lower()``s, the
    behavior is undefined.
    """

    def xǁCaseInsensitiveDictǁ__init____mutmut_orig(self, data=None, **kwargs):
        self._store = OrderedDict()
        if data is None:
            data = {}
        self.update(data, **kwargs)

    def xǁCaseInsensitiveDictǁ__init____mutmut_1(self, data=None, **kwargs):
        self._store = None
        if data is None:
            data = {}
        self.update(data, **kwargs)

    def xǁCaseInsensitiveDictǁ__init____mutmut_2(self, data=None, **kwargs):
        self._store = OrderedDict()
        if data is not None:
            data = {}
        self.update(data, **kwargs)

    def xǁCaseInsensitiveDictǁ__init____mutmut_3(self, data=None, **kwargs):
        self._store = OrderedDict()
        if data is None:
            data = None
        self.update(data, **kwargs)

    def xǁCaseInsensitiveDictǁ__init____mutmut_4(self, data=None, **kwargs):
        self._store = OrderedDict()
        if data is None:
            data = {}
        self.update(None, **kwargs)

    def xǁCaseInsensitiveDictǁ__init____mutmut_5(self, data=None, **kwargs):
        self._store = OrderedDict()
        if data is None:
            data = {}
        self.update(**kwargs)

    def xǁCaseInsensitiveDictǁ__init____mutmut_6(self, data=None, **kwargs):
        self._store = OrderedDict()
        if data is None:
            data = {}
        self.update(data, )
    
    xǁCaseInsensitiveDictǁ__init____mutmut_mutants : ClassVar[MutantDict] = {
    'xǁCaseInsensitiveDictǁ__init____mutmut_1': xǁCaseInsensitiveDictǁ__init____mutmut_1, 
        'xǁCaseInsensitiveDictǁ__init____mutmut_2': xǁCaseInsensitiveDictǁ__init____mutmut_2, 
        'xǁCaseInsensitiveDictǁ__init____mutmut_3': xǁCaseInsensitiveDictǁ__init____mutmut_3, 
        'xǁCaseInsensitiveDictǁ__init____mutmut_4': xǁCaseInsensitiveDictǁ__init____mutmut_4, 
        'xǁCaseInsensitiveDictǁ__init____mutmut_5': xǁCaseInsensitiveDictǁ__init____mutmut_5, 
        'xǁCaseInsensitiveDictǁ__init____mutmut_6': xǁCaseInsensitiveDictǁ__init____mutmut_6
    }
    
    def __init__(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁCaseInsensitiveDictǁ__init____mutmut_orig"), object.__getattribute__(self, "xǁCaseInsensitiveDictǁ__init____mutmut_mutants"), args, kwargs, self)
        return result 
    
    __init__.__signature__ = _mutmut_signature(xǁCaseInsensitiveDictǁ__init____mutmut_orig)
    xǁCaseInsensitiveDictǁ__init____mutmut_orig.__name__ = 'xǁCaseInsensitiveDictǁ__init__'

    def xǁCaseInsensitiveDictǁ__setitem____mutmut_orig(self, key, value):
        # Use the lowercased key for lookups, but store the actual
        # key alongside the value.
        self._store[key.lower()] = (key, value)

    def xǁCaseInsensitiveDictǁ__setitem____mutmut_1(self, key, value):
        # Use the lowercased key for lookups, but store the actual
        # key alongside the value.
        self._store[key.lower()] = None

    def xǁCaseInsensitiveDictǁ__setitem____mutmut_2(self, key, value):
        # Use the lowercased key for lookups, but store the actual
        # key alongside the value.
        self._store[key.upper()] = (key, value)
    
    xǁCaseInsensitiveDictǁ__setitem____mutmut_mutants : ClassVar[MutantDict] = {
    'xǁCaseInsensitiveDictǁ__setitem____mutmut_1': xǁCaseInsensitiveDictǁ__setitem____mutmut_1, 
        'xǁCaseInsensitiveDictǁ__setitem____mutmut_2': xǁCaseInsensitiveDictǁ__setitem____mutmut_2
    }
    
    def __setitem__(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁCaseInsensitiveDictǁ__setitem____mutmut_orig"), object.__getattribute__(self, "xǁCaseInsensitiveDictǁ__setitem____mutmut_mutants"), args, kwargs, self)
        return result 
    
    __setitem__.__signature__ = _mutmut_signature(xǁCaseInsensitiveDictǁ__setitem____mutmut_orig)
    xǁCaseInsensitiveDictǁ__setitem____mutmut_orig.__name__ = 'xǁCaseInsensitiveDictǁ__setitem__'

    def xǁCaseInsensitiveDictǁ__getitem____mutmut_orig(self, key):
        return self._store[key.lower()][1]

    def xǁCaseInsensitiveDictǁ__getitem____mutmut_1(self, key):
        return self._store[key.upper()][1]

    def xǁCaseInsensitiveDictǁ__getitem____mutmut_2(self, key):
        return self._store[key.lower()][2]
    
    xǁCaseInsensitiveDictǁ__getitem____mutmut_mutants : ClassVar[MutantDict] = {
    'xǁCaseInsensitiveDictǁ__getitem____mutmut_1': xǁCaseInsensitiveDictǁ__getitem____mutmut_1, 
        'xǁCaseInsensitiveDictǁ__getitem____mutmut_2': xǁCaseInsensitiveDictǁ__getitem____mutmut_2
    }
    
    def __getitem__(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁCaseInsensitiveDictǁ__getitem____mutmut_orig"), object.__getattribute__(self, "xǁCaseInsensitiveDictǁ__getitem____mutmut_mutants"), args, kwargs, self)
        return result 
    
    __getitem__.__signature__ = _mutmut_signature(xǁCaseInsensitiveDictǁ__getitem____mutmut_orig)
    xǁCaseInsensitiveDictǁ__getitem____mutmut_orig.__name__ = 'xǁCaseInsensitiveDictǁ__getitem__'

    def xǁCaseInsensitiveDictǁ__delitem____mutmut_orig(self, key):
        del self._store[key.lower()]

    def xǁCaseInsensitiveDictǁ__delitem____mutmut_1(self, key):
        del self._store[key.upper()]
    
    xǁCaseInsensitiveDictǁ__delitem____mutmut_mutants : ClassVar[MutantDict] = {
    'xǁCaseInsensitiveDictǁ__delitem____mutmut_1': xǁCaseInsensitiveDictǁ__delitem____mutmut_1
    }
    
    def __delitem__(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁCaseInsensitiveDictǁ__delitem____mutmut_orig"), object.__getattribute__(self, "xǁCaseInsensitiveDictǁ__delitem____mutmut_mutants"), args, kwargs, self)
        return result 
    
    __delitem__.__signature__ = _mutmut_signature(xǁCaseInsensitiveDictǁ__delitem____mutmut_orig)
    xǁCaseInsensitiveDictǁ__delitem____mutmut_orig.__name__ = 'xǁCaseInsensitiveDictǁ__delitem__'

    def __iter__(self):
        return (casedkey for casedkey, mappedvalue in self._store.values())

    def __len__(self):
        return len(self._store)

    def xǁCaseInsensitiveDictǁlower_items__mutmut_orig(self):
        """Like iteritems(), but with all lowercase keys."""
        return ((lowerkey, keyval[1]) for (lowerkey, keyval) in self._store.items())

    def xǁCaseInsensitiveDictǁlower_items__mutmut_1(self):
        """Like iteritems(), but with all lowercase keys."""
        return ((lowerkey, keyval[2]) for (lowerkey, keyval) in self._store.items())
    
    xǁCaseInsensitiveDictǁlower_items__mutmut_mutants : ClassVar[MutantDict] = {
    'xǁCaseInsensitiveDictǁlower_items__mutmut_1': xǁCaseInsensitiveDictǁlower_items__mutmut_1
    }
    
    def lower_items(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁCaseInsensitiveDictǁlower_items__mutmut_orig"), object.__getattribute__(self, "xǁCaseInsensitiveDictǁlower_items__mutmut_mutants"), args, kwargs, self)
        return result 
    
    lower_items.__signature__ = _mutmut_signature(xǁCaseInsensitiveDictǁlower_items__mutmut_orig)
    xǁCaseInsensitiveDictǁlower_items__mutmut_orig.__name__ = 'xǁCaseInsensitiveDictǁlower_items'

    def xǁCaseInsensitiveDictǁ__eq____mutmut_orig(self, other):
        if isinstance(other, Mapping):
            other = CaseInsensitiveDict(other)
        else:
            return NotImplemented
        # Compare insensitively
        return dict(self.lower_items()) == dict(other.lower_items())

    def xǁCaseInsensitiveDictǁ__eq____mutmut_1(self, other):
        if isinstance(other, Mapping):
            other = None
        else:
            return NotImplemented
        # Compare insensitively
        return dict(self.lower_items()) == dict(other.lower_items())

    def xǁCaseInsensitiveDictǁ__eq____mutmut_2(self, other):
        if isinstance(other, Mapping):
            other = CaseInsensitiveDict(None)
        else:
            return NotImplemented
        # Compare insensitively
        return dict(self.lower_items()) == dict(other.lower_items())

    def xǁCaseInsensitiveDictǁ__eq____mutmut_3(self, other):
        if isinstance(other, Mapping):
            other = CaseInsensitiveDict(other)
        else:
            return NotImplemented
        # Compare insensitively
        return dict(None) == dict(other.lower_items())

    def xǁCaseInsensitiveDictǁ__eq____mutmut_4(self, other):
        if isinstance(other, Mapping):
            other = CaseInsensitiveDict(other)
        else:
            return NotImplemented
        # Compare insensitively
        return dict(self.lower_items()) != dict(other.lower_items())

    def xǁCaseInsensitiveDictǁ__eq____mutmut_5(self, other):
        if isinstance(other, Mapping):
            other = CaseInsensitiveDict(other)
        else:
            return NotImplemented
        # Compare insensitively
        return dict(self.lower_items()) == dict(None)
    
    xǁCaseInsensitiveDictǁ__eq____mutmut_mutants : ClassVar[MutantDict] = {
    'xǁCaseInsensitiveDictǁ__eq____mutmut_1': xǁCaseInsensitiveDictǁ__eq____mutmut_1, 
        'xǁCaseInsensitiveDictǁ__eq____mutmut_2': xǁCaseInsensitiveDictǁ__eq____mutmut_2, 
        'xǁCaseInsensitiveDictǁ__eq____mutmut_3': xǁCaseInsensitiveDictǁ__eq____mutmut_3, 
        'xǁCaseInsensitiveDictǁ__eq____mutmut_4': xǁCaseInsensitiveDictǁ__eq____mutmut_4, 
        'xǁCaseInsensitiveDictǁ__eq____mutmut_5': xǁCaseInsensitiveDictǁ__eq____mutmut_5
    }
    
    def __eq__(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁCaseInsensitiveDictǁ__eq____mutmut_orig"), object.__getattribute__(self, "xǁCaseInsensitiveDictǁ__eq____mutmut_mutants"), args, kwargs, self)
        return result 
    
    __eq__.__signature__ = _mutmut_signature(xǁCaseInsensitiveDictǁ__eq____mutmut_orig)
    xǁCaseInsensitiveDictǁ__eq____mutmut_orig.__name__ = 'xǁCaseInsensitiveDictǁ__eq__'

    # Copy is required
    def xǁCaseInsensitiveDictǁcopy__mutmut_orig(self):
        return CaseInsensitiveDict(self._store.values())

    # Copy is required
    def xǁCaseInsensitiveDictǁcopy__mutmut_1(self):
        return CaseInsensitiveDict(None)
    
    xǁCaseInsensitiveDictǁcopy__mutmut_mutants : ClassVar[MutantDict] = {
    'xǁCaseInsensitiveDictǁcopy__mutmut_1': xǁCaseInsensitiveDictǁcopy__mutmut_1
    }
    
    def copy(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁCaseInsensitiveDictǁcopy__mutmut_orig"), object.__getattribute__(self, "xǁCaseInsensitiveDictǁcopy__mutmut_mutants"), args, kwargs, self)
        return result 
    
    copy.__signature__ = _mutmut_signature(xǁCaseInsensitiveDictǁcopy__mutmut_orig)
    xǁCaseInsensitiveDictǁcopy__mutmut_orig.__name__ = 'xǁCaseInsensitiveDictǁcopy'

    def xǁCaseInsensitiveDictǁ__repr____mutmut_orig(self):
        return str(dict(self.items()))

    def xǁCaseInsensitiveDictǁ__repr____mutmut_1(self):
        return str(None)

    def xǁCaseInsensitiveDictǁ__repr____mutmut_2(self):
        return str(dict(None))
    
    xǁCaseInsensitiveDictǁ__repr____mutmut_mutants : ClassVar[MutantDict] = {
    'xǁCaseInsensitiveDictǁ__repr____mutmut_1': xǁCaseInsensitiveDictǁ__repr____mutmut_1, 
        'xǁCaseInsensitiveDictǁ__repr____mutmut_2': xǁCaseInsensitiveDictǁ__repr____mutmut_2
    }
    
    def __repr__(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁCaseInsensitiveDictǁ__repr____mutmut_orig"), object.__getattribute__(self, "xǁCaseInsensitiveDictǁ__repr____mutmut_mutants"), args, kwargs, self)
        return result 
    
    __repr__.__signature__ = _mutmut_signature(xǁCaseInsensitiveDictǁ__repr____mutmut_orig)
    xǁCaseInsensitiveDictǁ__repr____mutmut_orig.__name__ = 'xǁCaseInsensitiveDictǁ__repr__'


class LookupDict(dict):
    """Dictionary lookup object."""

    def xǁLookupDictǁ__init____mutmut_orig(self, name=None):
        self.name = name
        super().__init__()

    def xǁLookupDictǁ__init____mutmut_1(self, name=None):
        self.name = None
        super().__init__()
    
    xǁLookupDictǁ__init____mutmut_mutants : ClassVar[MutantDict] = {
    'xǁLookupDictǁ__init____mutmut_1': xǁLookupDictǁ__init____mutmut_1
    }
    
    def __init__(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁLookupDictǁ__init____mutmut_orig"), object.__getattribute__(self, "xǁLookupDictǁ__init____mutmut_mutants"), args, kwargs, self)
        return result 
    
    __init__.__signature__ = _mutmut_signature(xǁLookupDictǁ__init____mutmut_orig)
    xǁLookupDictǁ__init____mutmut_orig.__name__ = 'xǁLookupDictǁ__init__'

    def __repr__(self):
        return f"<lookup '{self.name}'>"

    def xǁLookupDictǁ__getitem____mutmut_orig(self, key):
        # We allow fall-through here, so values default to None

        return self.__dict__.get(key, None)

    def xǁLookupDictǁ__getitem____mutmut_1(self, key):
        # We allow fall-through here, so values default to None

        return self.__dict__.get(None, None)

    def xǁLookupDictǁ__getitem____mutmut_2(self, key):
        # We allow fall-through here, so values default to None

        return self.__dict__.get(None)

    def xǁLookupDictǁ__getitem____mutmut_3(self, key):
        # We allow fall-through here, so values default to None

        return self.__dict__.get(key, )
    
    xǁLookupDictǁ__getitem____mutmut_mutants : ClassVar[MutantDict] = {
    'xǁLookupDictǁ__getitem____mutmut_1': xǁLookupDictǁ__getitem____mutmut_1, 
        'xǁLookupDictǁ__getitem____mutmut_2': xǁLookupDictǁ__getitem____mutmut_2, 
        'xǁLookupDictǁ__getitem____mutmut_3': xǁLookupDictǁ__getitem____mutmut_3
    }
    
    def __getitem__(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁLookupDictǁ__getitem____mutmut_orig"), object.__getattribute__(self, "xǁLookupDictǁ__getitem____mutmut_mutants"), args, kwargs, self)
        return result 
    
    __getitem__.__signature__ = _mutmut_signature(xǁLookupDictǁ__getitem____mutmut_orig)
    xǁLookupDictǁ__getitem____mutmut_orig.__name__ = 'xǁLookupDictǁ__getitem__'

    def xǁLookupDictǁget__mutmut_orig(self, key, default=None):
        return self.__dict__.get(key, default)

    def xǁLookupDictǁget__mutmut_1(self, key, default=None):
        return self.__dict__.get(None, default)

    def xǁLookupDictǁget__mutmut_2(self, key, default=None):
        return self.__dict__.get(key, None)

    def xǁLookupDictǁget__mutmut_3(self, key, default=None):
        return self.__dict__.get(default)

    def xǁLookupDictǁget__mutmut_4(self, key, default=None):
        return self.__dict__.get(key, )
    
    xǁLookupDictǁget__mutmut_mutants : ClassVar[MutantDict] = {
    'xǁLookupDictǁget__mutmut_1': xǁLookupDictǁget__mutmut_1, 
        'xǁLookupDictǁget__mutmut_2': xǁLookupDictǁget__mutmut_2, 
        'xǁLookupDictǁget__mutmut_3': xǁLookupDictǁget__mutmut_3, 
        'xǁLookupDictǁget__mutmut_4': xǁLookupDictǁget__mutmut_4
    }
    
    def get(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁLookupDictǁget__mutmut_orig"), object.__getattribute__(self, "xǁLookupDictǁget__mutmut_mutants"), args, kwargs, self)
        return result 
    
    get.__signature__ = _mutmut_signature(xǁLookupDictǁget__mutmut_orig)
    xǁLookupDictǁget__mutmut_orig.__name__ = 'xǁLookupDictǁget'
