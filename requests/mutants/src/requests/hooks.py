"""
requests.hooks
~~~~~~~~~~~~~~

This module provides the capabilities for the Requests hooks system.

Available hooks:

``response``:
    The response generated from a Request.
"""
HOOKS = ["response"]
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


def default_hooks():
    return {event: [] for event in HOOKS}


# TODO: response is the only one


def x_dispatch_hook__mutmut_orig(key, hooks, hook_data, **kwargs):
    """Dispatches a hook dictionary on a given piece of data."""
    hooks = hooks or {}
    hooks = hooks.get(key)
    if hooks:
        if hasattr(hooks, "__call__"):
            hooks = [hooks]
        for hook in hooks:
            _hook_data = hook(hook_data, **kwargs)
            if _hook_data is not None:
                hook_data = _hook_data
    return hook_data


# TODO: response is the only one


def x_dispatch_hook__mutmut_1(key, hooks, hook_data, **kwargs):
    """Dispatches a hook dictionary on a given piece of data."""
    hooks = None
    hooks = hooks.get(key)
    if hooks:
        if hasattr(hooks, "__call__"):
            hooks = [hooks]
        for hook in hooks:
            _hook_data = hook(hook_data, **kwargs)
            if _hook_data is not None:
                hook_data = _hook_data
    return hook_data


# TODO: response is the only one


def x_dispatch_hook__mutmut_2(key, hooks, hook_data, **kwargs):
    """Dispatches a hook dictionary on a given piece of data."""
    hooks = hooks and {}
    hooks = hooks.get(key)
    if hooks:
        if hasattr(hooks, "__call__"):
            hooks = [hooks]
        for hook in hooks:
            _hook_data = hook(hook_data, **kwargs)
            if _hook_data is not None:
                hook_data = _hook_data
    return hook_data


# TODO: response is the only one


def x_dispatch_hook__mutmut_3(key, hooks, hook_data, **kwargs):
    """Dispatches a hook dictionary on a given piece of data."""
    hooks = hooks or {}
    hooks = None
    if hooks:
        if hasattr(hooks, "__call__"):
            hooks = [hooks]
        for hook in hooks:
            _hook_data = hook(hook_data, **kwargs)
            if _hook_data is not None:
                hook_data = _hook_data
    return hook_data


# TODO: response is the only one


def x_dispatch_hook__mutmut_4(key, hooks, hook_data, **kwargs):
    """Dispatches a hook dictionary on a given piece of data."""
    hooks = hooks or {}
    hooks = hooks.get(None)
    if hooks:
        if hasattr(hooks, "__call__"):
            hooks = [hooks]
        for hook in hooks:
            _hook_data = hook(hook_data, **kwargs)
            if _hook_data is not None:
                hook_data = _hook_data
    return hook_data


# TODO: response is the only one


def x_dispatch_hook__mutmut_5(key, hooks, hook_data, **kwargs):
    """Dispatches a hook dictionary on a given piece of data."""
    hooks = hooks or {}
    hooks = hooks.get(key)
    if hooks:
        if hasattr(None, "__call__"):
            hooks = [hooks]
        for hook in hooks:
            _hook_data = hook(hook_data, **kwargs)
            if _hook_data is not None:
                hook_data = _hook_data
    return hook_data


# TODO: response is the only one


def x_dispatch_hook__mutmut_6(key, hooks, hook_data, **kwargs):
    """Dispatches a hook dictionary on a given piece of data."""
    hooks = hooks or {}
    hooks = hooks.get(key)
    if hooks:
        if hasattr(hooks, None):
            hooks = [hooks]
        for hook in hooks:
            _hook_data = hook(hook_data, **kwargs)
            if _hook_data is not None:
                hook_data = _hook_data
    return hook_data


# TODO: response is the only one


def x_dispatch_hook__mutmut_7(key, hooks, hook_data, **kwargs):
    """Dispatches a hook dictionary on a given piece of data."""
    hooks = hooks or {}
    hooks = hooks.get(key)
    if hooks:
        if hasattr("__call__"):
            hooks = [hooks]
        for hook in hooks:
            _hook_data = hook(hook_data, **kwargs)
            if _hook_data is not None:
                hook_data = _hook_data
    return hook_data


# TODO: response is the only one


def x_dispatch_hook__mutmut_8(key, hooks, hook_data, **kwargs):
    """Dispatches a hook dictionary on a given piece of data."""
    hooks = hooks or {}
    hooks = hooks.get(key)
    if hooks:
        if hasattr(hooks, ):
            hooks = [hooks]
        for hook in hooks:
            _hook_data = hook(hook_data, **kwargs)
            if _hook_data is not None:
                hook_data = _hook_data
    return hook_data


# TODO: response is the only one


def x_dispatch_hook__mutmut_9(key, hooks, hook_data, **kwargs):
    """Dispatches a hook dictionary on a given piece of data."""
    hooks = hooks or {}
    hooks = hooks.get(key)
    if hooks:
        if hasattr(hooks, "XX__call__XX"):
            hooks = [hooks]
        for hook in hooks:
            _hook_data = hook(hook_data, **kwargs)
            if _hook_data is not None:
                hook_data = _hook_data
    return hook_data


# TODO: response is the only one


def x_dispatch_hook__mutmut_10(key, hooks, hook_data, **kwargs):
    """Dispatches a hook dictionary on a given piece of data."""
    hooks = hooks or {}
    hooks = hooks.get(key)
    if hooks:
        if hasattr(hooks, "__CALL__"):
            hooks = [hooks]
        for hook in hooks:
            _hook_data = hook(hook_data, **kwargs)
            if _hook_data is not None:
                hook_data = _hook_data
    return hook_data


# TODO: response is the only one


def x_dispatch_hook__mutmut_11(key, hooks, hook_data, **kwargs):
    """Dispatches a hook dictionary on a given piece of data."""
    hooks = hooks or {}
    hooks = hooks.get(key)
    if hooks:
        if hasattr(hooks, "__call__"):
            hooks = None
        for hook in hooks:
            _hook_data = hook(hook_data, **kwargs)
            if _hook_data is not None:
                hook_data = _hook_data
    return hook_data


# TODO: response is the only one


def x_dispatch_hook__mutmut_12(key, hooks, hook_data, **kwargs):
    """Dispatches a hook dictionary on a given piece of data."""
    hooks = hooks or {}
    hooks = hooks.get(key)
    if hooks:
        if hasattr(hooks, "__call__"):
            hooks = [hooks]
        for hook in hooks:
            _hook_data = None
            if _hook_data is not None:
                hook_data = _hook_data
    return hook_data


# TODO: response is the only one


def x_dispatch_hook__mutmut_13(key, hooks, hook_data, **kwargs):
    """Dispatches a hook dictionary on a given piece of data."""
    hooks = hooks or {}
    hooks = hooks.get(key)
    if hooks:
        if hasattr(hooks, "__call__"):
            hooks = [hooks]
        for hook in hooks:
            _hook_data = hook(None, **kwargs)
            if _hook_data is not None:
                hook_data = _hook_data
    return hook_data


# TODO: response is the only one


def x_dispatch_hook__mutmut_14(key, hooks, hook_data, **kwargs):
    """Dispatches a hook dictionary on a given piece of data."""
    hooks = hooks or {}
    hooks = hooks.get(key)
    if hooks:
        if hasattr(hooks, "__call__"):
            hooks = [hooks]
        for hook in hooks:
            _hook_data = hook(**kwargs)
            if _hook_data is not None:
                hook_data = _hook_data
    return hook_data


# TODO: response is the only one


def x_dispatch_hook__mutmut_15(key, hooks, hook_data, **kwargs):
    """Dispatches a hook dictionary on a given piece of data."""
    hooks = hooks or {}
    hooks = hooks.get(key)
    if hooks:
        if hasattr(hooks, "__call__"):
            hooks = [hooks]
        for hook in hooks:
            _hook_data = hook(hook_data, )
            if _hook_data is not None:
                hook_data = _hook_data
    return hook_data


# TODO: response is the only one


def x_dispatch_hook__mutmut_16(key, hooks, hook_data, **kwargs):
    """Dispatches a hook dictionary on a given piece of data."""
    hooks = hooks or {}
    hooks = hooks.get(key)
    if hooks:
        if hasattr(hooks, "__call__"):
            hooks = [hooks]
        for hook in hooks:
            _hook_data = hook(hook_data, **kwargs)
            if _hook_data is None:
                hook_data = _hook_data
    return hook_data


# TODO: response is the only one


def x_dispatch_hook__mutmut_17(key, hooks, hook_data, **kwargs):
    """Dispatches a hook dictionary on a given piece of data."""
    hooks = hooks or {}
    hooks = hooks.get(key)
    if hooks:
        if hasattr(hooks, "__call__"):
            hooks = [hooks]
        for hook in hooks:
            _hook_data = hook(hook_data, **kwargs)
            if _hook_data is not None:
                hook_data = None
    return hook_data

x_dispatch_hook__mutmut_mutants : ClassVar[MutantDict] = {
'x_dispatch_hook__mutmut_1': x_dispatch_hook__mutmut_1, 
    'x_dispatch_hook__mutmut_2': x_dispatch_hook__mutmut_2, 
    'x_dispatch_hook__mutmut_3': x_dispatch_hook__mutmut_3, 
    'x_dispatch_hook__mutmut_4': x_dispatch_hook__mutmut_4, 
    'x_dispatch_hook__mutmut_5': x_dispatch_hook__mutmut_5, 
    'x_dispatch_hook__mutmut_6': x_dispatch_hook__mutmut_6, 
    'x_dispatch_hook__mutmut_7': x_dispatch_hook__mutmut_7, 
    'x_dispatch_hook__mutmut_8': x_dispatch_hook__mutmut_8, 
    'x_dispatch_hook__mutmut_9': x_dispatch_hook__mutmut_9, 
    'x_dispatch_hook__mutmut_10': x_dispatch_hook__mutmut_10, 
    'x_dispatch_hook__mutmut_11': x_dispatch_hook__mutmut_11, 
    'x_dispatch_hook__mutmut_12': x_dispatch_hook__mutmut_12, 
    'x_dispatch_hook__mutmut_13': x_dispatch_hook__mutmut_13, 
    'x_dispatch_hook__mutmut_14': x_dispatch_hook__mutmut_14, 
    'x_dispatch_hook__mutmut_15': x_dispatch_hook__mutmut_15, 
    'x_dispatch_hook__mutmut_16': x_dispatch_hook__mutmut_16, 
    'x_dispatch_hook__mutmut_17': x_dispatch_hook__mutmut_17
}

def dispatch_hook(*args, **kwargs):
    result = _mutmut_trampoline(x_dispatch_hook__mutmut_orig, x_dispatch_hook__mutmut_mutants, args, kwargs)
    return result 

dispatch_hook.__signature__ = _mutmut_signature(x_dispatch_hook__mutmut_orig)
x_dispatch_hook__mutmut_orig.__name__ = 'x_dispatch_hook'
