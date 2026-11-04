"""Stable component error codes and value-free, validated source paths."""
from contextlib import contextmanager
import re


class ComponentError(ValueError):
    def __init__(self, code='component.invalid', path=()):
        if not re.fullmatch(r'component\.[a-z][a-z-]*', code):
            code = 'component.invalid'
        safe = tuple(part for part in path if isinstance(part, str)
                     and re.fullmatch(r'[a-z][a-z0-9_-]{0,62}', part))
        self.code, self.path = code, safe
        super().__init__(code + (' at ' + '.'.join(safe) if safe else ''))


@contextmanager
def at(*path):
    """Add only known field names and already validated component identifiers."""
    try:
        yield
    except ComponentError as error:
        raise ComponentError(error.code, path + error.path) from None
    except (TypeError, KeyError):
        raise ComponentError('component.type', path) from None


def checked(check, value, *path, **kwargs):
    with at(*path):
        return check(value, **kwargs)
