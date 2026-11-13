"""Source-only recovery-public-key selection using the existing confined reader."""
import backup_recovery
from component_sources import closed, require
from component_errors import ComponentError


def source(value):
    closed(value, ('source',))
    require(isinstance(value['source'], str) and bool(value['source']), 'component.backup-recovery-key')


def bind(resolver, value):
    source(value)
    raw = resolver.site_sources.raw(value['source'])
    try:
        return backup_recovery.public_key(raw)
    except ValueError:
        raise ComponentError('component.backup-recovery-key') from None
