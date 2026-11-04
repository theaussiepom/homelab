"""Bound the qualified vendor startup sizing to the selected application budget.

The qualified script's sizing prelude reads host memory and only cgroup v1.
Fresh no-config instances replace that prelude with four numeric assignments;
the exact SHA-checked vendor configuration/startup body is otherwise unchanged.
Mounted retained configuration does not select this capability.
"""
import math
from private_io import require

SCRIPT_SHA256 = '2eb96feeb94bbf05aa1655d591487a5ad40cefdc19c94fa6c8a751a95af60826'
BODY_LINE = 34
RESERVED_BYTES = 12582912


def command(memory_mib, cpu_limit):
    require(type(memory_mib) is int and 25 <= memory_mib <= 2**20,
            'Fresh Unbound needs an explicit supported application memory budget')
    require(type(cpu_limit) in (int, float) and math.isfinite(cpu_limit) and 0 < cpu_limit <= 256,
            'Fresh Unbound needs an explicit bounded CPU allocation')
    available = memory_mib * 1024**2 - RESERVED_BYTES
    rr_cache = available // 3
    msg_cache = rr_cache // 2
    cpus = max(1, math.floor(cpu_limit))
    threads = max(1, cpus - 1)
    slabs = 4 if cpus == 1 else 2**round(math.log2(cpus))
    assignments = [f'rr_cache_size={rr_cache}', f'msg_cache_size={msg_cache}',
                   f'threads={threads}', f'slabs={slabs}']
    # Only fixed source text and validated numbers enter this shell command.
    # No password, configured path, app label or other authored value enters it.
    script = ('[ "$(sha256sum /unbound.sh)" = "' + SCRIPT_SHA256 + '  /unbound.sh" ] '
              '|| { printf "%s\\n" "Unbound startup compatibility refused" >&2; exit 1; }; '
              'exec /bin/bash <(printf "%s\\n" ' + ' '.join("'" + row + "'" for row in assignments)
              + '; tail -n +' + str(BODY_LINE) + ' /unbound.sh)')
    return ['/bin/bash', '-c', script]
