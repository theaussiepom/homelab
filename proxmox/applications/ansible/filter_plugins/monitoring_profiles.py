"""Controller-only filters; callers must keep credential-bearing results no_log."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from monitoring_profiles import host_profile, plugin_config


class FilterModule:
    def filters(self):
        return {'homelab_monitoring_plugins': plugin_config,
                'homelab_monitoring_host_profile': host_profile}
