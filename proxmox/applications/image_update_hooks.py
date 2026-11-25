"""Resolve an image update through its owning stack profile and sealed runtime."""
import authentik_upgrade
from private_io import require


def ordinary(attempt, phase, app):
    return {}  # The ordinary Compose phase already reconciles the selected images.


def check(profile, adapter, hook):
    # A local hook is an app capability. A name alone never selects a handler.
    if (profile, adapter) == ('authentik', 'authentik'):
        require(hook == 'release-series', 'The Authentik profile requires its release-series hook')
        return authentik_upgrade.phase_options
    require(hook == 'standard', 'Select the standard image update hook for this profile')
    return ordinary


def phase_options(attempt, phase, app):
    if app is None or not app.get('software_selection', {}).get('images'):
        return {}
    handler = check(app['profile'], app['adapter'], app.get('image_update'))
    return handler(attempt, phase, app)
