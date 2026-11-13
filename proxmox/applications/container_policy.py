"""Shared Docker lifecycle convention for application guest containers."""


def restart_policy(config):
    policy = config.get("restart", "always")
    if policy not in ("always", "unless-stopped", "no"):
        raise ValueError("Use always, unless-stopped or no for container restart")
    return policy
