# Testing

The canonical guide is [Contributor testing](contributing/testing.md). It covers component/app/guest units, integration with the real compiler, all seven per-file coverage gates, generated source, security/signature checks and separate verification on the actual platform.

Use a **nonexistent** coverage output path. If a disposable parent is created with mktemp -d, append a new child such as "$WORK/coverage"; do not pass the already existing parent itself.
