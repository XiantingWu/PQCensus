# Publishing

PQCensus public distribution and source repository: `XiantingWu/PQCensus`.

## Current status

```text
CURRENT STATUS:
PUBLIC SOURCE ONLY

RELEASE AUTHORITY:
NOT ESTABLISHED

GITHUB RELEASE:
NONE

PYPI:
NOT PUBLISHED

REPOSITORY-HOSTED PUBLICATION AUTOMATION:
NONE
```

## Release and publication policy

No release authority is currently established. There are no tags, GitHub Releases, or PyPI uploads authorized.
The repository operates under a minimal public footprint with zero repository-hosted workflows.

Local verification of package build, metadata, and tests can be run using:

```bash
python -m build
python -m twine check dist/*
python scripts/release_check.py
```

Any future publication workflow will be addressed under a separate, dedicated release task.
