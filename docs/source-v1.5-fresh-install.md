# SecureScan Source V1.5 fresh installation

Build release artifacts from the tagged source on Python 3.12:

```bash
python -m build
python -m venv /tmp/securescan-v15
/tmp/securescan-v15/bin/pip install 'dist/securescan_core-0.1.0-py3-none-any.whl[postgres]'
/tmp/securescan-v15/bin/securescan --help
```

The Core distribution keeps version `0.1.0`; `source-v1.5.0` is the independent
Source product tag. The wheel installs Alembic configuration/migrations and
V1.5 documentation/examples under the environment's `share/securescan`.

For an isolated database, set `SECURESCAN_DATABASE_URL` and run:

```bash
ALEMBIC_CONFIG="$VIRTUAL_ENV/share/securescan/alembic.ini"
alembic -c "$ALEMBIC_CONFIG" upgrade head
```

The installed API resolves that same packaged migration graph for readiness.
Use the source distribution/checkout and documented Compose flow for the
managed Docker operator deployment, because `compose.yaml` builds the supplied
Dockerfile. A standalone installed wheel can run the API and trusted-host CLI
when database, storage roots, Enry, scanners, and worker are explicitly
provisioned.

Do not reuse a preserved production database for install tests. Use a unique
disposable PostgreSQL database ending in `_test`, migrate zero-to-head, exercise
readiness/API/UI, then remove it.
