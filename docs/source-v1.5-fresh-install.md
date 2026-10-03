# SecureScan Source V1.5 fresh installation

Build release artifacts from the tagged source on Python 3.12:

```bash
python -m build
python -m venv /tmp/securescan-v15
/tmp/securescan-v15/bin/pip install 'dist/securescan_core-0.1.0-py3-none-any.whl[postgres]'
/tmp/securescan-v15/bin/securescan --help
```

The Core distribution keeps version `0.1.0`; `source-v1.5.1` is the independent
Source product hotfix tag and `source-v1.5.0` remains its immutable product
baseline. The wheel installs Alembic configuration/migrations and V1.5
documentation/examples under the environment's `share/securescan`.

For a managed local deployment, create a restricted `KEY=VALUE` input and let
SecureScan write its private application profile:

```bash
export SECURESCAN_OPERATOR_PROFILE="$HOME/.config/securescan/v15-final.profile"
securescan system configure --from-env-file /tmp/securescan-v15-final.env
rm -f /tmp/securescan-v15-final.env
securescan system config
securescan doctor
securescan init
securescan system up
```

Do **not** source `$SECURESCAN_OPERATOR_PROFILE`. It is versioned SecureScan
JSON and is loaded automatically. The input should configure scanner paths.
For the release-built Enry helper, configure supplies the packaged frozen V1.5
digest when no explicit independently trusted digest is present. A custom
helper requires its own independently obtained digest; SecureScan never trusts
a digest calculated from the runtime file merely because that file exists.

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
provisioned. Its `system configure`, `system config`, profile loading, and
doctor diagnostics are the same as the source checkout; the wheel does not
bundle scanner executables.

Do not reuse a preserved production database for install tests. Use a unique
disposable PostgreSQL database ending in `_test`, migrate zero-to-head, exercise
readiness/API/UI, then remove it.
