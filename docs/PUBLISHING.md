# Publishing NetScope

The PyPI distribution name is `cmtrl-netscope`. The CLI command and Python
module are both still `netscope`.

`netscope-cli` belongs to another project on PyPI. A package name that returns
404 is not reserved or guaranteed to be available until PyPI accepts the upload.

## One-time account setup

Sign in to your own [PyPI account](https://pypi.org/account/publishing/).
If you need to register, complete PyPI's account verification and 2FA setup first.

Under **Add a new pending publisher**, select GitHub and enter:

| Field | Value |
| --- | --- |
| PyPI project name | `cmtrl-netscope` |
| Owner | `cmtrl` |
| Repository name | `netscope` |
| Workflow name | `publish.yml` |
| Environment name | `pypi` |

Save the pending publisher. It creates the PyPI project on the first successful
upload. No API token needs to be copied into chat or GitHub secrets.

This follows [PyPI's pending publisher setup](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/).

## Publish

In GitHub, open **Actions → Publish to PyPI → Run workflow** and select `main`.
The workflow tests the code, builds and checks both distributions, then publishes
using GitHub's identity. It does not run automatically on ordinary commits.

After a successful upload, test installation in a fresh virtual environment:

```bash
python -m venv .venv-release
source .venv-release/bin/activate
python -m pip install cmtrl-netscope
netscope --version
netscope --help
```

Update the README to show the PyPI installation command after the release is live.

## Later releases

Bump the version in both `pyproject.toml` and `netscope/utils.py`, commit the
changes, and run the workflow again. PyPI does not allow replacing an uploaded
distribution file with another file of the same name.

For a local packaging check:

```bash
python -m pip install build twine
python -m build
python -m twine check --strict dist/*
```
