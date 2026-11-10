# Publishing a release

The package on PyPI is `cmtrl-netscope`. The command and Python module are both
named `netscope`.

Trusted Publishing is already configured for `cmtrl/netscope`, using
`.github/workflows/publish.yml` and the `pypi` environment. It publishes through
GitHub Actions without a saved PyPI API token.

## Before a release

1. Update the version in `pyproject.toml` and `netscope/utils.py`.
2. Add the changes to `CHANGELOG.md`.
3. Run the tests and packaging checks below.
4. Commit the changes, push them, and check that CI passes on `main`.

```bash
python -m pip install build twine ruff
python -W error -m unittest discover -s tests -v
ruff check .
ruff format --check .
python -m build
python -m twine check --strict dist/*
```

Use a fresh `dist/` directory so files from an older release don't get uploaded.
The version check in the test suite catches mismatches between the two files.

## Upload

Open **Actions → Publish to PyPI → Run workflow** in GitHub and select `main`.
The workflow runs the platform checks, builds the wheel and source archive,
checks them, then uploads to PyPI. Publishing is started manually.

Check installation in a fresh virtual environment after the upload:

```bash
python -m pip install cmtrl-netscope
netscope --version
netscope --help
netscope-demo --help
```

Then add a GitHub release with the matching version tag and release notes.
PyPI won't let you replace an uploaded file, so a correction needs a new version.

If the publisher ever needs to be recreated, use the project's **Publishing**
settings on PyPI. The GitHub owner is `cmtrl`, repository `netscope`, workflow
`publish.yml`, and environment `pypi`. See the
[PyPI instructions](https://docs.pypi.org/trusted-publishers/adding-a-publisher/).
