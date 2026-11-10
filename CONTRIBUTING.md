# Contributing

Found a bug? Open an issue with your OS, Python and NetScope versions, the
command you ran, and what happened. A small local example helps. Remove private
hostnames and any header values you don't want to make public before attaching
output.

For code changes, install from source in a virtual environment:

```bash
python -m pip install -e .
python -m pip install ruff
python -W error -m unittest discover -s tests -v
ruff check .
ruff format --check .
```

Add a regression test when you fix a bug. Tests should use local servers or
controlled simulation. Update the reference when an option or report field
changes, and describe what you changed in the pull request.
