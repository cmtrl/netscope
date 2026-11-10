# Contributing

Bug reports, documentation fixes, and small improvements are welcome.

For a bug report, include your operating system, Python version, NetScope
version, the command, and what you expected. Replace private hostnames or other
sensitive data before attaching a report. A local reproduction is especially
helpful.

For a code change:

1. Install from source with `python -m pip install -e .` in a virtual environment.
2. Make a focused change and add a regression test when behavior changes.
3. Run `python -W error -m unittest discover -s tests -v`.
4. Run `ruff check .` and `ruff format --check .`.
5. Explain the behavior and checks in your pull request.

Tests must use local fixtures or controlled simulation rather than scan public
hosts. Update the README/reference when you change an option or report field.
