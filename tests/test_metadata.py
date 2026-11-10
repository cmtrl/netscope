"""Keep source installs and wheel releases consistent as the project changes."""

from pathlib import Path
import tomllib
import unittest

from netscope import __version__


class ReleaseMetadataTests(unittest.TestCase):
    def test_project_version_matches_installed_module(self):
        root = Path(__file__).resolve().parents[1]
        project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        self.assertEqual(project["version"], __version__)

    def test_both_installation_methods_use_the_same_dependencies(self):
        root = Path(__file__).resolve().parents[1]
        project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        requirements = {
            line.strip()
            for line in (root / "requirements.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        self.assertEqual(set(project["dependencies"]), requirements)
