"""Sphinx configuration for the uvctl documentation.

Trust role: none; documentation build only. The API reference is generated from
the in-code Google-style docstrings via autodoc + napoleon.
"""

import os
import sys

sys.path.insert(0, os.path.abspath("../src"))

project = "uvctl"
author = "attackd"
copyright = "2026, attackd"  # noqa: A001

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
]

exclude_patterns = ["_build"]

# Napoleon: Google style only.
napoleon_google_docstring = True
napoleon_numpy_docstring = False

autodoc_typehints = "description"
autodoc_member_order = "bysource"
add_module_names = False

html_theme = "furo"
html_title = "uvctl"
