# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

import os
import sys

sys.path.insert(0, os.path.abspath("../"))

project = "Sandroid"
copyright = "2024, Erik Nathrath"
author = "Erik Nathrath"
release = "0.4.1"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
"sphinx.ext.autodoc",
"myst_parser"
]
autodoc_mock_imports = ["src.utils.toolbox"]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "agogo"
html_static_path = ["_static"]
html_theme_options = {
    "headerfont": "Monaco",
    "headerbg": "#179c7d",
    "headercolor1": "#179c7d",
    "headerlinkcolor": "#ffffff"
}
