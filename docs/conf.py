# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------
import os
import sys
from pathlib import Path

# Add the package to Python path for autodoc
sys.path.insert(0, str(Path("../src").resolve()))

# -- Project information -----------------------------------------------------
project = "Sandroid"
project_copyright = "2024, Fraunhofer FKIE"
author = "Erik Nathrath, Daniel Baier, Jan-Niclas Hilgert"
version = "1.1.0"
release = "1.1.0"

# -- General configuration ---------------------------------------------------
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.viewcode",
    "sphinx.ext.napoleon",
    "sphinx.ext.intersphinx",
    "sphinx.ext.todo",
    "myst_parser",
]

# Autodoc configuration
autodoc_default_options = {
    "members": True,
    "member-order": "bysource",
    "special-members": "__init__",
    "undoc-members": True,
    "exclude-members": "__weakref__",
}

# Mock imports for external dependencies that may not be available during build
autodoc_mock_imports = [
    "frida",
    "objection",
    "scapy",
    "AndroidFridaManager",
    "trigdroid",
    "friTap",
    "dexray_intercept",
    "dexray_insight",
    "colorama",
    "beautifulsoup4",
    "reportlab",
    "geopy",
    "lxml",
]

# Autosummary
autosummary_generate = True

# Napoleon settings for Google/NumPy style docstrings
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = False
napoleon_include_private_with_doc = False

# Intersphinx mapping
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "frida": ("https://frida.re/docs/", None),
}

# Templates and static paths
templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# Source file suffixes
source_suffix = {
    ".rst": None,
    ".md": "myst_parser",
}

# Master document
master_doc = "index"

# -- Options for HTML output -------------------------------------------------
html_theme = "sphinx_rtd_theme"
html_theme_options = {
    "canonical_url": "",
    "analytics_id": "",
    "logo_only": False,
    "display_version": True,
    "prev_next_buttons_location": "bottom",
    "style_external_links": False,
    "vcs_pageview_mode": "",
    "style_nav_header_background": "#179c7d",
    # Toc options
    "collapse_navigation": True,
    "sticky_navigation": True,
    "navigation_depth": 4,
    "includehidden": True,
    "titles_only": False,
}

html_static_path = ["_static"]
html_logo = "../assets/sandroid_logo.png"
html_favicon = "../assets/sandroid_logo.png"

# Custom CSS
html_css_files = [
    "custom.css",
]

# -- Options for LaTeX output ------------------------------------------------
latex_elements = {
    "papersize": "letterpaper",
    "pointsize": "10pt",
    "preamble": "",
    "fncychap": "\\usepackage[Bjornstrup]{fncychap}",
    "printindex": "\\footnotesize\\raggedright\\printindex",
}

# -- Options for manual page output ------------------------------------------
man_pages = [(master_doc, "sandroid", "Sandroid Documentation", [author], 1)]

# -- Options for Texinfo output ----------------------------------------------
texinfo_documents = [
    (
        master_doc,
        "Sandroid",
        "Sandroid Documentation",
        author,
        "Sandroid",
        "Android forensic analysis framework.",
        "Miscellaneous",
    ),
]

# -- Extension configuration -------------------------------------------------
# TODO extension
todo_include_todos = True

# -- MyST configuration ------------------------------------------------------
myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "html_admonition",
    "html_image",
    "replacements",
    "smartquotes",
    "substitution",
    "tasklist",
]
