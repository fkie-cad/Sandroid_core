# src/sandroid/_about.py
from ._version import __version__

__authors__ = [
    {"name": "Erik Nathrath", "email": "erik.nathrath@fkie.fraunhofer.de"},
    {"name": "Daniel Baier", "email": "daniel.baier@fkie.fraunhofer.de"},
    {"name": "Jan-Niclas Hilgert", "email": "jan-niclas.hilgert@fkie.fraunhofer.de"},
]
__author__ = ", ".join(a["name"] for a in __authors__)
__email__ = "daniel.baier@fkie.fraunhofer.de"
__description__ = (
    "An Android sandbox for automated Forensic, Malware, and Security Analysis"
)
