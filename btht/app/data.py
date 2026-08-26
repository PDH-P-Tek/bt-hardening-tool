"""Locations of the shipped data files.

The catalogues live at the repository root, where every document in the design
package refers to them. Resolving them through here means the app has one place
to change if they are later moved into the package for distribution.
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

ISA_CHECKS = REPO_ROOT / "isa-checks.yaml"
SERVICE_CATALOGUE = REPO_ROOT / "service-catalogue.yaml"
SEED_PROFILE = REPO_ROOT / "seed-profile.yaml"
ENCLAVE_TEMPLATES = REPO_ROOT / "templates"

#: Per-team policy files. Working data, never committed.
ESTATES = REPO_ROOT / "data" / "estates"
