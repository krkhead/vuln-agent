"""
test_cve_lookup.py - Unit tests for CVE lookup and version matching
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from cve_lookup import _parse_version, _version_matches_range


def test_parse_version():
    """Test semantic version parsing."""
    assert _parse_version("1.2.3") == ((0, 1), (0, 2), (0, 3), (2, ""))
    assert _parse_version("2.0.0-beta") == ((0, 2), (0, 0), (0, 0), (1, "beta"))
    assert _parse_version("1.2.3-rc1") == ((0, 1), (0, 2), (0, 3), (1, "rc1"))
    print("[PASS] Version parsing tests passed")


def test_version_matching():
    """Test version range matching logic."""
    # Version within range
    match_data = {"versionStartIncluding": "1.0", "versionEndExcluding": "2.0"}
    assert _version_matches_range("1.5", match_data) is True

    # Version below minimum
    assert _version_matches_range("0.9", match_data) is False

    # Version at or above exclusive maximum
    assert _version_matches_range("2.0", match_data) is False

    # Version below exclusive maximum
    assert _version_matches_range("1.99", match_data) is True

    # No version constraints (assume vulnerable)
    assert _version_matches_range("1.0", {}) is True

    # Empty version (assume vulnerable)
    assert _version_matches_range("", {"versionStartIncluding": "1.0"}) is True

    print("[PASS] Version matching tests passed")


def test_version_comparison():
    """Test version comparison operators."""
    # Semantic version comparison
    assert _parse_version("1.2.3") < _parse_version("1.2.4")
    assert _parse_version("1.2.3") < _parse_version("1.3.0")
    assert _parse_version("2.0.0") > _parse_version("1.99.99")

    # Pre-release versions (numbers before strings in sort order)
    assert _parse_version("1.2.3-alpha") < _parse_version("1.2.3-beta")
    assert _parse_version("1.2.3-beta") < _parse_version("1.2.3")

    print("[PASS] Version comparison tests passed")


if __name__ == "__main__":
    test_parse_version()
    test_version_matching()
    test_version_comparison()
    print("\n[PASS] All CVE lookup tests passed!")
