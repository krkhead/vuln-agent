# VulnAgent Tests

Basic unit test suite for core modules.

## Running Tests

```bash
# Run individual test modules
python tests/test_cve_lookup.py
python tests/test_trend.py

# Or with pytest (if installed)
pytest tests/

# Run with verbose output
pytest tests/ -v
```

## Test Coverage

- `test_cve_lookup.py` — Version parsing, range matching, comparison operators
- `test_trend.py` — Database initialization, scan logging, trend queries

## Requirements

- Python 3.9+
- `pytest` (optional, but recommended)

```bash
pip install pytest
```
