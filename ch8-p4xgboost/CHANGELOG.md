# Changelog

All notable changes to this project will be documented in this file.

## [v1.1.0] - 2026-06-15
### Added
- Modularized controller into `core`, `ml`, and `p4` architecture.
- Full test suite evaluating models and features via pytest.
- Configuration YAML specifying pipeline thresholds.
- P4Runtime interface for modular rules handling.

### Changed
- Removed single-file controller.py implementation.
- Refactored imports to align with standard Python packaging.
