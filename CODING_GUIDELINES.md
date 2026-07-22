# Sandroid Coding Guidelines

This document outlines the coding standards, best practices, and development guidelines for the Sandroid project. Following these guidelines ensures code quality, maintainability, and consistency across the entire codebase.

## Table of Contents

- [Core Principles](#core-principles)
- [Python Code Standards](#python-code-standards)
- [Architecture Guidelines](#architecture-guidelines)
- [Sandroid-Specific Patterns](#sandroid-specific-patterns)
- [Testing Requirements](#testing-requirements)
- [Security Considerations](#security-considerations)
- [Documentation Standards](#documentation-standards)
- [Development Workflow](#development-workflow)
- [Code Modification Protocol](#code-modification-protocol)
- [Performance Guidelines](#performance-guidelines)
- [Error Handling](#error-handling)

## Core Principles

### Preservation and Backward Compatibility

- Maintain backward compatibility for public APIs

### SOLID Principles

- **Single Responsibility**: Each class/function should have one reason to change
- **Open/Closed**: Open for extension, closed for modification
- **Liskov Substitution**: Derived classes must be substitutable for base classes
- **Interface Segregation**: Many specific interfaces are better than one general-purpose interface
- **Dependency Inversion**: Depend on abstractions, not concretions

### Code Quality Characteristics

- **Readable**: Code should read like well-written prose
- **Self-documenting**: Variable and function names should clearly express intent
- **Consistent**: Follow established patterns and conventions within the codebase
- **Simple**: Prefer simple solutions over clever ones
- **DRY**: Don't Repeat Yourself - extract common functionality
- **YAGNI**: You Aren't Gonna Need It - don't over-engineer

## Python Code Standards

### PEP 8 Compliance

Follow [PEP 8](https://peps.python.org/pep-0008/) with these specific requirements:

```python
# Line length: 88 characters (Black formatter standard)
# Use double quotes for strings
name = "sandroid_analysis"

# Import organization
import os
import sys
from pathlib import Path

import requests
from pydantic import BaseModel

from sandroid.core.toolbox import Toolbox
from sandroid.analysis.base_di import DataGatherBase
```

### Naming Conventions

```python
# Classes: PascalCase
class AnalysisModule:
    pass

# Functions and variables: snake_case
def analyze_network_traffic():
    device_name = "Pixel_6_Pro_API_31"

# Constants: UPPER_SNAKE_CASE
DEFAULT_TIMEOUT = 30
SANDROID_VERSION = "1.1.0"

# Private methods: leading underscore
def _internal_helper_method(self):
    pass

# File names: lowercase with underscores
# network_analysis.py, frida_manager.py
```

### Type Hints

Use type hints throughout the codebase:

```python
from typing import Dict, List, Optional, Union
from pathlib import Path

def analyze_files(file_paths: List[Path], timeout: Optional[int] = None) -> Dict[str, str]:
    """Analyze a list of files and return results."""
    results: Dict[str, str] = {}
    # Implementation here
    return results

class AnalysisResult:
    def __init__(self, data: Dict[str, Union[str, int, List[str]]]) -> None:
        self.data = data
```

### Function and Class Structure

```python
# Keep functions small and focused (ideally < 20 lines)
def get_device_architecture() -> str:
    """Get the architecture of the connected Android device."""
    stdout, stderr = Adb.send_adb_command("shell getprop ro.product.cpu.abi")
    if stderr:
        raise DeviceError(f"Failed to get architecture: {stderr}")
    return stdout.strip()

# Use clear, descriptive names
def extract_changed_files_between_snapshots(first_snapshot: Dict, second_snapshot: Dict) -> List[str]:
    """Compare two filesystem snapshots and return list of changed files."""
    pass

# Group related functionality together
class NetworkAnalysis:
    def __init__(self):
        self.connections = []
        self.dns_queries = []

    def capture_traffic(self) -> None:
        """Start network traffic capture."""
        pass

    def analyze_connections(self) -> Dict[str, List[str]]:
        """Analyze captured network connections."""
        pass

    def generate_report(self) -> str:
        """Generate network analysis report."""
        pass
```

## Architecture Guidelines

### Module Organization

Sandroid follows a specific architecture pattern:

```
src/sandroid/
├── core/           # Core functionality (Toolbox, ADB, ActionQ)
├── analysis/       # Data gathering modules (inherit from DataGatherBase)
├── features/       # Enhanced functionality (inherit from Functionality)
├── config/         # Configuration management
└── cli.py          # Command-line interface
```

### Base Class Inheritance

All analysis modules must inherit from `DataGatherBase`:

```python
from sandroid.analysis.base_di import DataGatherBase
from logging import getLogger

class CustomAnalyzer(DataGatherBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.logger = getLogger(__name__)

    def gather(self) -> None:
        """Collect data from the device."""
        # Implementation here

    def return_data(self) -> Dict[str, Any]:
        """Return structured analysis results."""
        return {"Custom Analysis": self.results}

    def pretty_print(self) -> str:
        """Return formatted output for display."""
        return f"Custom Analysis: {len(self.results)} items found"

    def process_data(self) -> List[Any]:
        """Process and filter collected data."""
        # Apply noise filtering and whitelist rules
        return processed_data
```

All feature modules must inherit from `Functionality`:

```python
from sandroid.features.functionality import Functionality

class CustomFeature(Functionality):
    def __init__(self):
        super().__init__()
        self.feature_name = "Custom Feature"

    def run(self) -> None:
        """Execute the feature."""
        # Implementation here

    def cleanup(self) -> None:
        """Clean up resources."""
        # Cleanup logic here
```

### Configuration Integration

Use the configuration system throughout:

```python
from sandroid.config.loader import load_config

def initialize_analysis():
    config = load_config()

    # Use configuration values
    device_name = config.emulator.device_name
    timeout = config.analysis.timeout

    # Respect user settings
    if config.analysis.monitor_network:
        start_network_monitoring()
```

## Sandroid-Specific Patterns

### ADB Command Pattern

```python
from sandroid.core.adb import Adb

def get_installed_packages() -> List[str]:
    """Get list of installed packages."""
    stdout, stderr = Adb.send_adb_command("shell pm list packages -3")
    if stderr:
        logger.warning(f"ADB command warning: {stderr}")

    packages = []
    for line in stdout.splitlines():
        if line.startswith("package:"):
            packages.append(line.replace("package:", ""))

    return packages
```

### Error Handling Pattern

```python
class SandroidError(Exception):
    """Base exception for Sandroid-specific errors."""
    pass

class DeviceError(SandroidError):
    """Raised when device operations fail."""
    pass

def safe_device_operation():
    try:
        result = perform_device_operation()
        return result
    except DeviceError as e:
        logger.error(f"Device operation failed: {e}")
        # Attempt recovery or provide fallback
        return fallback_operation()
    except Exception as e:
        logger.critical(f"Unexpected error: {e}")
        raise SandroidError(f"Critical failure: {e}") from e
```

### Logging Pattern

```python
import logging
from pathlib import Path

# Use module-level loggers
logger = logging.getLogger(__name__)

def analysis_function():
    logger.debug("Starting analysis with parameters: %s", params)
    logger.info("Analysis completed successfully")
    logger.warning("Potential issue detected: %s", issue)
    logger.error("Analysis failed: %s", error)

    # Include context in log messages
    logger.info("Found %d changed files in %s", len(files), directory)
```

### Resource Management Pattern

```python
import contextlib
from typing import Generator

@contextlib.contextmanager
def frida_session(device_id: str) -> Generator[FridaSession, None, None]:
    """Context manager for Frida sessions."""
    session = None
    try:
        session = establish_frida_session(device_id)
        yield session
    except Exception as e:
        logger.error(f"Frida session error: {e}")
        raise
    finally:
        if session:
            session.cleanup()

# Usage
with frida_session("emulator-5554") as session:
    perform_dynamic_analysis(session)
```

## Testing Requirements

Right now we don't have tests for the current version but when introducing new features we should follow these testing requirements.

### Test Coverage

- Write tests for all new functions and classes
- Aim for 80%+ test coverage for critical paths
- Include unit tests, integration tests, and end-to-end tests as appropriate
- Test both happy path and edge cases

### Test Structure

```python
import pytest
from unittest.mock import patch, MagicMock

class TestNetworkAnalysis:
    def setup_method(self):
        """Setup before each test."""
        self.analyzer = NetworkAnalysis()

    def test_capture_traffic_success(self):
        """Test successful traffic capture."""
        # Arrange
        expected_connections = ["192.168.1.1:80", "google.com:443"]

        # Act
        result = self.analyzer.capture_traffic()

        # Assert
        assert result is not None
        assert len(result.connections) > 0

    @patch('sandroid.core.adb.Adb.send_adb_command')
    def test_capture_traffic_with_mock_adb(self, mock_adb):
        """Test traffic capture with mocked ADB."""
        # Arrange
        mock_adb.return_value = ("tcp 192.168.1.1:80", "")

        # Act
        result = self.analyzer.capture_traffic()

        # Assert
        mock_adb.assert_called_once()
        assert "192.168.1.1:80" in result.connections

    def test_invalid_device_raises_error(self):
        """Test that invalid device raises appropriate error."""
        with pytest.raises(DeviceError):
            self.analyzer.analyze_invalid_device()
```

### Mock Usage Guidelines

```python
# Mock external dependencies
@patch('sandroid.core.frida_manager.frida.get_usb_device')
def test_frida_interaction(self, mock_frida):
    mock_device = MagicMock()
    mock_frida.return_value = mock_device

    # Test logic here

# Mock file system operations
@patch('pathlib.Path.exists')
@patch('pathlib.Path.read_text')
def test_file_operations(self, mock_read, mock_exists):
    mock_exists.return_value = True
    mock_read.return_value = "test content"

    # Test logic here
```

## Security Considerations

### Forensic Tool Security Patterns

Since Sandroid is a forensic analysis tool, certain security practices are different:

```python
# Subprocess usage is legitimate for ADB/emulator control
import subprocess

def execute_adb_command(command: str) -> str:
    """Execute ADB command safely."""
    # Input validation
    if not command.startswith(('shell', 'install', 'pull', 'push')):
        raise ValueError(f"Invalid ADB command: {command}")

    # Use subprocess for legitimate forensic operations
    result = subprocess.run(['adb'] + command.split(),
                          capture_output=True, text=True, timeout=30)
    return result.stdout

# Hash usage is for file integrity, not cryptographic security
import hashlib

def calculate_file_hash(file_path: Path) -> str:
    """Calculate MD5 hash for file integrity checking."""
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()
```

### Input Validation

```python
import re

def validate_device_name(device_name: str) -> str:
    """Validate Android device name."""
    if not device_name or not device_name.strip():
        raise ValueError("Device name cannot be empty")

    # Allow alphanumeric, underscore, hyphen
    if not re.match(r'^[a-zA-Z0-9_-]+$', device_name):
        raise ValueError("Invalid device name format")

    return device_name.strip()

def validate_file_path(file_path: str) -> Path:
    """Validate file path for security."""
    path = Path(file_path).resolve()

    # Prevent directory traversal
    if '..' in str(path):
        raise ValueError("Directory traversal not allowed")

    return path
```

### Sensitive Data Handling

```python
# Never log sensitive information
def connect_to_device(device_id: str, auth_token: Optional[str] = None):
    logger.info(f"Connecting to device: {device_id}")
    # DO NOT log auth_token

    if auth_token:
        logger.debug("Using authentication token")  # Don't log the actual token

    # Use configuration for sensitive values
    config = load_config()
    api_key = config.ai.api_key  # Loaded from environment or secure config
```

## Documentation Standards

### Docstring Format

Use Google-style docstrings:

```python
def analyze_network_traffic(interface: str, duration: int = 60) -> Dict[str, List[str]]:
    """Analyze network traffic on specified interface.

    Args:
        interface: Network interface to monitor (e.g., 'eth0', 'wlan0')
        duration: Monitoring duration in seconds (default: 60)

    Returns:
        Dictionary containing:
            - 'connections': List of network connections
            - 'dns_queries': List of DNS queries observed

    Raises:
        DeviceError: If network interface is not available
        TimeoutError: If analysis times out

    Example:
        >>> analyzer = NetworkAnalyzer()
        >>> result = analyzer.analyze_network_traffic('eth0', 120)
        >>> print(f"Found {len(result['connections'])} connections")
    """
```

### Code Comments

```python
# Use comments for complex business logic
def calculate_noise_filter_threshold(file_changes: List[str]) -> float:
    # Sandroid uses a dynamic noise filtering algorithm based on
    # the ratio of system files to application files changed
    system_files = [f for f in file_changes if f.startswith('/system/')]
    app_files = [f for f in file_changes if '/data/data/' in f]

    # If more than 70% are system files, increase noise threshold
    if len(system_files) / len(file_changes) > 0.7:
        return 0.8  # Higher threshold = more filtering
    else:
        return 0.3  # Lower threshold = less filtering
```

### API Documentation

```python
class NetworkAnalyzer:
    """Network traffic analysis for Android devices.

    This class provides comprehensive network monitoring capabilities
    including connection tracking, DNS query logging, and traffic
    pattern analysis.

    Attributes:
        interface: Network interface being monitored
        capture_duration: Duration of traffic capture in seconds
        connections: List of observed network connections

    Example:
        >>> analyzer = NetworkAnalyzer('eth0')
        >>> analyzer.start_capture()
        >>> results = analyzer.get_results()
    """
```

## Development Workflow

### Git Practices

```bash
# Branch naming
feature/network-analysis-enhancement
bugfix/frida-connection-timeout
hotfix/security-vulnerability-fix

# Commit messages
git commit -m "feat: add SSL/TLS traffic interception

- Implement friTap integration for HTTPS monitoring
- Add certificate analysis capabilities
- Update network analyzer to handle encrypted traffic

Closes #123"

# Commit message format:
# <type>: <description>
#
# <body>
#
# <footer>
```

### Code Review Checklist

Before submitting code:

- [ ] All tests pass: `pytest`
- [ ] Code is formatted: `black src/`
- [ ] Imports are sorted: `isort src/`
- [ ] Linting passes: `ruff check src/`
- [ ] Type checking passes: `mypy src/`
- [ ] Documentation updated
- [ ] Configuration changes documented
- [ ] Backward compatibility maintained

### Continuous Integration

```python
# Test all Python versions
def test_python_version_compatibility():
    """Ensure code works on Python 3.10+"""
    import sys
    assert sys.version_info >= (3, 10)

# Test on different platforms
def test_cross_platform_paths():
    """Test path handling across platforms"""
    from pathlib import Path
    path = Path("results") / "analysis.json"
    assert path.exists() or not path.exists()  # Path should be valid
```

## Code Modification Protocol

When working with existing code:

1. **Analyze first**: Understand what the existing code does
2. **Explain changes**: Describe what modifications you plan to make
3. **Ask permission**: Request confirmation before deleting or significantly altering code
4. **Show alternatives**: Present options when multiple approaches are possible
5. **Test thoroughly**: Ensure all changes are properly tested

### Refactoring Guidelines

```python
# Before refactoring - document the current behavior
def legacy_function(data):
    """Legacy implementation of data processing.

    Note: This function has complex logic that handles edge cases
    for older Android versions. Be careful when modifying.
    """
    # ... existing implementation

# After refactoring - preserve behavior
def modern_function(data):
    """Modern implementation with improved error handling.

    Maintains backward compatibility with legacy_function().
    Improvements:
    - Better error messages
    - Type hints added
    - Performance optimization for large datasets
    """
    # ... new implementation with same external behavior
```

## Performance Guidelines

### Efficient Algorithms

```python
# Use appropriate data structures
from collections import defaultdict, deque
from typing import Set

def analyze_file_changes_efficiently(files: List[str]) -> Dict[str, List[str]]:
    """Efficiently categorize file changes."""
    # Use defaultdict to avoid key checking
    categories = defaultdict(list)

    # Use sets for fast lookup
    system_prefixes = {'/system/', '/vendor/', '/apex/'}

    for file_path in files:
        for prefix in system_prefixes:
            if file_path.startswith(prefix):
                categories['system'].append(file_path)
                break
        else:
            categories['user'].append(file_path)

    return dict(categories)
```

### Resource Management

```python
# Use context managers for resource cleanup
def process_large_dataset(file_path: Path):
    """Process large files efficiently."""
    with open(file_path, 'r') as file:
        # Process in chunks to avoid memory issues
        while True:
            chunk = file.readlines(1000)  # Read 1000 lines at a time
            if not chunk:
                break
            process_chunk(chunk)

# Cache expensive operations
from functools import lru_cache

@lru_cache(maxsize=128)
def get_device_info(device_id: str) -> Dict[str, str]:
    """Get device info with caching."""
    # Expensive ADB operation
    return fetch_device_info(device_id)
```

## Error Handling

### Exception Hierarchy

```python
class SandroidError(Exception):
    """Base exception for all Sandroid errors."""
    pass

class ConfigurationError(SandroidError):
    """Configuration-related errors."""
    pass

class DeviceError(SandroidError):
    """Device communication errors."""
    pass

class AnalysisError(SandroidError):
    """Analysis operation errors."""
    pass

class FridaError(SandroidError):
    """Frida-related errors."""
    pass
```

### Error Handling Patterns

```python
def robust_analysis_function():
    """Example of robust error handling."""
    try:
        # Attempt primary operation
        result = perform_analysis()
        return result

    except DeviceError as e:
        logger.error(f"Device communication failed: {e}")
        # Attempt recovery
        if try_device_recovery():
            logger.info("Device recovery successful, retrying analysis")
            return perform_analysis()
        else:
            raise AnalysisError("Cannot recover device connection") from e

    except ConfigurationError as e:
        logger.error(f"Configuration error: {e}")
        # Provide helpful guidance
        logger.info("Try running: sandroid-config validate")
        raise

    except Exception as e:
        # Log unexpected errors with full context
        logger.exception(f"Unexpected error in analysis: {e}")
        raise SandroidError(f"Analysis failed: {e}") from e

    finally:
        # Always clean up resources
        cleanup_resources()
```

## Tools and Automation

### Development Tools Setup

```bash
# Install development dependencies
pip install -e .[dev]

# Setup pre-commit hooks
pre-commit install

# Run all quality checks
./scripts/quality-check.sh  # If available, or:
black src/
isort src/
ruff check src/
mypy src/
pytest
```

### IDE Configuration

For VS Code, use these settings in `.vscode/settings.json`:

```json
{
    "python.linting.enabled": true,
    "python.linting.ruffEnabled": true,
    "python.formatting.provider": "black",
    "python.sortImports.provider": "isort",
    "python.testing.pytestEnabled": true,
    "python.testing.unittestEnabled": false
}
```

---

## Conclusion

These guidelines ensure that Sandroid maintains high code quality, consistency, and reliability. They should be followed for all contributions to the project. When in doubt, look at existing code patterns and ask for clarification.

For questions about these guidelines or specific implementation details, please:

1. Check the existing codebase for similar patterns
2. Review the API documentation
3. Open an issue for discussion
4. Refer to the migration guide for legacy/modern patterns

**Remember**: The goal is to improve code quality while maintaining reliability and functionality. These guidelines exist to help, not hinder, development productivity.
