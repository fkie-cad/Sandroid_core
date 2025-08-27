Testing
=======

Sandroid uses pytest for testing. This guide covers testing practices and procedures.

Running Tests
-------------

.. code-block:: bash

   # Run all tests
   pytest

   # Run with coverage
   pytest --cov=src/sandroid --cov-report=html

   # Run specific test categories
   pytest tests/unit/
   pytest tests/integration/

Test Structure
--------------

- **Unit Tests**: Test individual components
- **Integration Tests**: Test component interaction
- **Configuration Tests**: Test configuration validation
- **End-to-End Tests**: Test complete workflows

Writing Tests
-------------

Follow pytest conventions:

.. code-block:: python

   def test_feature_functionality():
       # Arrange
       feature = MyFeature()

       # Act
       result = feature.run()

       # Assert
       assert result is not None

Mock Testing
------------

Use mocks for external dependencies:

.. code-block:: python

   from unittest.mock import patch

   @patch('sandroid.core.adb.Adb.send_adb_command')
   def test_adb_interaction(mock_adb):
       mock_adb.return_value = ("success", "")
       # Test logic here

Testing Standards
-----------------

For comprehensive testing guidelines including coverage requirements, test quality standards, security testing practices, and Sandroid-specific testing patterns, see the `Coding Guidelines <../../CODING_GUIDELINES.md>`_.

These guidelines cover:
- Test coverage requirements (80%+ for critical paths)
- Test naming conventions and structure
- Mock testing best practices
- Integration test patterns
- Security test considerations

For CI/CD testing, see the deployment documentation.
