Contributing to Sandroid
========================

We welcome contributions to Sandroid! This guide explains how to contribute effectively.

Development Setup
-----------------

.. code-block:: bash

   # Clone repository
   git clone https://github.com/fkie-cad/Sandroid_core.git
   cd Sandroid_core

   # Install in development mode
   pip install -e .[dev]

   # Initialize configuration
   sandroid-config init

   # Run tests
   pytest

Code Guidelines
---------------

Follow the comprehensive coding guidelines outlined in `CODING_GUIDELINES.md <../../CODING_GUIDELINES.md>`_:

- Write clean, self-documenting code following Python PEP 8 standards
- Use meaningful variable and function names (snake_case for functions, PascalCase for classes)
- Add comprehensive tests for new features (aim for 80%+ coverage)
- Update documentation and docstrings
- Follow existing Sandroid architectural patterns
- Implement proper error handling and logging
- Follow SOLID principles and maintain DRY code

For complete details on code style, testing requirements, security practices, and Sandroid-specific patterns, see the full `CODING_GUIDELINES.md <../../CODING_GUIDELINES.md>`_ document.

Submitting Changes
------------------

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Update documentation
6. Submit a pull request

For more details, see the AUTHORS.md file.
