Contributing to Sandroid
========================

We welcome contributions to Sandroid! This guide explains how to contribute effectively.

Development Setup
-----------------

.. code-block:: bash

   # Clone repository
   git clone https://github.com/fkie-cad/Sandroid_core.git
   cd Sandroid_core

   # Work happens on the dev branch
   git switch dev

   # Install in development mode (Python 3.12+)
   pip install -e ".[dev,full]"
   pre-commit install

   # Run tests and linters (same as CI)
   pytest
   ruff check .
   ruff format --check .

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
2. Create a feature branch off ``dev``
3. Make your changes
4. Add tests (they must not touch a real device -- see :doc:`testing`)
5. Update documentation and ``CHANGELOG.md``
6. Submit a pull request against ``dev``

Releases are cut from ``dev`` to ``main``; the procedure is described in the
*Release Process* section of ``CODING_GUIDELINES.md``.
