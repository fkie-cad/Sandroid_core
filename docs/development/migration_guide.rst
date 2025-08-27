Migration Guide
===============

This guide helps you migrate from the legacy Sandroid installation to the modern PyPI package, and understand the changes introduced in v1.1.0.

Migration Overview
------------------

**What Changed in v1.1.0:**

- Complete package restructuring from ``src/utils/`` to proper Python packages
- Modern PyPI distribution with all analysis modules included
- New configuration system with ``sandroid-config`` CLI tool
- Dual-mode architecture supporting both legacy and modern usage
- Fixed the critical "Legacy analysis modules not available" error

**Migration Types:**

1. **Gradual Migration** - Use both systems in parallel (recommended)
2. **Complete Migration** - Switch entirely to modern system
3. **Development Migration** - Update development workflows

Legacy to Modern Migration
--------------------------

**Current State Assessment:**

First, determine your current setup:

.. code-block:: bash

   # Check if you have legacy installation
   ls -la ./sandroid  # Legacy script exists?

   # Check if you have PyPI installation
   which sandroid    # Modern command available?
   sandroid --version  # Should show 1.1.0+

**Gradual Migration (Recommended):**

This approach lets you test the modern system while keeping the legacy system working:

.. code-block:: bash

   # 1. Keep your existing legacy installation
   # Don't remove anything yet

   # 2. Install modern PyPI package alongside
   pip install sandroid

   # 3. Test modern installation
   sandroid --version  # Should work without "legacy modules" error
   sandroid --help     # Should show full help

   # 4. Initialize modern configuration
   sandroid-config init

   # 5. Test side-by-side
   ./sandroid --help         # Legacy way (still works)
   sandroid --help           # Modern way (now also works)

**Configuration Migration:**

.. code-block:: bash

   # 1. Create modern configuration
   sandroid-config init

   # 2. Migrate settings from legacy hardcoded values
   # Check your current settings in src/utils/toolbox.py
   grep -r "device_name\|results_path\|number_of_runs" src/utils/

   # 3. Set corresponding values in modern config
   sandroid-config set emulator.device_name "Your_Current_Device"
   sandroid-config set paths.results_path "./results/"
   sandroid-config set analysis.number_of_runs 2

**Testing Migration:**

.. code-block:: bash

   # Test with identical parameters

   # Legacy way:
   ./sandroid -n 2 --network --screenshot 5

   # Modern way:
   sandroid --number 2 --network --screenshot 5

   # Compare results - they should be identical

**Complete Migration:**

Once you're confident the modern system works:

.. code-block:: bash

   # 1. Archive your legacy installation
   tar -czf sandroid_legacy_backup.tar.gz src/ utils/ *.py sandroid

   # 2. Update your scripts/aliases
   echo "alias sandroid-legacy='./sandroid'" >> ~/.bashrc
   echo "alias sandroid='sandroid'"  # Modern version is now default

   # 3. Update documentation and workflows
   # Replace ./sandroid with sandroid in scripts

Package Structure Migration
---------------------------

**Old Structure (Legacy):**

.. code-block:: text

   Sandroid_core/
   ├── src/
   │   ├── utils/           # Core utilities (15 modules)
   │   ├── datagather/      # Analysis modules (10 modules)
   │   └── functionality/   # Feature modules (5 modules)
   ├── sandroid             # Main script
   └── install-requirements.sh

**New Structure (Modern):**

.. code-block:: text

   Sandroid_core/
   ├── src/sandroid/
   │   ├── core/           # Was: src/utils/ (15 modules)
   │   ├── analysis/       # Was: src/datagather/ (10 modules)
   │   ├── features/       # Was: src/functionality/ (5 modules)
   │   ├── config/         # New: Configuration system
   │   └── cli.py          # New: Modern CLI entry point
   ├── src/utils/          # Compatibility aliases
   ├── src/datagather/     # Compatibility aliases
   ├── src/functionality/  # Compatibility aliases
   └── sandroid            # Still works (legacy compatibility)

**Import Path Changes:**

If you have custom code importing Sandroid modules:

.. code-block:: python

   # Old imports (still work via compatibility layer):
   from src.utils.toolbox import Toolbox
   from src.datagather.changedfiles import ChangedFiles
   from src.functionality.screenshot import Screenshot

   # New imports (recommended):
   from sandroid.core.toolbox import Toolbox
   from sandroid.analysis.changedfiles import ChangedFiles
   from sandroid.features.screenshot import Screenshot

Development Workflow Migration
-------------------------------

**Legacy Development Setup:**

.. code-block:: bash

   git clone https://github.com/fkie-cad/Sandroid_core.git
   cd Sandroid_core
   ./install-requirements.sh
   ./sandroid --help

**Modern Development Setup:**

.. code-block:: bash

   git clone https://github.com/fkie-cad/Sandroid_core.git
   cd Sandroid_core

   # Install in development mode
   pip install -e .[dev]

   # Initialize configuration
   sandroid-config init

   # Test installation
   sandroid --version
   sandroid --help

**CI/CD Migration:**

**Legacy CI Pipeline:**

.. code-block:: yaml

   - name: Setup Sandroid
     run: |
       git clone https://github.com/fkie-cad/Sandroid_core.git
       cd Sandroid_core
       ./install-requirements.sh

   - name: Run Analysis
     run: |
       cd Sandroid_core
       ./sandroid --network --report

**Modern CI Pipeline:**

.. code-block:: yaml

   - name: Setup Sandroid
     run: |
       pip install sandroid[ai]
       sandroid-config init

   - name: Run Analysis
     run: |
       sandroid --network --report

**Docker Migration:**

**Legacy Dockerfile:**

.. code-block:: dockerfile

   FROM python:3.10
   RUN git clone https://github.com/fkie-cad/Sandroid_core.git
   WORKDIR /app/Sandroid_core
   RUN ./install-requirements.sh
   CMD ["./sandroid"]

**Modern Dockerfile:**

.. code-block:: dockerfile

   FROM python:3.10
   RUN pip install sandroid[ai]
   RUN sandroid-config init
   CMD ["sandroid"]

Configuration System Migration
------------------------------

**Legacy Configuration (Hardcoded):**

Previously, configuration was hardcoded in ``src/utils/toolbox.py``:

.. code-block:: python

   # Old way - hardcoded values
   class Toolbox:
       device_name = "Pixel_6_Pro_API_31"
       results_path = "./results/"
       number_of_runs = 2

**Modern Configuration (File-based):**

Now configuration uses structured files:

.. code-block:: toml

   # ~/.config/sandroid/sandroid.toml
   log_level = "INFO"
   output_file = "sandroid.json"

   [emulator]
   device_name = "Pixel_6_Pro_API_31"

   [analysis]
   number_of_runs = 2

   [paths]
   results_path = "./results/"

**Environment Variable Migration:**

**Legacy:**

.. code-block:: bash

   export RESULTS_PATH="/custom/results"
   export RAW_RESULTS_PATH="/custom/raw"

**Modern:**

.. code-block:: bash

   export SANDROID_PATHS__RESULTS_PATH="/custom/results"
   export SANDROID_PATHS__RAW_RESULTS_PATH="/custom/raw"

API Migration Guide
-------------------

**For Developers Using Sandroid as a Library:**

**Legacy API Usage:**

.. code-block:: python

   # Old way
   sys.path.append('path/to/Sandroid_core/src')
   from utils.toolbox import Toolbox
   from datagather.changedfiles import ChangedFiles

   # Initialize and run
   toolbox = Toolbox()
   changed_files = ChangedFiles()
   changed_files.gather()

**Modern API Usage:**

.. code-block:: python

   # New way
   from sandroid.core.toolbox import Toolbox
   from sandroid.analysis.changedfiles import ChangedFiles
   from sandroid.config.loader import load_config

   # Initialize with configuration
   config = load_config()
   Toolbox.configure(config)

   # Use analysis modules
   changed_files = ChangedFiles()
   changed_files.gather()

**Custom Module Development:**

**Legacy Custom Module:**

.. code-block:: python

   # old_custom_module.py
   import sys
   sys.path.append('src/')
   from utils.toolbox import Toolbox
   from datagather.datagather import DataGather

   class CustomAnalyzer(DataGather):
       def gather(self):
           # Custom logic
           pass

**Modern Custom Module:**

.. code-block:: python

   # modern_custom_module.py
   from sandroid.core.toolbox import Toolbox
   from sandroid.analysis.datagather import DataGather
   from sandroid.config.loader import load_config

   class CustomAnalyzer(DataGather):
       def __init__(self):
           super().__init__()
           self.config = load_config()

       def gather(self):
           # Custom logic with configuration support
           pass

Breaking Changes and Compatibility
----------------------------------

**No Breaking Changes for End Users:**

- All CLI commands work identically
- All analysis results are the same format
- All interactive menu options unchanged
- Legacy ``./sandroid`` script still works

**Potential Issues for Developers:**

1. **Direct File Path Dependencies:**

.. code-block:: python

   # This might break:
   with open('src/utils/config.py') as f:
       content = f.read()

   # Use imports instead:
   from sandroid.core import config

2. **Hardcoded sys.path Modifications:**

.. code-block:: python

   # This is no longer needed:
   sys.path.append('src/')

   # Just use normal imports:
   from sandroid.core.toolbox import Toolbox

3. **Assumption About File Structure:**

.. code-block:: python

   # Don't assume file paths:
   config_path = 'src/utils/config.json'  # Bad

   # Use proper configuration:
   from sandroid.config.loader import find_config_file
   config_path = find_config_file()  # Good

Validation and Testing
----------------------

**Migration Validation Checklist:**

.. code-block:: bash

   # 1. Installation validation
   sandroid --version  # Should show 1.1.0+
   sandroid-config validate  # Should pass

   # 2. Basic functionality
   sandroid --help  # Should show full help without errors

   # 3. Configuration system
   sandroid-config show  # Should display configuration

   # 4. Analysis capability
   sandroid --number 1 --screenshot 10  # Should run without errors

   # 5. Compatibility
   ./sandroid --help  # Legacy script should still work

**Regression Testing:**

.. code-block:: bash

   # Test with same APK using both methods

   # Legacy method
   ./sandroid --number 2 --network --output legacy_results.json

   # Modern method
   sandroid --number 2 --network --output modern_results.json

   # Compare results (should be identical)
   diff legacy_results.json modern_results.json

**Performance Comparison:**

.. code-block:: bash

   # Time both methods
   time ./sandroid --number 2
   time sandroid --number 2

   # Performance should be identical or better

Rollback Plan
-------------

If you need to rollback the modern installation:

.. code-block:: bash

   # 1. Remove PyPI installation
   pip uninstall sandroid

   # 2. Restore legacy installation (if you have backup)
   tar -xzf sandroid_legacy_backup.tar.gz

   # 3. Reinstall legacy dependencies
   ./install-requirements.sh

   # 4. Test legacy functionality
   ./sandroid --version

Common Migration Issues
-----------------------

**Issue: "Command not found: sandroid"**

.. code-block:: bash

   # Solution: Check pip installation location
   pip show sandroid

   # Add to PATH if needed
   export PATH=$PATH:~/.local/bin

**Issue: "Configuration file not found"**

.. code-block:: bash

   # Solution: Initialize configuration
   sandroid-config init

   # Or create manually
   mkdir -p ~/.config/sandroid
   sandroid-config init

**Issue: "Import errors in custom code"**

.. code-block:: python

   # Update import statements
   # Old:
   from src.utils.toolbox import Toolbox

   # New:
   from sandroid.core.toolbox import Toolbox

**Issue: "Different results between legacy and modern"**

.. code-block:: bash

   # Check configuration differences
   sandroid-config show

   # Ensure same parameters
   sandroid --loglevel DEBUG --number 2

**Issue: "Performance degradation"**

.. code-block:: bash

   # Check for conflicting installations
   which sandroid
   pip list | grep sandroid

   # Clear Python cache
   find . -name "*.pyc" -delete
   find . -name "__pycache__" -delete

Support and Help
----------------

**Getting Help During Migration:**

1. **Check Documentation:**
   - :doc:`../installation` - Modern installation guide
   - :doc:`../troubleshooting` - Common issues and solutions

2. **Validate Your Setup:**

.. code-block:: bash

   sandroid-config validate
   sandroid --version
   sandroid --help

3. **Enable Debug Mode:**

.. code-block:: bash

   SANDROID_LOG_LEVEL=DEBUG sandroid --network

4. **Report Issues:**
   - GitHub Issues: https://github.com/fkie-cad/Sandroid_core/issues
   - Include: Sandroid version, system info, error messages

**Pre-Migration Checklist:**

- [ ] Backup current installation
- [ ] Document current configuration/settings
- [ ] Test modern installation in parallel
- [ ] Validate results match between versions
- [ ] Update scripts and documentation
- [ ] Train team on new configuration system

**Post-Migration Checklist:**

- [ ] All team members can run ``sandroid --version``
- [ ] Configuration system is working: ``sandroid-config validate``
- [ ] CI/CD pipelines updated and tested
- [ ] Documentation reflects modern installation
- [ ] Legacy backup is archived safely

This migration ensures you get all the benefits of the modern Sandroid system while maintaining complete compatibility with your existing workflows.
