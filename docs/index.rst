Sandroid Documentation
=======================

.. image:: ../assets/sandroid_logo.png
   :alt: Sandroid Logo
   :align: center
   :width: 200px

Sandroid is a comprehensive Android forensic analysis framework designed for extracting artifacts from Android Virtual Devices (AVD). It provides both static and dynamic analysis capabilities for Android applications, including automated malware trigger execution, file system monitoring, network traffic capture, and comprehensive forensic reporting.

Features
--------

🔍 **Dynamic Analysis**
   - Real-time file system monitoring
   - Network traffic capture and analysis
   - Process and socket monitoring
   - Frida-based runtime instrumentation

📱 **Android Integration**
   - ADB interface for device communication
   - Android emulator management
   - APK installation and analysis
   - Automated screenshot capture

🛡️ **Security Analysis**
   - Malware behavior monitoring
   - SSL/TLS traffic interception (friTap)
   - Memory dumping capabilities
   - Automated trigger execution (TrigDroid)

📊 **Reporting**
   - JSON output format
   - PDF report generation
   - AI-powered analysis summaries
   - Comprehensive logging

Quick Start
-----------

**Installation**::

   pip install sandroid

**Initialize Configuration**::

   sandroid-config init

**Run Analysis**::

   # Interactive mode
   sandroid

   # Command-line mode
   sandroid --network --screenshot 5 --report

Getting Started
===============

.. toctree::
   :maxdepth: 2
   :caption: User Guide

   installation
   quickstart
   configuration
   interactive_mode
   command_line_usage
   troubleshooting

API Reference
=============

.. toctree::
   :maxdepth: 3
   :caption: Python API

   api/core
   api/analysis
   api/features
   api/config

Advanced Topics
===============

.. toctree::
   :maxdepth: 2
   :caption: Advanced Usage

   advanced/custom_analysis
   advanced/extending
   advanced/ground_truth_apk
   advanced/docker_deployment

Developer Documentation
=======================

.. toctree::
   :maxdepth: 2
   :caption: Development

   development/contributing
   development/architecture
   development/testing
   development/migration_guide

.. note::
   **For Contributors:** Before contributing to Sandroid, please review the comprehensive `Coding Guidelines <../CODING_GUIDELINES.md>`_ that cover code style, testing requirements, security practices, and Sandroid-specific development patterns.

About
=====

.. toctree::
   :maxdepth: 1
   :caption: Project Information

   changelog
   authors
   license

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
