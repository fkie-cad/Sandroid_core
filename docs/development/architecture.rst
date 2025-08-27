Architecture Overview
====================

Understanding Sandroid's architecture helps with development and customization.

Core Components
---------------

**Toolbox (Central Orchestrator)**
   - Configuration management
   - Device communication coordination
   - Analysis result aggregation

**ActionQ (Workflow Management)**
   - Analysis workflow orchestration
   - Module coordination
   - Queue management

**ADB Interface**
   - Android Debug Bridge communication
   - Device command execution
   - File transfer operations

Module Architecture
-------------------

**Analysis Modules (sandroid.analysis)**
   - Inherit from DataGather base class
   - Follow consistent interface pattern
   - Modular and extensible design

**Feature Modules (sandroid.features)**
   - Inherit from Functionality base class
   - Provide enhanced capabilities
   - Independent operation

**Configuration System**
   - Pydantic-based validation
   - Multiple format support
   - Environment variable integration

Development Standards
---------------------

When implementing new modules or extending existing ones, follow the comprehensive `Coding Guidelines <../../CODING_GUIDELINES.md>`_ which cover architectural patterns, testing standards, and Sandroid-specific conventions.

For detailed API information, see the API documentation.
