Docker Deployment
=================

Deploy Sandroid using Docker containers for consistent, isolated analysis environments.

Quick Deployment
----------------

Use the provided Docker scripts:

.. code-block:: bash

   # Build and export Docker image
   ./build_and_export_docker.sh

   # Deploy with custom output path
   cd deploy
   ./deploy /path/to/output

Custom Docker Setup
-------------------

Create your own Dockerfile:

.. code-block:: dockerfile

   FROM python:3.10-slim

   # Install system dependencies
   RUN apt-get update && apt-get install -y \
       adb android-tools-adb \
       sqlite3 \
       && rm -rf /var/lib/apt/lists/*

   # Install Sandroid
   RUN pip install sandroid[ai]

   # Initialize configuration
   RUN sandroid-config init

   # Set working directory
   WORKDIR /app

   # Default command
   CMD ["sandroid", "--help"]

Container Configuration
-----------------------

Mount configuration and results:

.. code-block:: bash

   docker run -v $(pwd)/config:/root/.config/sandroid \
              -v $(pwd)/results:/app/results \
              sandroid:latest sandroid --network --report

For production deployments, see the deployment documentation.
