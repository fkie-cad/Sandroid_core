Docker Deployment
=================

.. warning::

   Docker support is **best effort**: the image is not built or tested in CI.
   The Android emulator always runs on the **host**; the container only runs
   Sandroid and talks to the host's adb server.

Building the Image
------------------

``docker/dockerfile`` installs Sandroid (with the ``full`` extras) from the
repository's ``pyproject.toml`` on ``python:3.12-slim``:

.. code-block:: bash

   # from the repository root
   docker build -t sandroid -f docker/dockerfile .

   # or build + export a compressed image to deploy/sandroid_image.tar.gz
   ./build_and_export_docker.sh

Running
-------

**Linux** -- share the host network so the container reaches the host adb
server on ``localhost:5037``:

.. code-block:: bash

   docker run --rm -it --network host \
       -v "$PWD/results:/sandroid/results" \
       -v "$HOME/.config/sandroid:/root/.config/sandroid" \
       sandroid

**Docker Desktop (macOS/Windows)** -- start the host adb server so it accepts
remote connections and point the container's adb client at it:

.. code-block:: bash

   adb kill-server && adb -a nodaemon server &      # on the host
   docker run --rm -it \
       -e ADB_SERVER_SOCKET=tcp:host.docker.internal:5037 \
       -v "$PWD/results:/sandroid/results" sandroid

Inside the container run ``sandroid`` (TUI) or ``sandroid --headless ...``
as usual. Features that talk to the emulator console or forward ports from
the device to the host (mitmproxy proxies, frida-server port forwarding) may
need additional port mappings when not using host networking.

Custom Images
-------------

.. code-block:: dockerfile

   FROM python:3.12-slim
   RUN apt-get update && apt-get install -y --no-install-recommends adb \
       && rm -rf /var/lib/apt/lists/*
   RUN pip install "sandroid[full]"
   WORKDIR /sandroid
   CMD ["sandroid", "--help"]

The legacy ``deploy/deploy`` bundle (image + packaged emulator archive) is
kept for reference only and is not maintained.
