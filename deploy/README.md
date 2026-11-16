# Sandroid quickstart guide (legacy Docker bundle)

> **Legacy / best effort.** This bundle (Docker image + packaged emulator archive)
> is not maintained or tested. For normal use install Sandroid with
> `pip install sandroid` (Python 3.12+) and see [SETUP.md](../SETUP.md).
> The current Docker image is described in `docs/advanced/docker_deployment.rst`.
> `deploy/create_avd.py` (AVD creation helper) is still usable on its own.

Run `./deploy`

---

### Requirements
You will need
- Docker
- Android Studio
- An Android Emulator (included in Android Studio)
- The Android Debug Bridge (included in Android Studio)

### More Options
If you want to specify your own folder where you can pass results from the container to your host, run deploy like this:
`./deploy ABSOLUTE/path/to/folder`

Otherwise a default folder called ouput will be created in the current directory.
