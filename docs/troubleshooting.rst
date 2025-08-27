Troubleshooting
===============

This guide helps you resolve common issues when using Sandroid. Issues are organized by category with step-by-step solutions.

Installation Issues
-------------------

Legacy Analysis Modules Not Available
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Error Message**::

   Error: Legacy analysis modules not available in this installation!

**Root Cause**: This error occurred in Sandroid versions before v1.1.0 due to incomplete package migration.

**Solution**:

1. **Update to latest version**::

   pip install --upgrade sandroid

2. **Verify installation**::

   sandroid --version  # Should show 1.1.0 or later
   sandroid --help     # Should load without errors

3. **If still failing, reinstall**::

   pip uninstall sandroid
   pip install sandroid

**Prevention**: Always use the latest version from PyPI.

No Module Named 'src'
~~~~~~~~~~~~~~~~~~~~~~

**Error Message**::

   ImportError: No module named 'src'

**Root Cause**: Hardcoded import paths in older versions.

**Solution**:

1. **Update Sandroid**::

   pip install --upgrade sandroid>=1.1.0

2. **Clear Python cache**::

   find . -name "*.pyc" -delete
   find . -name "__pycache__" -type d -exec rm -rf {} +

3. **Restart Python interpreter** if using interactive Python

Missing Dependencies
~~~~~~~~~~~~~~~~~~~~

**Error Message**::

   ModuleNotFoundError: No module named 'frida'

**Root Cause**: Required dependencies not installed.

**Solution**:

1. **Install with all dependencies**::

   pip install sandroid[ai,dev]

2. **For specific missing modules**::

   pip install frida frida-tools
   pip install scapy beautifulsoup4

3. **Check requirements**::

   pip check sandroid

Permission Errors
~~~~~~~~~~~~~~~~~

**Error Message**::

   Permission denied: '/usr/local/bin/sandroid'

**Root Cause**: Installing without proper permissions.

**Solution**:

1. **Use user installation**::

   pip install --user sandroid

2. **Or use virtual environment**::

   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   # or: venv\Scripts\activate  # Windows
   pip install sandroid

3. **Add to PATH if needed**::

   export PATH=$PATH:~/.local/bin

Device Connection Issues
------------------------

ADB Not Found
~~~~~~~~~~~~~~

**Error Message**::

   Android debug bridge path found: None

**Root Cause**: ADB not installed or not in PATH.

**Solution**:

1. **Install Android SDK Platform Tools**:
   - Download from https://developer.android.com/studio/releases/platform-tools
   - Extract and add to PATH

2. **Verify ADB installation**::

   adb version
   which adb  # Linux/Mac
   where adb  # Windows

3. **Add to PATH permanently**::

   # Linux/Mac (.bashrc or .zshrc)
   export PATH=$PATH:/path/to/android-sdk/platform-tools

   # Windows (System Properties > Environment Variables)
   Add to PATH: C:\path\to\android-sdk\platform-tools

4. **Test connection**::

   adb devices

No Devices Found
~~~~~~~~~~~~~~~~

**Error Message**::

   List of devices attached
   (empty)

**Root Cause**: No emulator running or USB debugging disabled.

**Solution**:

1. **Start Android emulator**::

   # List available AVDs
   emulator -list-avds

   # Start emulator
   emulator -avd Pixel_6_Pro_API_31

2. **For physical devices**:
   - Enable Developer Options
   - Enable USB Debugging
   - Accept debugging prompt on device

3. **Check USB connection**::

   lsusb  # Linux
   # Look for Android device

4. **Restart ADB server**::

   adb kill-server
   adb start-server
   adb devices

Device Unauthorized
~~~~~~~~~~~~~~~~~~~

**Error Message**::

   List of devices attached
   ABC123456 unauthorized

**Root Cause**: Device hasn't authorized the computer.

**Solution**:

1. **Accept authorization prompt** on the Android device
2. **If no prompt appears**::

   adb kill-server
   adb start-server

3. **Revoke and re-authorize**:
   - Go to Developer Options on device
   - Revoke USB Debugging authorizations
   - Reconnect and accept new prompt

Device Not Rooted
~~~~~~~~~~~~~~~~~

**Error Message**::

   [-] none rooted device. Please root it before using FridaAndroidManager

**Root Cause**: Advanced features require root access.

**Solution**:

1. **For emulators**: Use Google APIs system images (usually rooted)

2. **Verify root access**::

   adb shell su -c 'id'

3. **Root emulator if needed**:
   - Use Android Studio AVDs with Google APIs
   - Or manually root using Magisk/SuperSU

4. **Alternative**: Use features that don't require root::

   sandroid --number 2 --screenshot 5  # Basic analysis

Frida Issues
------------

Frida Server Not Running
~~~~~~~~~~~~~~~~~~~~~~~~~

**Error Message**::

   Frida Server: [Not running]

**Root Cause**: Frida server not installed or started on device.

**Solution**:

1. **In interactive mode**::

   Press 'f' to install and start Frida server

2. **Manual installation**::

   # Check device architecture
   adb shell getprop ro.product.cpu.abi

   # Download appropriate frida-server
   # Install and start via ADB

3. **Verify Frida is working**::

   frida-ps -U  # List processes on USB device

4. **Check Frida server process**::

   adb shell ps | grep frida

Frida Version Mismatch
~~~~~~~~~~~~~~~~~~~~~~

**Error Message**::

   Failed to spawn: unable to connect to remote frida-server

**Root Cause**: Frida client/server version mismatch.

**Solution**:

1. **Update Frida**::

   pip install --upgrade frida frida-tools

2. **Reinstall Frida server** using Sandroid (interactive mode → 'f')

3. **Check versions match**::

   frida --version
   adb shell /data/local/tmp/frida-server --version

Frida Connection Timeout
~~~~~~~~~~~~~~~~~~~~~~~~

**Error Message**::

   Timeout while connecting to frida-server

**Root Cause**: Network or device issues.

**Solution**:

1. **Restart Frida server**::

   adb shell su -c 'killall frida-server'
   # Then reinstall via Sandroid

2. **Check network connectivity**::

   adb shell ping 8.8.8.8

3. **Restart ADB connection**::

   adb kill-server && adb start-server

Analysis Issues
---------------

No Results Generated
~~~~~~~~~~~~~~~~~~~~

**Symptoms**: Analysis completes but no changes detected.

**Root Cause**: Clean system or insufficient activity.

**Solution**:

1. **Increase analysis activity**:
   - Install/uninstall apps
   - Browse internet
   - Use more features during analysis

2. **Disable noise filtering**::

   sandroid --avoid-strong-noise-filter

3. **Check baseline is clean**:
   - Use fresh emulator snapshot
   - Avoid background system updates

Empty or Minimal Output
~~~~~~~~~~~~~~~~~~~~~~~

**Symptoms**: Very few files or changes reported.

**Root Cause**: Restrictive noise filtering or limited monitoring scope.

**Solution**:

1. **Expand monitoring scope**::

   sandroid --network --sockets --show-deleted

2. **Use multiple runs**::

   sandroid --number 3

3. **Monitor more file types**::

   sandroid --avoid-strong-noise-filter

High System Resource Usage
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Symptoms**: Slow performance, high CPU/memory usage.

**Root Cause**: Comprehensive monitoring is resource-intensive.

**Solution**:

1. **Reduce monitoring scope**::

   sandroid --number 1 --no-processes

2. **Optimize system**:
   - Close unnecessary applications
   - Use SSD storage for faster I/O
   - Increase available RAM

3. **Use targeted analysis**:
   - Monitor specific apps only
   - Shorter screenshot intervals

Analysis Stuck or Hanging
~~~~~~~~~~~~~~~~~~~~~~~~~

**Symptoms**: Analysis doesn't progress or complete.

**Root Cause**: Device unresponsive or resource exhaustion.

**Solution**:

1. **Check device responsiveness**::

   adb shell echo "test"

2. **Monitor system resources**::

   # Linux/Mac
   htop

   # Windows
   Task Manager

3. **Force restart if needed**::

   # Kill Sandroid processes
   pkill -f sandroid

   # Restart device
   adb reboot

Network Issues
--------------

Network Monitoring Not Working
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Symptoms**: No network connections captured with ``--network``.

**Root Cause**: Missing dependencies or permissions.

**Solution**:

1. **Install network dependencies**::

   pip install scapy

2. **Check root permissions** (required for packet capture)

3. **Verify network activity**::

   adb shell netstat -an

4. **Test with simple network activity**:
   - Open browser on device
   - Make HTTP requests

SSL/TLS Interception Failing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Error Message**::

   friTap hook failed

**Root Cause**: App uses certificate pinning or advanced protection.

**Solution**:

1. **Use Objection for bypassing**::

   # In interactive mode: press 'b'
   objection -g com.app.name explore

2. **Try different hooking methods**:
   - Universal SSL Kill Switch
   - Custom Frida scripts

3. **Analyze without decryption**:
   - Monitor connection metadata only
   - Focus on network patterns

Proxy Configuration Issues
~~~~~~~~~~~~~~~~~~~~~~~~~

**Symptoms**: Network traffic not routing through proxy.

**Root Cause**: Incorrect proxy setup or app bypassing proxy.

**Solution**:

1. **Verify proxy settings**::

   adb shell settings get global http_proxy

2. **Force proxy for all traffic**::

   # Configure iptables rules if rooted
   adb shell su -c 'iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 8080'

3. **Use transparent proxy tools**:
   - mitmproxy in transparent mode
   - burpsuite with invisible proxying

Configuration Issues
--------------------

Configuration File Not Found
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Error Message**::

   Configuration file not found: config.toml

**Root Cause**: File doesn't exist or wrong path specified.

**Solution**:

1. **Initialize configuration**::

   sandroid-config init

2. **Check configuration locations**::

   sandroid-config paths

3. **Specify full path**::

   sandroid --config /full/path/to/config.toml

4. **Verify file exists and readable**::

   ls -la ~/.config/sandroid/sandroid.toml
   cat ~/.config/sandroid/sandroid.toml

Invalid Configuration Values
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Error Message**::

   ValidationError: Invalid configuration

**Root Cause**: Configuration contains invalid values or syntax errors.

**Solution**:

1. **Validate configuration**::

   sandroid-config validate

2. **Check syntax**::

   # For TOML files
   python -c "import tomli; tomli.load(open('config.toml', 'rb'))"

3. **Reset to defaults**::

   mv ~/.config/sandroid/sandroid.toml ~/.config/sandroid/sandroid.toml.backup
   sandroid-config init

4. **Check for typos** in configuration keys and values

Environment Variable Issues
~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Symptoms**: Environment variables not taking effect.

**Root Cause**: Incorrect variable names or format.

**Solution**:

1. **Check variable format**::

   # Correct format
   export SANDROID_LOG_LEVEL=DEBUG
   export SANDROID_EMULATOR__DEVICE_NAME=MyDevice

   # Incorrect format
   export sandroid_log_level=debug  # Wrong case
   export SANDROID_EMULATOR.DEVICE_NAME=MyDevice  # Wrong separator

2. **Verify variables are set**::

   env | grep SANDROID

3. **Test variable precedence**::

   SANDROID_LOG_LEVEL=DEBUG sandroid --loglevel INFO
   # Environment variable should be overridden by CLI

Memory and Storage Issues
-------------------------

Out of Memory Errors
~~~~~~~~~~~~~~~~~~~~

**Error Message**::

   MemoryError: Unable to allocate memory

**Root Cause**: Large analysis datasets or memory leaks.

**Solution**:

1. **Increase system memory** or use smaller analysis scope

2. **Clear previous results**::

   rm -rf results/
   rm -f *.json

3. **Use streaming analysis** for large datasets

4. **Monitor memory usage**::

   # Linux/Mac
   free -h

   # Check specific process
   ps aux | grep sandroid

Disk Space Issues
~~~~~~~~~~~~~~~~

**Error Message**::

   No space left on device

**Root Cause**: Analysis results consuming too much storage.

**Solution**:

1. **Clean previous results**::

   find results/ -type f -mtime +7 -delete  # Clean old results

2. **Use custom results path**::

   sandroid-config set paths.results_path /path/with/more/space

3. **Compress results**::

   tar -czf results_$(date +%Y%m%d).tar.gz results/
   rm -rf results/

4. **Limit screenshot capture**::

   # Reduce screenshot frequency or disable
   sandroid --screenshot 30  # Every 30 seconds instead of 5

Performance Issues
------------------

Slow Analysis Performance
~~~~~~~~~~~~~~~~~~~~~~~~

**Symptoms**: Analysis takes very long to complete.

**Root Cause**: System limitations or inefficient configuration.

**Solution**:

1. **Optimize configuration**::

   # Reduce number of runs for testing
   sandroid --number 1

   # Disable resource-intensive features
   sandroid --no-processes --screenshot 30

2. **System optimization**:
   - Use SSD storage
   - Close unnecessary applications
   - Increase virtual memory

3. **Use incremental analysis**:
   - Analyze specific apps instead of full system
   - Use targeted monitoring

Screenshot Capture Issues
~~~~~~~~~~~~~~~~~~~~~~~~~

**Symptoms**: Screenshots not captured or corrupted.

**Root Cause**: Device screen issues or permissions.

**Solution**:

1. **Test manual screenshot**::

   adb shell screencap -p /sdcard/test.png
   adb pull /sdcard/test.png

2. **Check device screen state**:
   - Ensure screen is on
   - Disable screen lock
   - Verify device is responsive

3. **Adjust screenshot interval**::

   # Reduce frequency to avoid overload
   sandroid --screenshot 10

Getting Help
------------

Log Analysis
~~~~~~~~~~~~

**Find detailed logs**::

   # Main log file
   tail -f ~/.cache/sandroid/logs/sandroid.log

   # Search for specific errors
   grep -i "error\|exception\|failed" ~/.cache/sandroid/logs/sandroid.log

**Enable debug logging**::

   SANDROID_LOG_LEVEL=DEBUG sandroid

**Save logs for support**::

   # Copy logs with timestamp
   cp ~/.cache/sandroid/logs/sandroid.log sandroid_debug_$(date +%Y%m%d_%H%M%S).log

Reporting Issues
~~~~~~~~~~~~~~~

When reporting issues, include:

1. **Sandroid version**::

   sandroid --version

2. **System information**::

   # Linux/Mac
   uname -a
   python --version

   # Windows
   systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
   python --version

3. **Configuration**::

   sandroid-config show

4. **Error logs** (sanitized of sensitive information)

5. **Steps to reproduce** the issue

**Report at**: https://github.com/fkie-cad/Sandroid_core/issues

Common Solutions Summary
------------------------

**Quick Fixes for Common Issues**:

1. **Update Sandroid**: ``pip install --upgrade sandroid``
2. **Restart ADB**: ``adb kill-server && adb start-server``
3. **Check device connection**: ``adb devices``
4. **Validate configuration**: ``sandroid-config validate``
5. **Clear Python cache**: ``find . -name "*.pyc" -delete``
6. **Enable debug logging**: ``SANDROID_LOG_LEVEL=DEBUG sandroid``
7. **Check logs**: ``tail -f ~/.cache/sandroid/logs/sandroid.log``

**Emergency Reset**::

   # Complete reset procedure
   adb kill-server
   pkill -f sandroid
   rm -rf ~/.cache/sandroid/
   pip uninstall sandroid
   pip install sandroid
   sandroid-config init
   adb start-server
   sandroid --version

Prevention Tips
---------------

1. **Always use latest version** of Sandroid
2. **Test with simple cases** before complex analysis
3. **Keep configuration files** backed up
4. **Monitor system resources** during analysis
5. **Use clean snapshots** for baseline analysis
6. **Regular system maintenance** (disk cleanup, updates)
7. **Document working configurations** for future use

This troubleshooting guide covers the most common issues. For additional help, check the project documentation or create an issue on GitHub with detailed information about your specific problem.
