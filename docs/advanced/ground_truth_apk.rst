Ground Truth APK
================

Sandroid includes a custom-built Ground Truth APK for testing and validation purposes. This APK creates predictable forensic artifacts that can be used to verify Sandroid's detection capabilities.

Overview
--------

The Ground Truth APK (``ground_truth.apk``) is a specially designed Android application that:

- Creates known file system artifacts
- Generates predictable database entries
- Produces XML configuration changes
- Establishes network connections
- Demonstrates various Android behaviors

This makes it ideal for:

- Testing Sandroid installations
- Validating analysis accuracy
- Demonstrating capabilities
- Training and education
- Regression testing

Features
--------

**File System Artifacts**
   - Creates files in ``/sdcard/GroundTruth/``
   - Modifies application preferences
   - Generates temporary files
   - Creates and updates SQLite databases

**Database Operations**
   - SQLite database creation and modification
   - Table insertions and updates
   - Index creation
   - Transaction logging

**XML Configuration**
   - Updates shared preferences
   - Modifies application configuration
   - Creates custom XML files

**Network Activity**
   - HTTP requests to test endpoints
   - DNS lookups
   - Connection establishment

Usage Instructions
------------------

**Installation and Execution:**

.. code-block:: bash

   # Install Ground Truth APK
   adb install ground_truth.apk

   # Launch the application
   adb shell am start -n de.fkie.ground_truth/.MainActivity

**Using with Sandroid:**

.. code-block:: bash

   # Interactive analysis with Ground Truth
   sandroid
   # In interactive mode:
   # 1. Press 'r' to start recording
   # 2. Launch Ground Truth APK manually or via ADB
   # 3. Interact with the app (press all buttons)
   # 4. Press Enter to complete analysis

   # Command-line analysis
   sandroid --number 2 --screenshot 5

**Expected Artifacts:**

When you run the Ground Truth APK through Sandroid analysis, you should detect:

1. **New Files:**
   - ``/sdcard/GroundTruth/test_file.txt``
   - ``/sdcard/GroundTruth/binary_file.dat``
   - ``/data/data/de.fkie.ground_truth/databases/test.db``

2. **Changed Files:**
   - Application shared preferences
   - Database modifications
   - Log file updates

3. **Network Connections:**
   - HTTP requests to httpbin.org
   - DNS lookups for test domains

Building from Source
--------------------

The Ground Truth APK source code is located in ``ground_truth_src/``:

.. code-block:: bash

   cd ground_truth_src/
   ./gradlew build

   # The APK will be built to:
   # app/build/outputs/apk/debug/app-debug.apk

**Source Structure:**

.. code-block:: text

   ground_truth_src/
   ├── app/
   │   ├── src/main/java/de/fkie/ground_truth/
   │   │   ├── MainActivity.java      # Main application logic
   │   │   ├── DatabaseHelper.java    # Database operations
   │   │   └── XMLHelper.java         # XML file operations
   │   └── src/main/
   │       ├── AndroidManifest.xml    # Application manifest
   │       └── res/                   # Resources and layouts
   ├── build.gradle.kts              # Build configuration
   └── settings.gradle.kts

**Code Overview:**

**MainActivity.java:**

.. code-block:: java

   public class MainActivity extends AppCompatActivity {

       @Override
       protected void onCreate(Bundle savedInstanceState) {
           // Initialize UI components
           // Create file system artifacts
           // Set up database operations
           // Configure network requests
       }

       private void createFileArtifacts() {
           // Creates test files in /sdcard/GroundTruth/
           // Generates binary and text files
           // Updates timestamps
       }

       private void performDatabaseOperations() {
           // Creates SQLite database
           // Inserts test records
           // Performs updates and queries
       }
   }

**DatabaseHelper.java:**

.. code-block:: java

   public class DatabaseHelper extends SQLiteOpenHelper {

       @Override
       public void onCreate(SQLiteDatabase db) {
           // Create tables
           // Insert initial data
           // Create indexes
       }

       public void performTestOperations() {
           // Insert test records
           // Update existing data
           // Delete records
       }
   }

Testing and Validation
----------------------

**Verification Checklist:**

After running Sandroid analysis with the Ground Truth APK:

1. **File Detection:**
   - [ ] New files detected in ``/sdcard/GroundTruth/``
   - [ ] Database file changes detected
   - [ ] Shared preferences modifications found

2. **Content Analysis:**
   - [ ] File content differences captured
   - [ ] Database schema changes detected
   - [ ] XML structure modifications identified

3. **Network Activity:**
   - [ ] HTTP connections captured (if ``--network`` enabled)
   - [ ] DNS queries logged
   - [ ] Connection timing recorded

4. **System Changes:**
   - [ ] Process activity monitored
   - [ ] Application installation detected
   - [ ] Permission requests captured

**Sample Expected Output:**

.. code-block:: json

   {
     "New Files": [
       "/sdcard/GroundTruth/test_file.txt",
       "/sdcard/GroundTruth/binary_file.dat",
       "/data/data/de.fkie.ground_truth/databases/test.db"
     ],
     "Changed Files": [
       {"/data/data/de.fkie.ground_truth/shared_prefs/settings.xml": [
         "- <string name=\"user_action\">none</string>",
         "+ <string name=\"user_action\">button_clicked</string>"
       ]}
     ],
     "Network": {
       "connections": [
         "httpbin.org:80",
         "httpbin.org:443"
       ],
       "dns_queries": [
         "httpbin.org",
         "www.example.com"
       ]
     }
   }

Customization
-------------

**Modifying the Ground Truth APK:**

You can customize the Ground Truth APK to test specific scenarios:

1. **Add Custom File Operations:**

.. code-block:: java

   private void createCustomArtifacts() {
       // Add your custom file creation logic
       File customDir = new File(Environment.getExternalStorageDirectory(),
                                "CustomTest");
       customDir.mkdirs();

       // Create test files
       writeTestFile(new File(customDir, "custom_test.txt"));
   }

2. **Add Database Tests:**

.. code-block:: java

   private void performCustomDatabaseOps() {
       SQLiteDatabase db = getWritableDatabase();

       // Create custom tables
       db.execSQL("CREATE TABLE custom_test (id INTEGER, data TEXT)");

       // Insert test data
       db.execSQL("INSERT INTO custom_test VALUES (1, 'test_data')");
   }

3. **Add Network Tests:**

.. code-block:: java

   private void performNetworkTests() {
       // Custom HTTP requests
       new AsyncTask<Void, Void, Void>() {
           protected Void doInBackground(Void... params) {
               try {
                   URL url = new URL("https://your-test-endpoint.com/api");
                   HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                   conn.getResponseCode();
               } catch (Exception e) {
                   Log.e("GroundTruth", "Network test failed", e);
               }
               return null;
           }
       }.execute();
   }

**Build Custom Version:**

.. code-block:: bash

   # After modifications
   cd ground_truth_src/
   ./gradlew clean build

   # Install custom version
   adb install app/build/outputs/apk/debug/app-debug.apk

Automated Testing
-----------------

**Automated Ground Truth Testing:**

.. code-block:: bash

   #!/bin/bash

   # Ground Truth test script

   echo "Starting Ground Truth validation..."

   # Install Ground Truth APK
   adb install ground_truth.apk

   # Run Sandroid analysis
   sandroid --number 2 --screenshot 10 --output ground_truth_results.json

   # Launch Ground Truth during analysis
   adb shell am start -n de.fkie.ground_truth/.MainActivity
   sleep 5

   # Interact with app (simulate button clicks)
   adb shell input tap 500 800  # Click main button
   sleep 2
   adb shell input tap 500 900  # Click secondary button

   # Wait for analysis completion
   echo "Analysis complete. Validating results..."

   # Validate expected artifacts
   if grep -q "GroundTruth" ground_truth_results.json; then
       echo "✅ Ground Truth artifacts detected"
   else
       echo "❌ Ground Truth artifacts missing"
   fi

**Integration with CI/CD:**

.. code-block:: yaml

   # GitHub Actions example
   - name: Ground Truth Validation
     run: |
       # Start emulator
       emulator -avd test_device -no-window &
       adb wait-for-device

       # Install and test Ground Truth
       adb install ground_truth.apk
       sandroid --number 2 --output validation_results.json &

       # Launch app and interact
       adb shell am start -n de.fkie.ground_truth/.MainActivity
       sleep 10

       # Validate results
       python validate_ground_truth.py validation_results.json

Troubleshooting
---------------

**Common Issues:**

1. **APK Installation Fails:**
   - Ensure device has sufficient storage
   - Check ADB connection: ``adb devices``
   - Verify APK is not corrupted

2. **No Artifacts Detected:**
   - Ensure proper permissions for file access
   - Check device is rooted (for full filesystem access)
   - Verify timing - allow sufficient interaction time

3. **Network Activity Not Captured:**
   - Enable network monitoring: ``sandroid --network``
   - Check device internet connectivity
   - Verify firewall/proxy settings

4. **Database Changes Not Detected:**
   - Ensure SQLite tools are installed
   - Check file permissions
   - Verify database file locations

**Debug Mode:**

.. code-block:: bash

   # Enable debug logging
   SANDROID_LOG_LEVEL=DEBUG sandroid --network --screenshot 5

   # Monitor logs
   tail -f ~/.cache/sandroid/logs/sandroid.log

See Also
--------

- :doc:`../quickstart` - Using Ground Truth APK in quick start
- :doc:`../troubleshooting` - General troubleshooting
- :doc:`../api/core` - Core API for custom testing
- :doc:`custom_analysis` - Creating custom analysis modules
