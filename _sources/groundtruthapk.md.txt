# Ground Truth APK
The framework also includes a custom Android app for testing and calibration.
This app is designed to **create specific forensic artefacts with pinpoint accuracy** at the user's command, while being as minimal as possible to avoid unintended artefacts.
To use it, simply install it on the emulator using Sandroid's built-in APK installer and open the app.

## Supported Artefacts
In the current version, the ground truth app supports nine different artefacts
- Creating a new file
- Adding an entry to a Database
- Deleting an entry from a Database
- Updating an entry in a Database
- Sending a specific number of bytes to a specific URL
- Starting a specific process
- Adding an entry to a XML file
- Deleting an entry from a XML file
- Updating an entry in a XML file
Simply press the corresponding button to generate the Artefact

## Some considerations
- Values added to the XML file and the Database will be the current unix time on the emulator. It can deviate from the actual time but will be automatically be highlighted in the output.
- The first time the application is launched after installation, the XML file and database will be initialised, and Android will create a profile for the application, so **it is recommended that you open the application first, and only then start any analysis.**
- The XML and database files are called `GroundTruth.xml` and `GroundTruth.db` respectively and are stored in the applications directory.
