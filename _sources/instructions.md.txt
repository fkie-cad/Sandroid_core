# Install Instructions
## Setup
You'll need:
- Python 3.10 or newer
- sqldiff
- Android Studio
- Android SDK & ADB (Comes with Studio)
- A running emulator

#### Modern Installation (Recommended):
```bash
$ sudo apt install python3 sqlite3-tools
$ python3 -m venv env
$ source env/bin/activate
$ pip install sandroid
$ sandroid-config init
```

#### Legacy Installation:
```bash
$ sudo apt install python3 sqlite3-tools
$ git clone <repository>
$ cd sandroid
$ ./install-requirements.sh
```
- Download Android Studio from https://developer.android.com/studio, then create an emulator like this:
- Open Android Studio
- Click "more options"
- from there, open "Virtual device manager"
- Click "Create device"
- Choose a phone (Preprogrammed actions are intended for Pixel 5). If you choose a phone with play services, you will need to jailbreak it before you can use the tool.
- Choose an API
- Click Finish
- Start the emulator (little play button in the virtual device manager)


## Dependencies
- sqldiff: https://manpages.debian.org/unstable/sqlite3/sqldiff.1.en.html
