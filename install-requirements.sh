#!/bin/bash

# filepath: install-requirements.sh

set -e  # Exit immediately if a command exits with a non-zero status
set -u  # Treat unset variables as an error

# Check if the script is being run on a Linux system with apt
if [ "$(uname)" != "Linux" ]; then
    echo "Error: This script is intended to run on Linux systems."
    exit 1
fi

if [ ! -f /etc/os-release ]; then
    echo "Error: Unable to determine the Linux distribution. Ensure this is a Debian-based system."
    exit 1
fi

# Check if the system uses apt package manager
if ! grep -qi "debian" /etc/os-release && ! grep -qi "ubuntu" /etc/os-release; then
    echo "Error: This script is intended to run on Debian-based systems with apt package manager (e.g., Ubuntu, Debian)."
    exit 1
fi

if ! command -v apt-get &> /dev/null; then
    echo "Error: apt package manager not found. Ensure this is a Debian-based system."
    exit 1
fi

# Set variables
VENV_PATH="${VENV_PATH:-$HOME/.virtualenvs}"
VENV_NAME="sandroid"
FULL_VENV_PATH="$VENV_PATH/$VENV_NAME"

echo "Updating package lists..."
sudo apt-get update

echo "Installing required packages..."
sudo apt-get install -y \
    git \
    python3 \
    python3-pip \
    python3-venv \
    cmake \
    tzdata \
    sqlite3-tools \
    adb \
    build-essential \
    libxml2-dev \
    libxslt-dev

echo "Creating virtual environment directory: $VENV_PATH (if it doesn't exist)..."
mkdir -p "$VENV_PATH" || {
    echo "Error: Could not create directory $VENV_PATH."
    echo "Please set a different path using the VENV_PATH environment variable:"
    echo "Example: VENV_PATH=/path/to/directory $0"
    exit 1
}

echo "Creating and activating virtual environment: $FULL_VENV_PATH..."
# Try to create virtual environment if it doesn't exist
if [ ! -d "$FULL_VENV_PATH" ]; then
    python3 -m venv "$FULL_VENV_PATH" || {
        echo "Error: Failed to create virtual environment at $FULL_VENV_PATH."
        echo "Please ensure you have python3-venv installed correctly and"
        echo "you have write permissions to the specified directory."
        exit 1
    }
fi

# Activate the virtual environment
source "$FULL_VENV_PATH/bin/activate" || {
    echo "Error: Failed to activate virtual environment at $FULL_VENV_PATH."
    exit 1
}

echo "Installing modern PyPI dependencies..."
# Install all dependencies via PyPI
python3 -m pip install AndroidFridaManager
python3 -m pip install trigdroid[full]
python3 -m pip install dexray-intercept
python3 -m pip install dexray-insight

echo "Installing Sandroid requirements..."
# Install Sandroid requirements
if [ -f docker/requirements.txt ]; then
    python3 -m pip install --no-cache-dir -r docker/requirements.txt
elif [ -f requirements.txt ]; then
    python3 -m pip install --no-cache-dir -r requirements.txt
else
    echo "requirements.txt not found. Installing basic dependencies."
    python3 -m pip install sandroid[full]
fi

echo "Cleaning up..."
# Clean up unnecessary files
sudo rm -rf /var/lib/apt/lists/*

echo "Deactivating virtual environment..."
deactivate

echo "Installation complete!"
echo ""
echo "To activate the Sandroid virtual environment, run:"
echo "source $FULL_VENV_PATH/bin/activate"
