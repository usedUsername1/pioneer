#!/bin/bash

# Function to install Python if the version is less than 3.12 or not installed
check_python_version() {
    if command -v python3 &>/dev/null; then
        PYTHON_VERSION=$(python3 -V 2>&1 | awk '{print $2}')
        REQUIRED_VERSION="3.10"

        # Check if the major.minor version matches 3.10.x
        if [[ "$PYTHON_VERSION" == 3.10.* ]]; then
            echo "Python version is $PYTHON_VERSION. No update needed."
        else
            echo "Current Python version is $PYTHON_VERSION. Please update/downgrade to version $REQUIRED_VERSION manually."
            exit 1  # Stop execution of the script
        fi
    else
        echo "Python is not installed. Please install Python version $REQUIRED_VERSION manually and run the script again."
        exit 1  # Stop execution of the script
    fi
}

# Function to check PostgreSQL version and install if less than 15.5 or not installed
check_postgresql_version() {
    if command -v psql &>/dev/null; then
        PSQL_VERSION=$(psql -V | awk '{print $3}')
        REQUIRED_VERSION="15.5"

        if [[ "$(printf '%s\n' "$REQUIRED_VERSION" "$PSQL_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]]; then
            echo "PostgreSQL version is less than 15.5. Installing PostgreSQL 15..."
            sudo sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
            wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -
            sudo apt update
            sudo apt install postgresql-15 postgresql-client-15 -y
        else
            echo "PostgreSQL version is $PSQL_VERSION. No update needed."
        fi
    else
        echo "PostgreSQL is not installed. Installing PostgreSQL 15..."
        sudo sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
        wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -
        sudo apt update
        sudo apt install postgresql-15 postgresql-client-15 -y
    fi
}

# Function to clone from a GitHub repository
clone_repo() {
    REPO_URL=$1
    if [[ -z "$REPO_URL" ]]; then
        echo "Repository URL not provided."
        exit 1
    fi
    echo "Cloning from the repository: $REPO_URL"
    git clone "$REPO_URL"
    cd "$(basename "$REPO_URL" .git)" || exit
    
    sudo apt install -y python3-pip
    # Install necessary build tools for psycopg2
    sudo apt install -y libpq-dev build-essential

    if [[ -f "requirements.txt" ]]; then
        echo "Installing Python libraries from requirements.txt..."
        # Ensure pip is available
        pip install --upgrade pip
        pip install -r requirements.txt  # Install required libraries directly
    else
        echo "requirements.txt not found. Skipping Python libraries installation."
    fi
}

# Function to create PostgreSQL user and database
setup_postgresql() {
    # Create the role if it doesn't exist
    sudo -u postgres psql -c "DO \$\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pioneer_admin') THEN CREATE ROLE pioneer_admin LOGIN PASSWORD '2wsx#EDC'; END IF; END \$\$;"
    
    # Grant CREATEDB permission to the role
    sudo -u postgres psql -c "ALTER ROLE pioneer_admin CREATEDB;"

    # Create the database and set the owner
    sudo -u postgres psql -c "CREATE DATABASE pioneer_projects OWNER pioneer_admin;"
    
    echo "Created PostgreSQL user 'pioneer_admin' with CREATEDB permission and database 'pioneer_projects'."
}

# Main script execution
check_python_version
check_postgresql_version
setup_postgresql
clone_repo "https://github.com/usedUsername1/pioneer.git"

echo "Script execution completed."
