#!/bin/bash

# Function to handle cleanup on script exit
cleanup() {
    echo "Cleaning up..."
    # Use fuser to kill the process using the specified port
    fuser -k -n tcp $port
    echo "Killed process using port $port"
    exit 0
}

# Trap SIGINT (Ctrl+C) to run the cleanup function
trap cleanup SIGINT

# Check if argument is provided, if not set default values
if [ -z "$1" ]; then
    ip_address='127.0.0.1'
    port='8000'
else
    # Extract the IP address and port number from the argument
    IFS=':' read -r -a parts <<< "$1"
    ip_address="${parts[0]}"
    port="${parts[1]}"
fi

# Run the Python script to check for environment variables
python3 ENV_VAR.py

# Pass the port number to the Python script
python3 PORT_CHECK.py $port

# If the Python script exits with a non-zero status, exit the shell script
if [ $? -ne 0 ]; then
    exit 1
fi

function validate_ip () {
    local IP=$1
    local stat=1

    if [[ $IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($IP)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    if [ "$stat" -eq 0 ]; then
        return $stat
    else
        echo 'Bad IP'
        exit 1   
    fi
}

function validate_port () {
    local PORT=$1
    if [ -z "$PORT" ]; then
        echo 'Port can not be empty'
        exit 1
    fi    
    if [ "$PORT" -gt 1024 ] && [ "$PORT" -lt 65535 ]; then
        return 0
    else
        echo 'Invalid Port'
        exit 1
    fi    
}

validate_ip $ip_address
validate_port $port

python3 -m poetry run gunicorn -b ${ip_address}:${port} mobsf.MobSF.wsgi:application --workers=1 --threads=10 --timeout=3600 \
    --log-level=critical --log-file=- --access-logfile=- --error-logfile=- --capture-output
