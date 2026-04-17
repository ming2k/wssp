#!/bin/bash
# WSSP Daemon Verification Tool

BUS_NAME="org.freedesktop.secrets.test"
SERVICE_PATH="/org/freedesktop/secrets"

echo "--- 1. Checking Object Tree ---"
busctl --user tree $BUS_NAME

echo -e "\n--- 2. Checking Service Properties ---"
busctl --user get-property $BUS_NAME $SERVICE_PATH org.freedesktop.Secret.Service Collections

echo -e "\n--- 3. Testing Alias Resolution (login) ---"
busctl --user call $BUS_NAME $SERVICE_PATH org.freedesktop.Secret.Service ReadAlias s "login"

echo -e "\n--- 4. Testing Alias Resolution (default) ---"
busctl --user call $BUS_NAME $SERVICE_PATH org.freedesktop.Secret.Service ReadAlias s "default"

echo -e "\n--- 5. Simulating Session Opening ---"
busctl --user call $BUS_NAME $SERVICE_PATH org.freedesktop.Secret.Service OpenSession s "plain" v "s" ""

echo -e "\nVerification complete."
