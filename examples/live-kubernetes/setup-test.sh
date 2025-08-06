#! /bin/bash

# Create a test namespace
oc create namespace test-namespace

# Create a test pod and service account
echo "Creating test pod and service account"

echo "Applying testpod.yaml"
oc apply -f testpod.yaml

