#!/bin/bash
# k6 Load Testing Helper Script for Endeavour Backend

TARGET_URL=${1:-"http://localhost:4000"}

echo "🚀 Starting k6 Load Test against target: $TARGET_URL"
echo "--------------------------------------------------------"

./backend/load-tests/k6-v0.56.0-linux-amd64/k6 run -e TARGET_URL="$TARGET_URL" backend/load-tests/load-test.js
