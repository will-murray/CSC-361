#!/bin/bash
# test cases
urls=(
  "www.google.com"
  "https://chatgpt.com"
  "docs.engr.uvic.ca"


)


for url in "${urls[@]}"; do
  # Read URL and HTTP version from the case
  
  echo "Testing URL: $url"
  py WebTester.py "$url"
  echo "--------------------------------------"
done