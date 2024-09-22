#!/bin/bash
# test cases
urls=(
  "www.google.com"
  "https://chatgpt.com"
  "docs.engr.uvic.ca"
  "www.uvic.ca"
  "not.a.url.com"


)


for url in "${urls[@]}"; do
  # Read URL and HTTP version from the case
  
  echo "Testing URL: $url"
  python WebTester.py "$url"
  echo "--------------------------------------"
done