#!/bin/bash
# test cases
urls=(
  #"https://www.uvic.ca"
  "http://www.uvic.ca"
  "http://www.uvic.ca/tools/"
  "http://chatgpt.com"
  
  #"google.com"

)


for url in "${urls[@]}"; do
  # Read URL and HTTP version from the case
  echo
  echo
  echo "++++++++++++++++++++++++++++++++++++++"
  echo "Testing URL: $url"
  python3 WebTester.py "$url"
  echo "++++++++++++++++++++++++++++++++++++++"
  echo
  echo
done