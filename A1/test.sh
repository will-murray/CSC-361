#!/bin/bash
# test cases
urls=(
  #"https://www.uvic.ca"
  #"https://www.bing.com/"
  #"http://www.uvic.ca/index.html"
  #"www.uvic.ca"
  "https://www.python.org/downloads/"
  "www.python.org/downloads/"
  "https://www.python.org/community/forums/"
  
  #"google.com"

)


for url in "${urls[@]}"; do
  # Read URL and HTTP version from the case
  
  echo "Testing URL: $url"
  python3 WebTester.py "$url"
  echo "++++++++++++++++++++++++++++++++++++++"
done