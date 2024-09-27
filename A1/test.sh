#!/bin/bash
# test cases
urls=(
  "https://www.uvic.ca"
  "http://www.uvic.ca"
  "http://www.uvic.ca/tools/"
  "http://chatgpt.com"
  "google.com"
  "https://www.bing.com/"
  "http://www.bing.com/"
  "cloudflare.com"
  "not a uri"
  "docs.engr.uvic.ca/docs"
)


for url in "${urls[@]}"; do
  # Read URL and HTTP version from the case
  echo
  echo
  echo "++++++++++++++++++++++++++++++++++++++"
  python3 WebTester.py "$url"
  echo "++++++++++++++++++++++++++++++++++++++"
  echo
  echo
done