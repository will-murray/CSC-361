#!/bin/bash


# The directory passed as an argument
DIR="PcapTracesAssignment3"

# Check if the directory exists
if [ ! -d "$DIR" ]; then
    echo "Directory $DIR does not exist."
    exit 1
fi



# Loop over the pcap files in the directory
for pcap_file in "$DIR"/*.pcap; do
    if [ -f "$pcap_file" ]; then
        # Run p3.py with the pcap file as argument and append output to test_output.txt
        python3 p3.py "$pcap_file"
        echo -e "------------------------\n\n\n"

        
    fi
done

echo -e "Processing complete. Results stored in $OUTPUT_FILE."
