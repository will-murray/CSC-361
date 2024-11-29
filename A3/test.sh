#!/bin/bash


# The directory passed as an argument
DIR="PcapTracesAssignment3"

# Check if the directory exists
if [ ! -d "$DIR" ]; then
    echo "Directory $DIR does not exist."
    exit 1
fi

# Output file
OUTPUT_FILE="test_output.txt"
touch $OUTPUT_FILE

# Clear the output file if it already exists
> "$OUTPUT_FILE"

# Loop over the pcap files in the directory
for pcap_file in "$DIR"/*.pcap; do
    if [ -f "$pcap_file" ]; then
        echo "Processing $pcap_file..."
        # Run p3.py with the pcap file as argument and append output to test_output.txt
        echo -e "processing $pcap_file \n" >> "$OUTPUT_FILE"
        python3 p3.py "$pcap_file" >> "$OUTPUT_FILE"
        echo -e "------------------------\n\n\n" >> "$OUTPUT_FILE"

        
    fi
done

echo -e "Processing complete. Results stored in $OUTPUT_FILE."
