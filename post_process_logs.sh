#!/bin/bash

# Check if at least one file is provided as input
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 file1 [file2 ... fileN]"
    exit 1
fi

# Create an array to hold temporary file paths
temp_files=()

# Process each input file
for file in "$@"; do
    if [ ! -f "$file" ]; then
        echo "Error: File '$file' not found. Skipping..."
        continue
    fi

    # Create a temporary file
    temp_file=$(mktemp)
    temp_files+=("$temp_file")

    # Extract lines containing 'timestamp' and save to the temporary file
    grep 'timestamp' "$file" | grep workflow_name | grep success | grep -v step_name > "$temp_file"
    sort -o "$temp_file" "$temp_file"

done

# Check if there are any valid temporary files to process
if [ "${#temp_files[@]}" -eq 0 ]; then
    echo "No valid files to process. Exiting."
    exit 1
fi

echo "Calling Python post-processing tool: stats will be in cum_stats.csv"
python3 post_process_logs.py "${temp_files[@]}" -o cum_stats.csv -t 30

# Clean up temporary files
for temp_file in "${temp_files[@]}"; do
cat $temp_file
    rm -f "$temp_file"
done
