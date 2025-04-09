import argparse
import pandas as pd
import json
from datetime import datetime


# Helper function to compute bin number based on time period T
def compute_bin(timestamp, start_time, bin_period):
    # Compute which bin the timestamp belongs to
    # Assumes bin_period is in seconds
    elapsed = (timestamp - start_time).total_seconds()
    return int(elapsed // bin_period)


def process_file(input_file, bin_period):
    all_data = []

    # Read and aggregate data from all input ndjson files
    with open(input_file, 'r') as f:
        for line in f:
            record = json.loads(line)
            record['timestamp'] = datetime.fromisoformat(record['timestamp'])
            all_data.append(record)

    # Sort all_data by timestamp to determine the dynamic start_time
    all_data.sort(key=lambda x: x['timestamp'])
    start_time = all_data[0]['timestamp']  # First timestamp as the start_time
    end_time = all_data[-1]['timestamp']  # Last timestamp as the end_time

    # Convert data to DataFrame
    df = pd.DataFrame(all_data)

    # Compute the bin column based on timestamps
    df['bin'] = df['timestamp'].apply(lambda x: compute_bin(x, start_time, bin_period))

    # Group by bin and calculate statistics
    grouped = df.groupby('bin').size().reset_index(name='count')

    # Create a complete list of bins
    total_bins = int((end_time - start_time).total_seconds() // bin_period) + 1
    full_bins = pd.DataFrame({'bin': range(total_bins)})

    print(f"Total bins: {total_bins}")
    print(f"Full bins: {full_bins}")

    # Merge with grouped data and fill missing bins with 0
    grouped = pd.merge(full_bins, grouped, on='bin', how='left').fillna({'count': 0})
    grouped['count'] = grouped['count'].astype(int)

    # Add a cumulative count column
    grouped['cumulative_count'] = grouped['count'].cumsum()

    return grouped


def calculate_bin_statistics(dfs):
    # Concatenate all DataFrames
    combined_df = pd.concat(dfs, ignore_index=True)

    # Group by "bin" and calculate mean and stddev for "count"
    stats = combined_df.groupby('bin')['cumulative_count'].agg(['mean', 'std']).reset_index()

    return stats


def main():
    parser = argparse.ArgumentParser(description="Bin and analyze NDJSON files by time intervals.")
    parser.add_argument('input_files', nargs='+', help="Input NDJSON files")
    parser.add_argument('-o', '--output_csv', required=True, help="Output CSV file")
    parser.add_argument('-t', '--time_period', type=int, required=True, help="Time period for binning in seconds")

    args = parser.parse_args()

    dfs = []
    for file in args.input_files:
        df = process_file(file, args.time_period)
        for index, row in df.iterrows():
            print(row)
        dfs.append(df)

    # Example usage
    # dfs = [df1, df2, df3, ...]  # List of DataFrames
    result = calculate_bin_statistics(dfs)

    # Display the result
    print(result)

    result[['bin', 'mean', 'std']].to_csv(args.output_csv, index=False)


if __name__ == "__main__":
    main()
