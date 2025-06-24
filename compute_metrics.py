#!/usr/bin/env python3

import json
from collections import defaultdict
from typing import Dict, Any, List, TypedDict
import argparse


"""
MetricCounts
------------
Represents the raw count of events for a given workflow or step.
Fields:
    - total: Total number of events observed
    - start: Number of times the workflow/step was started
    - success: Number of successful completions
    - error: Number of error outcomes
"""
class MetricCounts(TypedDict):
    total: int
    start: int
    success: int
    error: int


"""
AvailabilityStats
------------------
Stores computed availability statistics for a workflow or step.
Fields:
    - availability: Success ratio, or "N/A" if no starts
    - num_started: Count of start events
    - num_success: Count of success events
    - num_err: Count of error events
"""
class AvailabilityStats(TypedDict):
    availability: Any  # Can be float or "N/A"
    num_started: int
    num_success: int
    num_err: int


# Type aliases for cleaner annotations
JsonObject = Dict[str, Any]
JsonObjectList = List[JsonObject]
MetricsByName = Dict[str, MetricCounts]
MetricsCollection = Dict[str, MetricsByName]
AvailabilityReport = Dict[str, Dict[str, AvailabilityStats]]


"""
extract_json_objects
--------------------
Reads a log file line by line and extracts valid JSON objects.

Parameters:
    log_file_path (str): Path to the log file

Returns:
    JsonObjectList: A list of dictionaries parsed from JSON lines
"""
def extract_json_objects(log_file_path: str) -> JsonObjectList:
    json_objects: JsonObjectList = []
    with open(log_file_path, 'r') as file:
        for line in file:
            line = line.strip()
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    json_objects.append(obj)
            except json.JSONDecodeError:
                continue
    return json_objects


"""
parse_json_objects
------------------
Classifies and counts status occurrences for each workflow and step.

Parameters:
    json_objects (JsonObjectList): List of valid JSON dictionaries

Returns:
    MetricsCollection: Aggregated raw counts for workflows and steps
"""
def parse_json_objects(json_objects: JsonObjectList) -> MetricsCollection:
    metrics: MetricsCollection = {
        "workflows": defaultdict(lambda: {"total": 0, "start": 0, "success": 0, "error": 0}),
        "steps": defaultdict(lambda: {"total": 0, "start": 0, "success": 0, "error": 0})
    }

    # Classify each JSON object and increment relevant counters
    for obj in json_objects:
        if "workflow_name" in obj and "status" in obj:
            wf = obj["workflow_name"]
            status = obj["status"]
            category = "steps" if "step_name" in obj else "workflows"
            metrics[category][wf]["total"] += 1
            if status == "start":
                metrics[category][wf]["start"] += 1
            elif status == "success":
                metrics[category][wf]["success"] += 1
            elif status == "error":
                metrics[category][wf]["error"] += 1
            else:
                print(f"Warning: Unrecognized status '{status}' in object: {json.dumps(obj)}")
        else:
            print(f"Warning: Missing required fields in object: {json.dumps(obj)}")

    return metrics


"""
compute_availability
--------------------
Converts raw counts into availability statistics for each workflow/step.

Parameters:
    metrics (MetricsCollection): Raw parsed counts per name

Returns:
    AvailabilityReport: Availability statistics with success ratios
"""
def compute_availability(metrics: MetricsCollection) -> AvailabilityReport:
    report: AvailabilityReport = {}
    for category in ["workflows", "steps"]:
        category_report: Dict[str, AvailabilityStats] = {}
        for wf, counts in metrics[category].items():
            start = counts["start"]
            success = counts["success"]
            error = counts["error"]
            availability = round(success / start, 4) if start > 0 else "N/A"
            category_report[wf] = {
                "availability": availability,
                "num_started": start,
                "num_success": success,
                "num_err": error
            }
        report[category] = category_report
    return report


"""
print_metrics
-------------
Prints availability statistics for a single workflow or step.

Parameters:
    label (str): Header label for the output block
    data (AvailabilityStats): The computed statistics to display
"""
def print_metrics(label: str, data: AvailabilityStats):
    print(f"\n{label}")
    print(f"Availability: {data['availability']}")
    print(f"Started: {data['num_started']}")
    print(f"Success: {data['num_success']}")
    print(f"Errors: {data['num_err']}")


"""
print_summary
-------------
Aggregates and prints total availability across all workflows or steps.

Parameters:
    label (str): Category label (e.g., "Workflows")
    count (int): Number of unique names observed
    start (int): Total start events across all names
    success (int): Total success events across all names
"""
def print_summary(label: str, count: int, start: int, success: int):
    if start:
        availability = round(success / start, 4)
        print_metrics(f"Total {label}: {count}", {
            "availability": availability,
            "num_started": start,
            "num_success": success,
            "num_err": start - success
        })
    else:
        print(f"No {label.lower()} starts to compute availability.")


"""
main
----
Entry point for command-line invocation.
Parses arguments, processes the log, and prints detailed and summary metrics.
"""
def main():
    parser = argparse.ArgumentParser(description="Parse workflow and step metrics from a log file.")
    parser.add_argument("logfile", help="Path to the log file")
    args = parser.parse_args()

    # Read and process input log
    json_objects = extract_json_objects(args.logfile)
    metrics = parse_json_objects(json_objects)
    report = compute_availability(metrics)

    # Prepare aggregate stats
    all_keys = set(report["workflows"]).union(report["steps"])
    total_workflows = total_steps = 0
    total_workflow_success = total_step_success = 0
    total_workflow_start = total_step_start = 0

    # Output metrics per workflow
    for wf in sorted(all_keys):
        if wf in report["workflows"]:
            data = report["workflows"][wf]
            total_workflows += 1
            total_workflow_start += data["num_started"]
            total_workflow_success += data["num_success"]
            print_metrics(f"=== WORKFLOW: {wf} ===", data)

        if wf in report["steps"]:
            data = report["steps"][wf]
            total_steps += 1
            total_step_start += data["num_started"]
            total_step_success += data["num_success"]
            print_metrics(f"--- STEPS for {wf} ---", data)

    # Output summary
    print("\n=== SUMMARY ===")
    print_summary("Workflows", total_workflows, total_workflow_start, total_workflow_success)
    print_summary("Steps", total_steps, total_step_start, total_step_success)


if __name__ == "__main__":
    main()
