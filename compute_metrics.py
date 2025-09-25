#!/usr/bin/env python3

import json
from collections import defaultdict
from typing import Dict, Any, List
import argparse


def extract_json_objects(log_file_path: str) -> List[Dict[str, Any]]:
    """
    Extract valid JSON objects from the log file.

    Parameters:
        log_file_path (str): Path to the log file

    Returns:
        List[Dict[str, Any]]: List of valid JSON objects
    """
    json_objects = []
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


def parse_json_objects(json_objects: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    """
    Parse JSON objects to extract workflow statistics.

    Parameters:
        json_objects (List[Dict[str, Any]]): List of JSON objects

    Returns:
        Dict[str, Dict[str, int]]: Metrics for each workflow
    """
    metrics: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "start": 0, "success": 0, "error": 0})
    for obj in json_objects:
        if "workflow_name" in obj and "status" in obj:
            print(f"obj={obj}")
            wf = obj["workflow_name"]
            status = obj["status"]
            metrics[wf]["total"] += 1
            if status == "start":
                metrics[wf]["start"] += 1
            elif status == "success":
                metrics[wf]["success"] += 1
            elif status == "error":
                metrics[wf]["error"] += 1
            else:
                metrics[wf]["other"] += 1
    return metrics


def compute_availability(metrics: Dict[str, Dict[str, int]]) -> Dict[str, Dict[str, Any]]:
    """
    Compute availability for each workflow.

    Parameters:
        metrics (Dict[str, Dict[str, int]]): Raw metrics per workflow

    Returns:
        Dict[str, Dict[str, Any]]: Metrics with availability included
    """
    availability_report = {}
    for wf, counts in metrics.items():
        start = counts["start"]
        success = counts["success"]
        error = counts["error"]
        availability = round(success / start, 4) if start > 0 else "N/A"
        availability_report[wf] = {
            "availability": availability,
            "num_started": start,
            "num_success": success,
            "num_err": error
        }
    return availability_report


def main():
    parser = argparse.ArgumentParser(description="Parse workflow metrics from a log file.")
    parser.add_argument("logfile", help="Path to the log file")
    args = parser.parse_args()

    json_objects = extract_json_objects(args.logfile)
    metrics = parse_json_objects(json_objects)
    report = compute_availability(metrics)

    for wf, data in report.items():
        print(f"=== Metrics for {wf}")
        print(f"Availability: {data['availability']}")
        print(f"Started: {data['num_started']}")
        print(f"Success: {data['num_success']}")
        print(f"Errors: {data['num_err']}\n")


if __name__ == "__main__":
    main()
