#!/usr/bin/env python3

import json
from collections import defaultdict
from typing import Dict, Any, List, TypedDict
import argparse


"""
RawMetricCounts
---------------
Represents the raw count of events for a given workflow or step.
Fields:
    - total: Total number of events observed
    - start: Number of times the workflow/step was started
    - success: Number of successful completions
    - error: Number of error outcomes
    - integrity_1: Count of integrity==1
    - integrity_0: Count of integrity==0
"""
class RawMetricCounts(TypedDict):
    total: int
    start: int
    success: int
    error: int
    integrity_1: int
    integrity_0: int


"""
WorkflowStepMetrics
--------------------
Stores computed metrics for a workflow or step.
Fields:
    - availability: Success ratio, or "N/A" if no starts
    - num_started: Count of start events
    - num_success: Count of success events
    - num_err: Count of error events
    - integrity_total: Number of events with integrity data
    - integrity_success: Count of integrity==1
    - integrity_failure: Count of integrity==0
    - integrity: Integrity ratio or "N/A" if no integrity data
"""
class WorkflowStepMetrics(TypedDict):
    availability: Any
    num_started: int
    num_success: int
    num_err: int
    integrity_total: int
    integrity_success: int
    integrity_failure: int
    integrity: Any


# Type aliases for cleaner annotations
JsonObject = Dict[str, Any]
JsonObjectList = List[JsonObject]
MetricsByName = Dict[str, RawMetricCounts]
RawMetricsCollection = Dict[str, MetricsByName]
ComputedMetricsReport = Dict[str, Dict[str, WorkflowStepMetrics]]


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


def collect_raw_metrics(json_objects: JsonObjectList) -> RawMetricsCollection:
    metrics: RawMetricsCollection = {
        "workflows": defaultdict(lambda: {"total": 0, "start": 0, "success": 0, "error": 0, "integrity_1": 0, "integrity_0": 0}),
        "steps": defaultdict(lambda: {"total": 0, "start": 0, "success": 0, "error": 0, "integrity_1": 0, "integrity_0": 0})
    }

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

            if "integrity" in obj:
                if obj["integrity"] == 1:
                    metrics[category][wf]["integrity_1"] += 1
                elif obj["integrity"] == 0:
                    metrics[category][wf]["integrity_0"] += 1
                else:
                    print(f"Warning: Unexpected integrity value '{obj['integrity']}' in object: {json.dumps(obj)}")
        else:
            print(f"Warning: Missing required fields in object: {json.dumps(obj)}")

    return metrics


def compute_metrics(raw_metrics: RawMetricsCollection) -> ComputedMetricsReport:
    report: ComputedMetricsReport = {}
    for category in ["workflows", "steps"]:
        category_report: Dict[str, WorkflowStepMetrics] = {}
        for wf, counts in raw_metrics[category].items():
            start = counts["start"]
            success = counts["success"]
            error = counts["error"]
            availability = round(success / start, 4) if start > 0 else "N/A"

            integrity_1 = counts["integrity_1"]
            integrity_0 = counts["integrity_0"]
            integrity_total = integrity_1 + integrity_0
            integrity = round(integrity_1 / integrity_total, 4) if integrity_total > 0 else "N/A"

            category_report[wf] = {
                "availability_average": availability,
                "availability_total": start,
                "availability_success": success,
                "availability_error": error,
                "integrity_average": integrity,
                "integrity_total": integrity_total,
                "integrity_success": integrity_1,
                "integrity_failure": integrity_0
            }
        report[category] = category_report
    return report


def main():
    parser = argparse.ArgumentParser(description="Parse workflow and step metrics from a log file.")
    parser.add_argument("logfile", help="Path to the log file")
    args = parser.parse_args()

    json_objects = extract_json_objects(args.logfile)
    raw_metrics = collect_raw_metrics(json_objects)
    report = compute_metrics(raw_metrics)

    output = {
        "metric_type": "workflow_summary",
        "report": {}
    }
    all_workflows = set(report["workflows"]).union(report["steps"])
    for wf in sorted(all_workflows):
        output["report"][wf] = {}
        if wf in report["workflows"]:
            output["report"][wf]["workflow"] = report["workflows"][wf]
        if wf in report["steps"]:
            output["report"][wf]["steps"] = report["steps"][wf]

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
