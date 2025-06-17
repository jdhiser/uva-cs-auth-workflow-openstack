#!/usr/bin/env python3

# Standard library imports
import json
import argparse
import sys
import logging
from joblib import Parallel, delayed

# Impact handler functions imported from role_impact module
from role_impact import impact_availability, impact_confidentiality, impact_integrity

# Mapping of impact types to their corresponding handler functions
impact_handlers = {
    "availability": impact_availability,
    "confidentiality": impact_confidentiality,
    "integrity": impact_integrity
}


#
# load_json_file - Load and parse a JSON file.
#
# parameters:
#         name -- Path to the JSON file.
#
# returns: Parsed JSON data.
#
def load_json_file(name: str) -> dict:
    with open(name) as f:
        return json.load(f)


#
# find_node_details - Find and return node details by name.
#
# parameters:
#         node_name -- The name of the node to find.
#         built -- The parsed deployment dictionary.
#
# returns: Node dictionary if found, else None.
#
def find_node_details(node_name: str, built: dict) -> dict:
    for node in built['deployed']['nodes']:
        if node.get('name') == node_name:
            return node
    return None


#
# print_result - Log the type of impact and target node.
#
# parameters:
#         impact_type -- Type of the impact (e.g., availability).
#         node_name -- Target node name.
#
# returns: None
#
def print_result(impact_type: str, node_name: str) -> None:
    logging.info(f"Impact type: {impact_type}")
    logging.info(f"Node name: {node_name}")


#
# run_impact - Execute the impact function for a specific node.
#
# parameters:
#         impact_type -- Type of the impact.
#         node_name -- Node to impact.
#         deployed -- Deployment details from config.
#
# returns: None
#
def run_impact(impact_type: str, node_name: str, deployed: dict) -> None:
    if impact_type not in impact_handlers:
        logging.error(f"Unknown impact type '{impact_type}'")
        return

    node = find_node_details(node_name, deployed)
    if not node:
        logging.error(f"Node '{node_name}' not found in deployment.")
        return

    print_result(impact_type, node_name)
    handler = impact_handlers[impact_type]
    handler(node)


#
# apply_impacts - Parse and dispatch impacts sequentially or in parallel.
#
# parameters:
#         impact_entries -- List of impact specifications (e.g., "availability=node1").
#         deployed -- Deployment configuration from the JSON file.
#         parallel -- Whether to execute in parallel (default: False).
#
# returns: None
#
def apply_impacts(impact_entries: list[str], deployed: dict, parallel: bool = False) -> None:
    parsed_impacts = []

    for impact_entry in impact_entries:
        if '=' not in impact_entry:
            logging.error("Each --impact must be in the format <type>=<node>")
            continue
        impact_type, node_name = impact_entry.split('=', 1)
        parsed_impacts.append((impact_type, node_name))

    if parallel:
        Parallel(n_jobs=-1, backend="threading")(delayed(run_impact)(itype, inode, deployed) for itype, inode in parsed_impacts)
    else:
        for itype, inode in parsed_impacts:
            run_impact(itype, inode, deployed)


#
# main - Main entry point for argument parsing and orchestration.
#
# returns: Exit status code.
#
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Simulate a cybersecurity impact on a node in post-deploy-output.json."
    )
    parser.add_argument(
        "-i", "--impact",
        action="append",
        type=str,
        help="Specify the impact in the form <type>=<node>. Can be repeated.",
        required=True
    )
    parser.add_argument("-c", "--config", type=str, help="Path to post-deploy-output.json", required=True)
    parser.add_argument("--parallel", action="store_true", help="Run impacts in parallel")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug logging")

    args = parser.parse_args()

    logging_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=logging_level, format='%(asctime)s %(levelname)s: %(message)s')

    built_data = load_json_file(args.config)
    enterprise_built = built_data.get("enterprise_built", {})
    deployed = enterprise_built.get("deployed", {})

    apply_impacts(args.impact, deployed, parallel=args.parallel)

    return 0


#
# Script execution entry point
#
if __name__ == '__main__':
    sys.exit(main())
