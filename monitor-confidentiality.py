#!/usr/bin/env python3

import time
import json
from datetime import datetime
from shell_handler import ShellHandler
from concurrent.futures import ThreadPoolExecutor, as_completed

# Global verbose flag
verbose = False


def get_node_score(node: dict, domain_leaders: dict) -> tuple:
    """
    Attempt to connect to a node and check for passwordless sudo access.

    Parameters:
        node (dict): Node dictionary from built_output.
        domain_leaders (dict): Mapping of domain names to admin credentials.

    Returns:
        tuple: (node name, result dictionary with confidentiality score and status message)
    """
    node_name = node['name']
    ip = node['addresses'][0]['addr']
    roles = node['enterprise_description']['roles']

    user = 'impactroot' if 'linux' in roles else 'impactadmin'
    password = 'pwned'
    shell = None
    result = {"confidentiality_score": 1.0, "status": "ssh failed"}

    try:
        shell = ShellHandler(ip, user, password=password, verbose=verbose)

        if 'windows' in roles:
            cmd = (
                "if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent())."
                "IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Output 'sudo access confirmed' } else { Write-Output 'sudo access not confirmed' }"
            )
            stdout, stderr, exit_code = shell.execute_powershell(cmd)
        else:
            cmd = "sudo -n true && echo 'sudo access confirmed' || echo 'sudo access not confirmed'"
            stdout, stderr, exit_code = shell.execute_cmd(cmd)

        flat_output = '\n'.join(stdout + stderr).strip().lower()
        if "sudo access confirmed" in flat_output:
            result = {"confidentiality_score": 0.0, "status": "ssh and sudo successful"}
        else:
            result = {"confidentiality_score": 0.5, "status": "ssh ok, sudo failed"}

        if verbose:
            print(f"[{node_name}] output: {flat_output} -> {result}")

    except Exception as e:
        if verbose:
            print(f"[{node_name}] Exception: {e}")

    return node_name, result


def compute_scores(built_output: dict) -> dict:
    """
    Compute passwordless sudo scores for all nodes in parallel.

    Parameters:
        built_output (dict): Full post-deploy-output.json dictionary.

    Returns:
        dict: Mapping of node names to result dictionaries.
    """
    nodes = built_output['enterprise_built']['deployed']['nodes']
    domain_leaders = built_output['enterprise_built']['setup']['setup_domains']['domain_leaders']

    scores = {}
    with ThreadPoolExecutor(max_workers=16) as executor:
        future_to_node = {executor.submit(get_node_score, node, domain_leaders): node for node in nodes}
        for future in as_completed(future_to_node):
            node_name, result = future.result()
            scores[node_name] = result

    return scores


def log_scores(scores: dict, output_file: str) -> None:
    """
    Append score entry with timestamp and summary stats to the given file or stdout.

    Parameters:
        scores (dict): Node scores.
        output_file (str): File path to write, or '-' for stdout.
    """
    status_counts = {"ssh and sudo successful": 0, "ssh ok, sudo failed": 0, "ssh failed": 0}
    total_score = 0
    total_nodes = len(scores)

    for node_result in scores.values():
        status = node_result.get("status", "unknown")
        score = node_result.get("confidentiality_score", 0)
        total_score += score
        if status in status_counts:
            status_counts[status] += 1
        else:
            status_counts[status] = 1

    average_score = total_score / total_nodes if total_nodes else 0

    result = {
        "timestamp": datetime.now().isoformat(),
        "total_nodes": total_nodes,
        "average_confidentiality_score": average_score,
        "count_score_0": status_counts.get("ssh and sudo successful", 0),
        "count_score_0.5": status_counts.get("ssh ok, sudo failed", 0),
        "count_score_1": status_counts.get("ssh failed", 0),
        "scores": scores
    }

    output_json = json.dumps(result)

    if output_file == "-":
        print(output_json)
    else:
        with open(output_file, 'a') as f:
            f.write(output_json + '\n')
            f.flush()

    if verbose:
        print(f"Logged scores at {result['timestamp']}: {scores}")


def sudo_access_monitor_loop(built_output: dict, timestep: int, output_file: str) -> None:
    """
    Loop to periodically compute and log scores.

    Parameters:
        built_output (dict): Full post-deploy-output.json dictionary.
        timestep (int): Time between checks in seconds.
        output_file (str): Log output file.
    """
    print("Confidentiality score monitoring started. Press Ctrl+C to exit.")
    try:
        while True:
            scores = compute_scores(built_output)
            log_scores(scores, output_file)
            time.sleep(timestep)
    except KeyboardInterrupt:
        print("Exiting monitor loop.")


def main() -> None:
    """
    Example test function that runs the monitoring loop.
    """
    import argparse
    global verbose
    parser = argparse.ArgumentParser()
    parser.add_argument("--post-deploy-output", "-p", required=True, help="Path to post-deploy-output.json")
    parser.add_argument("--time-interval", "-t", type=int, default=300, help="Time step in seconds")
    parser.add_argument("--output", "-o", default="-", help="Score output file (use '-' for stdout)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose debug output")
    args = parser.parse_args()

    verbose = args.verbose

    with open(args.post_deploy_output) as f:
        built_output = json.load(f)

    sudo_access_monitor_loop(built_output, args.time_interval, args.output)


if __name__ == '__main__':
    main()
