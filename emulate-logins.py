#!/usr/bin/env python

import threading
import traceback
import time
import sys
import os
import json
import random
import argparse
import logging
from shell_handler import ShellHandler
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

# Remove Paramiko's default handlers
for name in ["paramiko", "paramiko.transport", "paramiko.auth_handler"]:
    plogger = logging.getLogger(name)
    plogger.setLevel(logging.WARN)  
    plogger.handlers.clear()       
    plogger.propagate = False

# faker stuff
from faker import Faker

# scheduler stuff.
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.executors.pool import ThreadPoolExecutor

# configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s:%(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# global variables
login_results = []
fake = Faker()
nowish = datetime.now()
scheduler = BackgroundScheduler()
verbose = False
use_fake_fromip = False
emulation_start_time = datetime.now().replace(microsecond=0)

timestamp_format = '%Y-%m-%d %H:%M:%S.%f'

# functions

file_lock = threading.Lock()



def contains_bad_term(lines: List[str]) -> bool:
    """
    Check if any line in a list of strings contains suspicious terms.

    Args:
        lines (List[str]): List of output lines (stdout or stderr).

    Returns:
        bool: True if 'pwned' or 'pwnd' is found (case insensitive), False otherwise.
    """
    return any("pwned" in line.lower() or "pwnd" in line.lower() for line in lines)

def record_log(logfile: Optional[str], new_record: Dict[str, Any]) -> None:
    """
    Append a JSON-encoded dictionary to a newline-delimited JSON (ndjson) log file.

    Automatically evaluates integrity of stdout/stderr fields and adds an 'integrity' field to the record:
    - integrity = 0 if 'pwned' or 'pwnd' appears in stdout or stderr (case insensitive)
    - integrity = 1 otherwise

    Args:
        logfile (str): Path to the output log file. If None or empty, nothing is written.
        new_record (dict): Dictionary to be serialized and written.
    """
    if not logfile:
        return

    stdout = new_record.get("stdout", [])
    stderr = new_record.get("stderr", [])
    integrity = 0 if contains_bad_term(stdout + stderr) else 1
    new_record["integrity"] = integrity

    json_line = json.dumps(new_record)

    with file_lock:  # Acquire the lock to prevent concurrent write collisions
        with open(logfile, 'a') as file:
            file.write(json_line + '\n')
            file.flush()


def log_ssh(status: str, message: str, host_ip: str, ssh_output: List[str], step_name:Optional[str] = None) -> None:

    """
    Log an SSH connection status message in JSON format to stdout.

    Optionally emits a second log line with a step name for recognized status types.

    Args:
        status (str): The SSH status type (e.g. 'start', 'success').
        message (str): Descriptive message of the SSH event.
        host_ip (str): The IP address of the target host.
        ssh_ouput (List[str]): the output of the ssh.  Check if this contains "pwnd" for integrity score.
        step_name (Optional[str]): a step name, if this is a step.  None if this is a full workflow.
    """
    timestamp = datetime.utcnow().isoformat()
    log_entry = {
        "timestamp": timestamp,
        "workflow_name": "ssh",
        "status": status,
        "message": message,
        "host_ip": host_ip,
    }
    if status != "start":
        log_entry["integrity"] =  0 if contains_bad_term(ssh_output) else 1

    if step_name is not None:
        log_entry["step_name"] = step_name
    print(json.dumps(log_entry))


def get_target_node(built, node_name):
    """Retrieve a node definition from the deployment metadata."""
    return next(filter(lambda node: node['name'] == node_name, built['deployed']['nodes']))

def get_user_credentials(user_data, username):
    """Fetch a user entry matching the given username."""
    return next(filter(lambda user: user['user_profile']['username'] == username, user_data))

def apply_fake_fromip(dev, mac, from_ip):
    """Optionally set up a dummy network interface with spoofed MAC and IP."""
    add_command = (
        f'sudo modprobe dummy ; '
        f'sudo ip link add {dev} type dummy ; '
        f'sudo ifconfig {dev} hw ether {mac} ; '
        f'sudo ip addr add {from_ip}/32 dev {dev} ; '
        f'sudo ip link set dev {dev} up'
    )
    os.system(add_command)
    del_command = f'sudo ip link delete {dev} type dummy'
    return del_command

def run_windows_login(shell, username, password):
    """Run a simple echo command to simulate login on Windows."""
    cmd = f'echo "{username}\n{password}"'
    return shell.execute_powershell(cmd)

def run_linux_login(shell, username, password, duration, seed):
    """Simulate a Linux login using the pyhuman automation script."""
    passfile = f"/tmp/shib_login.{username}"
    cmd = (
        f'echo "{username}\n{password}" > {passfile}; '
        f'stdbuf -i0 -oL -eL xvfb-run -a "/opt/pyhuman/bin/python" -u "/opt/pyhuman/human.py" '
        f'--clustersize 5 --taskinterval 10 --taskgroupinterval 500 --stopafter {duration} '
        f'--seed {seed} --extra passfile {passfile}'
    )
    return shell.execute_cmd(cmd, verbose=True)

def emulate_login(number, login, user_data, built, seed, logfile):
    """
    Simulate a login attempt from one node to another using SSH or PowerShell.

    The function handles IP spoofing (optional), user resolution, OS-specific login behavior,
    logging, and result recording.
    """
    # Validate login source and destination
    login_from = login['from']
    if 'ip' not in login_from:
        raise RuntimeError("Cannot get from IP for initial connection")
    login_to = login['to']
    if 'node' not in login_to:
        raise RuntimeError("Cannot get destination node for initial connection")

    # Extract connection details
    from_ip_str = login_from['ip']
    mac = fake.mac_address()
    dev = 'v' + mac.replace(':', '')
    to_node = get_target_node(built, login_to['node'])
    domain = to_node['domain']
    targ_ip = to_node['addresses'][0]['addr']
    is_windows = 'windows' in to_node['enterprise_description']['roles']

    # Extract credentials
    user = get_user_credentials(user_data, login['user'])
    username = user['user_profile']['username']
    fq_username = f"{username}@{domain}"
    password = user['user_profile']['password']

    # Log connection start
    msg = f"#{number} from ip {from_ip_str} with mac {mac} to ip = {targ_ip}, user = {fq_username}, password = {password}"
    log_ssh("start", msg, targ_ip, [])
    log_ssh("start", msg, targ_ip, [], "connect")
    logger.info(msg)

    shell = None
    del_command = None

    stdout1=[]
    stdout2=[]
    stderr1=[]
    stderr2=[]
    try:
        # Apply fake IP if configured
        if use_fake_fromip:
            del_command = apply_fake_fromip(dev, mac, from_ip_str)
        else:
            from_ip_str = None

        # Initialize shell session
        shell = ShellHandler(targ_ip, fq_username, password=password, from_ip=from_ip_str, verbose=verbose)

        # Send login metadata
        cmd1 = 'echo ' + json.dumps(login) + " > action.json"
        stdout1, stderr1, status1 = shell.execute_cmd(cmd1)

        # Run OS-specific login
        if is_windows:
            stdout2, stderr2, status2 = run_windows_login(shell, username, password)
        else:
            stdout2, stderr2, status2 = run_linux_login(shell, username, password, login['login_length'], seed)

        logger.info("ssh successful for windows" if is_windows else "ssh successful for linux")

    except KeyboardInterrupt:
        logger.warning(f"Aborting due to KeyboardInterrupt: {msg}")
        raise
    except Exception as e:
        log_ssh("error", msg, targ_ip, stdout1+stderr1+stdout2+stderr2, "connect")
        log_ssh("error", msg, targ_ip, stdout1+stderr1+stdout2+stderr2)
        logger.exception(f"FAILED CONNECTION {'windows' if is_windows else 'linux'}: {msg}")
    finally:
        if del_command:
            os.system(del_command)

    # Compose output log record
    new_output = {
        "cmd": cmd1,
        "stdout": stdout1 + stdout2,
        "stderr": stderr1 + stderr2,
        "login": login,
        "exit_status": [status1, status2]
    }

    #record_log(logfile, new_output)
    log_ssh("success", msg, targ_ip, stdout1+stderr1+stdout2+stderr2, "connect")
    log_ssh("success", msg, targ_ip, stdout1+stderr1+stdout2+stderr2)
    login_results.append(new_output)

    # Reset variables for memory hygiene
    shell = None


def load_json_file(name: str):
    """
    Load a JSON file from disk and return its contents.

    Args:
        name (str): Path to the JSON file.

    Returns:
        dict: Parsed JSON content.
    """
    with open(name) as f:
        return json.load(f)

def get_earliest_login(logins):
    """
    Determine the earliest login timestamp across all users and days.

    Logs a warning if any user has no logins on a given day.

    Args:
        logins (dict): Nested login structure keyed by day and user.

    Returns:
        datetime: The earliest login time found.
    """
    days = logins['days']
    earliest = datetime.now()

    for day in days:
        for user in days[day]:
            user_logins = days[day][user]
            if not user_logins:
                logger.warning(f"Caution:  {user} is taking a day off, on {day}")
                continue

            login_start = datetime.strptime(user_logins[0]['login_start'], timestamp_format)
            if earliest > login_start:
                earliest = login_start

    return earliest

def flatten_logins(logins, rebase_time=False):
    """
    Flatten a nested login structure into a list of login records.

    Optionally rebases login timestamps relative to the current time
    while preserving order and gaps.

    Args:
        logins (dict): Nested login structure with days and users.
        rebase_time (bool): Whether to shift timestamps to align with now.

    Returns:
        list: Flattened list of login dictionaries.
    """
    flat_logins = []
    days = logins['days']

    if rebase_time:
        now = datetime.now()
        earliest_login = get_earliest_login(logins)
        rebase_delta = now - earliest_login + timedelta(seconds=45)

    for day in days:
        for user in days[day]:
            if rebase_time:
                for index in days[day][user]:
                    login_start = datetime.strptime(index['login_start'], timestamp_format)
                    login_end = datetime.strptime(index['login_end'], timestamp_format)
                    index['login_start'] = str(login_start + rebase_delta)
                    index['login_end'] = str(login_end + rebase_delta)

            flat_logins += days[day][user]

    return flat_logins


def schedule_logins(logins_file, setup_output_file, logfile=None, fast_debug=False, seed=None, rebase_time=False):
    """
    Schedule or execute login simulation events based on input login structure.

    Optionally rebases time, supports immediate execution for debugging,
    and uses a background scheduler to spread logins over real or simulated time.

    Args:
        logins_file (dict): JSON structure containing login entries and user data.
        setup_output_file (dict): Setup data from prior deployment used to resolve targets.
        logfile (str, optional): File to log execution results.
        fast_debug (bool): If True, executes all logins immediately and quickly.
        seed (int, optional): Seed for task randomness. If None, a random seed is generated.
        rebase_time (bool): Whether to shift login timestamps to start near now.

    Returns:
        BackgroundScheduler: The scheduler instance managing deferred jobs.
    """
    global nowish

    # Extract user info and flatten login schedule into a flat list
    users = logins_file['users']
    flat_logins = flatten_logins(logins_file['logins'], rebase_time)

    # Configure the scheduler with a large thread pool to handle concurrency
    executors = { 'default': ThreadPoolExecutor(2000) }
    scheduler = BackgroundScheduler(executors=executors)

    # Use provided seed or fallback to stored/random
    if seed is None:
        seed = logins_file.get('seed', random.randint(0, 10000))

    logger.info(f"Starting seed: {seed}")

    number = 0
    for login in flat_logins:
        seed += number
        number += 1

        # If debugging, compress timing and shift schedule to nowish
        if fast_debug:
            nowish += timedelta(seconds=3)
            login['login_start'] = str(nowish)
            login['login_length'] = 60

        # Convert login_start string into a datetime object
        job_start = datetime.strptime(login['login_start'], timestamp_format)

        # In debug mode, run immediately. Otherwise, schedule for later.
        if fast_debug:
            emulate_login(
                number=number,
                login=login,
                user_data=users,
                built=setup_output_file['enterprise_built'],
                seed=seed,
                logfile=logfile
            )
        else:
            scheduler.add_job(
                emulate_login,
                'date',
                run_date=job_start,
                kwargs={
                    'number': number,
                    'login': login,
                    'user_data': users,
                    'built': setup_output_file['enterprise_built'],
                    'seed': seed,
                    'logfile': logfile
                }
            )

    logger.info(f"Scheduler ready at {datetime.now()}")
    return scheduler


def main():
    """
    Main function for orchestrating login emulation.

    Parses arguments, loads configuration and login data, schedules login events,
    runs the scheduler loop, and writes final output upon completion.

    Returns:
        int: Exit status code (0 for success).
    """
    # Set up argument parser and expected CLI options
    parser = argparse.ArgumentParser(description="Process post-deploy output and logins with optional flags.")
    parser.add_argument("post_deploy_output", type=str, help="Path to post-deploy-output.json")
    parser.add_argument("logins", type=str, help="Path to logins.json")
    parser.add_argument("--fast-debug", action="store_true", help="Enable fast debug mode")
    parser.add_argument("--seed", type=int, help="Specify a seed value")
    parser.add_argument("--logfile", type=str, help="Log output file", default=f"workflow.{emulation_start_time.isoformat()}.log")
    parser.add_argument("--rebase-time", action='store_true', help="Rebase timestamps from logins.json", default=False)

    args = parser.parse_args()

    # Load JSON input files
    setup_output_file = load_json_file(args.post_deploy_output)
    logins_file = load_json_file(args.logins)

    # Schedule login attempts from JSON
    scheduler = schedule_logins(
        logins_file,
        setup_output_file,
        logfile=args.logfile,
        fast_debug=args.fast_debug,
        seed=args.seed,
        rebase_time=args.rebase_time
    )

    scheduler.start()

    # Loop until all scheduled jobs are completed
    try:
        while scheduler.get_jobs():
            wakeup_time = scheduler.get_jobs()[0].next_run_time
            seconds_to_wakeup = (wakeup_time - datetime.now(timezone.utc)).total_seconds()
            logger.info(f"Next job at {wakeup_time}, {seconds_to_wakeup:.2f}s from now.")
            time.sleep(max(5, seconds_to_wakeup / 2))
    except KeyboardInterrupt:
        logger.warning("Shutting down early due to keyboard interrupt.")

    scheduler.shutdown()

    # Collect and store results to file
    output = {
        'start_time': emulation_start_time.isoformat(),
        'logins': login_results,
        'end_time': str(datetime.now())
    }

    with open("logins-output.json", "w") as f:
        json.dump(output, f, default=str)
    logger.info("Emulation complete. Results written to logins-output.json")

    return 0

# Standard CLI entry point
if __name__ == '__main__':
    sys.exit(main())

