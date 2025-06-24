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


# ndjson format
def record_log(logfile, new_record):
    if not logfile:
        return
    json_line = json.dumps(new_record)

    with file_lock:  # Acquire the lock
        with open(logfile, 'a') as file:
            file.write(json_line + '\n')
            file.flush()

def emulate_login(number, login, user_data, built, seed, logfile):
    login_from = login['from']
    if 'ip' not in login_from:
        raise RuntimeError("Cannot get from IP for initial connection")

    login_to = login['to']
    if 'node' not in login_to:
        raise RuntimeError("Cannot get from IP for initial connection")

    duration = login['login_length']
    from_ip_str = login_from['ip']
    mac = login_from['mac']
    to_node_name = login_to['node']
    to_node = next(filter(lambda node: to_node_name == node['name'], built['deployed']['nodes']))
    domain = to_node['domain']
    targ_ip = to_node['addresses'][0]['addr']
    to_roles = to_node['enterprise_description']['roles']
    is_windows = 'windows' in to_roles

    user = next(filter(lambda user: login['user'] == user['user_profile']['username'], user_data))
    username = user['user_profile']['username']
    fq_username = f"{username}@{domain}"
    password = user['user_profile']['password']

    mac = fake.mac_address()
    dev = 'v' + mac.replace(':', '')
    cmd = "not available yet"
    stdout = ""
    stderr = ""
    stdout2 = ""
    stderr2 = ""
    exit_status = -1
    exit_status2 = -1
    shell = None

    try:
        logger.info(f"#{number} from ip {from_ip_str} with mac {mac} to ip = {targ_ip}, user = {username}@{domain}, password = {password}")

        if use_fake_fromip:
            add_command = (
                'sudo modprobe dummy ; '
                'sudo ip link add ' + dev + ' type dummy ; '
                'sudo ifconfig ' + dev + ' hw ether ' + mac + ' ; '
                'sudo ip addr add ' + from_ip_str + '/32' + ' dev ' + dev + ' ; '
                'sudo ip link set dev ' + dev + ' up'
            )
            os.system(add_command)
            del_command = 'sudo ip link delete ' + dev + ' type dummy'
        else:
            from_ip_str = None
            del_command = None

        shell = ShellHandler(targ_ip, fq_username, password=password, from_ip=from_ip_str, verbose=verbose)

        cmd1 = 'echo ' + json.dumps(login) + " > action.json  "
        stdout, stderr, exit_status = shell.execute_cmd(cmd1)

        if is_windows:
            cmd2 = f'echo "{username}\n{password}"'
            stdout2, stderr2, exit_status2 = shell.execute_powershell(cmd2)
        else:
            passfile = f"/tmp/shib_login.{username}"
            cmd2 = f'echo "{username}\n{password}" > {passfile}; stdbuf -i0 -oL -eL xvfb-run -a "/opt/pyhuman/bin/python" -u "/opt/pyhuman/human.py" --clustersize 5 --taskinterval 10 --taskgroupinterval 500 --stopafter {duration} --seed {seed} --extra  passfile {passfile}'
            stdout2, stderr2, exit_status2 = shell.execute_cmd(cmd2, verbose=True)

        if is_windows:
            logger.info("ssh successful for windows")
        else:
            logger.info("ssh successful for linux")

        if del_command is not None:
            os.system(del_command)
    except KeyboardInterrupt:
        logger.warning(f"Aborting due to KeyboardInterrupt from ip {from_ip_str} with mac {mac} to ip = {targ_ip}, user = {username}@{domain}, password = {password}")
        raise
    except Exception as e:
        logger.exception(f"FAILED CONNECTION {'windows' if is_windows else 'linux'} to user = {username}@{domain}@{targ_ip}, password = {password}")
        pass

    new_output = {"cmd": cmd, "stdout": [stdout, stdout2], "stderr": [
        stderr, stderr2], "login": login, "exit_status": [exit_status, exit_status2]}

    record_log(logfile, new_output)

    login_results.append(new_output)

    stdout = stderr = stdout2 = stderr2 = ""
    exit_status = exit_status2 = -1
    shell = None

    return

connection_number = 0

def load_json_file(name: str):
    with open(name) as f:
        return json.load(f)

def get_earliest_login(logins):
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
    global nowish
    users = logins_file['users']
    flat_logins = flatten_logins(logins_file['logins'], rebase_time)

    executors = { 'default': ThreadPoolExecutor(2000) }
    scheduler = BackgroundScheduler(executors=executors)

    if seed is None:
        seed = logins_file.get('seed', random.randint(0, 10000))

    logger.info(f"Starting seed: {seed}")

    number = 0
    for login in flat_logins:
        seed += number
        number += 1
        if fast_debug:
            nowish += timedelta(seconds=3)
            login['login_start'] = str(nowish)
            login['login_length'] = 60

        job_start = datetime.strptime(login['login_start'], timestamp_format)
        if fast_debug:
            emulate_login(number=number, login=login, user_data=users,
                          built=setup_output_file['enterprise_built'], seed=seed, logfile=logfile)
        else:
            scheduler.add_job(emulate_login, 'date', run_date=job_start, kwargs={
                'number': number, 'login': login, 'user_data': users, 'built': setup_output_file['enterprise_built'], 'seed': seed, 'logfile': logfile})

    logger.info(f"Scheduler ready at {datetime.now()}")
    return scheduler

def main():
    parser = argparse.ArgumentParser(description="Process post-deploy output and logins with optional flags.")
    parser.add_argument("post_deploy_output", type=str, help="Path to post-deploy-output.json")
    parser.add_argument("logins", type=str, help="Path to logins.json")
    parser.add_argument("--fast-debug", action="store_true", help="Enable fast debug mode")
    parser.add_argument("--seed", type=int, help="Specify a seed value")
    parser.add_argument("--logfile", type=str, help="Log output file", default=f"workflow.{emulation_start_time.isoformat()}.log")
    parser.add_argument("--rebase-time", action='store_true', help="Rebase timestamps from logins.json", default=False)

    args = parser.parse_args()

    setup_output_file = load_json_file(args.post_deploy_output)
    logins_file = load_json_file(args.logins)
    scheduler = schedule_logins(logins_file, setup_output_file, logfile=args.logfile, fast_debug=args.fast_debug, seed=args.seed, rebase_time=args.rebase_time)

    scheduler.start()
  
    try:
        while scheduler.get_jobs():
            wakeup_time = scheduler.get_jobs()[0].next_run_time
            seconds_to_wakeup = (wakeup_time - datetime.now(timezone.utc)).total_seconds()
            logger.info(f"Next job at {wakeup_time}, {seconds_to_wakeup:.2f}s from now.")
            time.sleep(max(5, seconds_to_wakeup / 2))
    except KeyboardInterrupt:
        logger.warning("Shutting down early due to keyboard interrupt.")

    scheduler.shutdown()

    output = {
        'start_time': emulation_start_time.isoformat(),
        'logins': login_results,
        'end_time': str(datetime.now())
    }

    with open("logins-output.json", "w") as f:
        json.dump(output, f, default=str)
    logger.info("Emulation complete. Results written to logins-output.json")

    return 0

if __name__ == '__main__':
    sys.exit(main())

