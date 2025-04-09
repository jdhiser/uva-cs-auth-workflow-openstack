#!/usr/bin/env python

import threading
import traceback
import time
import sys
import os
import json
import random
import argparse
from shell_handler import ShellHandler
from datetime import datetime, timezone, timedelta

# faker stuff
from faker import Faker

# scheduler stuff.
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.executors.pool import ThreadPoolExecutor

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
    json_line = json.dumps(new_record)

    with file_lock:  # Acquire the lock
        with open(logfile, 'a') as file:
            file.write(json_line + '\n')
            file.flush()


def emulate_login(number, login, user_data, built, seed, logfile):

    # print(f"At {datetime.now()}, emulating login: " +  json.dumps(login))
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
    # print("To node:" + json.dumps(to_node,indent=2))
    domain = to_node['domain']
    targ_ip = to_node['addresses'][0]['addr']
    to_roles = to_node['enterprise_description']['roles']
    is_windows = 'windows' in to_roles

    # print("user:" + json.dumps(user_data,indent=2))
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
        print(f"At {datetime.now()}, #{number} from ip {from_ip_str} with mac {mac} to ip = {targ_ip}, user = {username}@{domain}, password = {password}")

        if use_fake_fromip:
            add_command = (
                'sudo modprobe dummy ; '
                'sudo ip link add ' + dev + ' type dummy ; '
                'sudo ifconfig ' + dev + ' hw ether ' + mac + ' ; '
                'sudo ip addr add ' + from_ip_str + '/32' + ' dev ' + dev + ' ; '
                'sudo ip link set dev ' + dev + ' up'
            )

            # print("add-dummy-nic cmd: " + add_command)
            os.system(add_command)

            #        'sudo ip addr del ' + from_ip_str+'/32' + ' dev ' + dev + ' ; '
            del_command = (
                'sudo ip link delete ' + dev + ' type dummy'
            )

            # sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            from_ip_str = None
            del_command = None

        if is_windows:
            print("To windows node")
        else:
            print("To linux node")

        shell = ShellHandler(targ_ip, fq_username, password=password, from_ip=from_ip_str, verbose=verbose)

        # works on linux and windows
        # cmd ='python -c "import json;  print(json.dumps(json.load(open(\'action.json\',\'r\'))))"'

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
            print("ssh successful for windows")
        else:
            print("ssh successful for linux")
        if del_command is not None:
            os.system(del_command)
    except KeyboardInterrupt:
        print(f"At {datetime.now()}, Aborting due to Keyboard request connection from ip {from_ip_str} with mac {mac} to ip = {targ_ip}, user = {username}@{domain}, password = {password}")
        raise
    except Exception as e:
        print("")
        if is_windows:
            print(
                f"FAILED CONNECTION windows: At {datetime.now()}, Failed connect to user = {username}@{domain}@{targ_ip}, password = {password}")
        else:
            print(
                f"FAILED CONNECTION linux: At {datetime.now()}, Failed connect to user = {username}@{domain}@{targ_ip}, password = {password}")
        print(f"{e}")
        traceback.print_exception(e)
        pass

    new_output = {"cmd": cmd, "stdout": [stdout, stdout2], "stderr": [
        stderr, stderr2], "login": login, "exit_status": [exit_status, exit_status2]}

    # dump to log as ssh sessions complete
    if logfile:
        record_log(logfile, new_output)

    # stash away output as before
    login_results.append(new_output)

    # explicitly clean up the shell so we don't somehow save anything from it
    stdout = ""
    stderr = ""
    stdout2 = ""
    stderr2 = ""
    exit_status = -1
    exit_status2 = -1
    shell = None

    return


connection_number = 0


def load_json_file(name: str):
    with open(name) as f:
        # Read the file
        ret = json.load(f)
    return ret


def get_earliest_login(logins):
    days = logins['days']
    earliest = datetime.now()
    for day in days:
        for user in days[day]:
            login_start = datetime.strptime(days[day][user][0]['login_start'], timestamp_format)
            if earliest > login_start:
                earliest = login_start
    return earliest


def flatten_logins(logins, rebase_time=False):

    flat_logins = []
    days = logins['days']

    # compute the time delta to add to every login_start and login_end timestamps
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
                    rebased_login_start = login_start + rebase_delta
                    rebased_login_end = login_end + rebase_delta
                    index['login_start'] = str(rebased_login_start)
                    index['login_end'] = str(rebased_login_end)

            flat_logins += days[day][user]
    return flat_logins


def schedule_logins(logins_file, setup_output_file, logfile=None, fast_debug=False, seed=None, rebase_time=False):
    global nowish
    users = logins_file['users']
    flat_logins = flatten_logins(logins_file['logins'], rebase_time)

    executors = {
        'default': ThreadPoolExecutor(2000)
    }
    scheduler = BackgroundScheduler(executors=executors)

    # Pick a seed if none specified
    if seed is None:
        if logins_file['seed']:
            seed = logins_file['seed']
        else:
            seed = random.randint(0, 10000)

    print(f"At {datetime.now()} - starting seed: {seed}")

    number = 0
    for login in flat_logins:
        # Make sure each workflow gets a different (yet deterministic) seed
        seed += number
        number += 1
        if fast_debug:
            nowish += timedelta(seconds=3)
            login['login_start'] = str(nowish)
            login['login_length'] = 60

        job_start = login['login_start']
        job_start = datetime.strptime(job_start, '%Y-%m-%d %H:%M:%S.%f')
        if fast_debug:
            emulate_login(number=number, login=login, user_data=users,
                          built=setup_output_file['enterprise_built'], seed=seed, logfile=logfile)
        else:
            scheduler.add_job(emulate_login, 'date', run_date=job_start, kwargs={
                'number': number, 'login': login, 'user_data': users, 'built': setup_output_file['enterprise_built'], 'seed': seed, 'logfile': logfile})

    print(f"Now is {datetime.now()}")
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

    # Parse and retrieve args
    setup_output_file = load_json_file(args.post_deploy_output)
    logins_file = load_json_file(args.logins)
    fast_debug = args.fast_debug
    seed = args.seed
    logfile = args.logfile
    rebase_time = args.rebase_time

    output = {}
    output['start_time'] = emulation_start_time.isoformat()

    scheduler = schedule_logins(logins_file, setup_output_file, logfile=logfile, fast_debug=fast_debug, seed=seed, rebase_time=rebase_time)

    scheduler.start()

    try:
        while len(scheduler.get_jobs()) > 0:
            wakeup_time = scheduler.get_jobs()[0].next_run_time
            seconds_to_wakeup = (wakeup_time - datetime.now(timezone.utc)).total_seconds()
            print(f"Next job at {wakeup_time}, {seconds_to_wakeup} from now.")
            sleep_time = max(5, seconds_to_wakeup / 2)
            time.sleep(sleep_time)
    except KeyboardInterrupt:
        print("Shutting down early due to keyboard interrupt.")

    scheduler.shutdown()

    output['logins'] = login_results
    output['end_time'] = str(datetime.now())

    with open("logins-output.json", "w") as f:
        json.dump(output, f, default=str)
    print("Emulation complete.  Results written to logins-output.json")

    return 0


if __name__ == '__main__':
    sys.exit(main())
