#!/usr/bin/env python


import argparse
import math
import random
import string
import password
import sys
import json
import role_domains
from datetime import datetime, timedelta

from faker import Faker

from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend


def generate_new_rsa_key():

    key = rsa.generate_private_key(
        backend=crypto_default_backend(),
        public_exponent=65537,
        key_size=2048
    )

    private_key = key.private_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PrivateFormat.PKCS8,
        crypto_serialization.NoEncryption()
    )

    public_key = key.public_key().public_bytes(
        crypto_serialization.Encoding.OpenSSH,
        crypto_serialization.PublicFormat.OpenSSH
    )
    return private_key, public_key


def load_configs(user_roles_filename, enterprise_filename, output_filename):
    built = None
    with open(user_roles_filename) as f:
        # Read the file
        user_roles = json.load(f)

    with open(enterprise_filename) as f:
        # Read the file
        enterprise = json.load(f)

    if output_filename is not None:
        with open(output_filename) as f:
            # Read the file
            output = json.load(f)
            built = output['enterprise_built']
    return user_roles, enterprise, built


def probabilistic_round(x):
    return int(math.floor(x + random.random()))


def simulate_login(term_no, login_start_time, login_length_seconds, user, enterprise, from_node=None):
    if from_node is None:
        from_node = {
            "ip": fake.ipv4(),
            "mac": fake.mac_address()
        }

    shared_nodes = list(filter(lambda node: 'shared' in node['roles'], enterprise['nodes']))
    endpoint_nodes = list(filter(lambda node: 'endpoint' in node['roles'], enterprise['nodes']))
    login_profile = user['login_profile']
    home_node = user['home_node']['name']
    login_end_time = login_start_time + timedelta(seconds=login_length_seconds)

    login = {
        "user": user['user_profile']['username'],
        "login_start": login_start_time,
        "login_end": login_end_time,
        "login_length": login_length_seconds
    }

    nonpersonal_logins = float(login_profile['fraction_of_non_personal_logins_to_shared_machines'])
    to_node = None
    while to_node is None or to_node == from_node:
        if random.random() < float(login_profile['fraction_of_logins_to_personal_machine']):
            # going to home node!
            to_node = {"node": home_node}
        elif len(shared_nodes) > 0 and random.random() < nonpersonal_logins:
            # going to shared node
            to_node = {"node": random.choice(shared_nodes)['name']}
        else:
            # not going to personal nor shared node
            to_node = {"node": random.choice(endpoint_nodes)['name']}

    recursions_no = random.choice(range(int(login_profile['recursive_logins_max'])))

    # not long enough to recurse
    if login_length_seconds == 1:
        recursions_no = 0
    actions = []

    for _ in range(recursions_no):
        recursive_start_time = login_start_time + timedelta(seconds=random.randint(1, login_length_seconds - 1))
        remaining_duration = (login_end_time - recursive_start_time).total_seconds()
        recursive_length_seconds = random.randint(1, remaining_duration)
        recursive_login = simulate_login(None, recursive_start_time,
                                         recursive_length_seconds, user, enterprise, to_node)
        action = {}
        action['type'] = 'recursive_login'
        action['recure'] = recursive_login
        actions.append(action)

    login['from'] = from_node
    login['to'] = to_node
    login['terminal'] = term_no
    if len(actions) > 0:
        login['actions'] = actions

    # to do, handle recursive logins.
    # if random.random() <  login_fraction
    return login


def simulate_hour(term_no, day_to_work, hour_to_work, user, enterprise):

    logins = []

    login_profile = user['login_profile']
    logins_per_hour_min = login_profile['activity_min_logins_per_hour']
    logins_per_hour_max = login_profile['activity_max_logins_per_hour']
    logins_this_hour = probabilistic_round(random.randint(int(logins_per_hour_min), int(logins_per_hour_max)) / 2.0)

    for login_no in range(logins_this_hour):
        start_second = day_to_work + timedelta(hours=hour_to_work) + timedelta(seconds=random.randint(0, 3600))
#        login_length_second = random.randint(1, 120 * 60)
# Use shorter settings for eval
        login_length_second = random.randint(1, 120)
        login_sequence = simulate_login(term_no, start_second, login_length_second, user, enterprise)
        logins.append(login_sequence)

    return logins


def simulate_terminal_day(term_no, day_to_simulate, user, enterprise):
    session = []
    login_profile = user['login_profile']

    day_of_week = day_to_simulate.weekday()
    min_hours_worked = login_profile['activity_daily_min_hours'][day_of_week]
    max_hours_worked = login_profile['activity_daily_max_hours'][day_of_week]
    start_hour_min = login_profile['day_start_hour_min']
    start_hour_max = login_profile['day_start_hour_max']

    hours_worked = random.randint(int(min_hours_worked), int(max_hours_worked))
    start_hour = random.randint(int(start_hour_min), int(start_hour_max))

    for hour_no in range(hours_worked):
        hour_to_work = start_hour + hour_no
        if hour_to_work > 24:
            break
        logins = simulate_hour(term_no, day_to_simulate, hour_to_work, user, enterprise)
        session += logins

    return session


def simulate_user_day(day_to_simulate, user, enterprise):
    terminals = []
    login_profile = user['login_profile']
    parallel_logins = login_profile['terminals_open']

    for term_no in range(1, int(parallel_logins)):
        terminal = simulate_terminal_day(term_no, day_to_simulate, user, enterprise)
        terminals += terminal

    return terminals


def simulate_day(day_to_simulate, users, enterprise):
    day = {}
    for user in users:
        user_day = simulate_user_day(day_to_simulate, user, enterprise)
        username = user['user_profile']['username']
        day[username] = user_day

    return day


def simulate_logins(start_date, days_to_simulate, users, enterprise):
    logins = {}
    logins['days'] = {}

    for i in range(days_to_simulate):
        day_to_simulate = start_date + timedelta(days=i)
        daystr = day_to_simulate.strftime('%A, %m/%d/%Y')
        print("Simulating day " + daystr)
        day = simulate_day(day_to_simulate, users, enterprise)
        logins['days'][daystr] = day

    return logins


def create_users(user_roles, enterprise):
    users = []
    user_nodes = list(filter(lambda node: 'user' in node, enterprise['nodes']))
    print("User nodes are " + str(list(map(lambda node: node['name'], user_nodes))))

    random.choice(string.ascii_letters)

    # uva compute ids are 3 digits + number + 2-3 digits.

    all_roles = user_roles['roles']

    for user_node in user_nodes:
        user_role_name = user_node['user']
        domain_name = user_node['domain']
        role = list(filter(lambda role: user_role_name == role['name'], all_roles))
        if len(role) == 0:
            errstr = ("Found no role specification for node " + user_node['name'])
            raise RuntimeError(errstr)
        if len(role) >= 10:
            errstr = ("Found multiple role specification for node " + user_node['name'])
            raise RuntimeError(errstr)
        role = role[0]
        user_nodes = list(filter(lambda node: 'user' in node, enterprise['nodes']))
        private_key, public_key = generate_new_rsa_key()
        user_profile = fake.profile()
        user_profile['password'] = password.generate_password(7 + int(random.choice(string.digits)))
        user = {
            "user_profile": user_profile,
            "login_profile": role,
            "ssh_key": {"private_key": private_key, "public_key": public_key},
            "home_node": user_node,
            "domain": domain_name
        }
        print("Generated user: " + user['user_profile']['username'] + ", pass: " + user['user_profile']['password'])
        users.append(user)
    return users


def main():
    start_date = datetime.today()
    days_to_simulate = 10

    parser = argparse.ArgumentParser(description="Process JSON files for deployment.")

    # Positional arguments
    parser.add_argument('user_roles', help="Path to user-roles.json")
    parser.add_argument('enterprise', help="Path to enterprise.json")
    parser.add_argument('post_deploy_output', nargs='?', help="Optional path to post-deploy-output.json")

    # Optional argument --seed
    parser.add_argument('--seed', type=int, help="Optional seed value for random operations")

    args = parser.parse_args()

    # Display parsed arguments
    print(f"User Roles JSON: {args.user_roles}")
    print(f"Enterprise JSON: {args.enterprise}")
    if args.post_deploy_output:
        print(f"Post Deploy Output JSON: {args.post_deploy_output}")
    if args.seed is not None:
        print(f"Seed: {args.seed}")

    # setup output
    json_output = {}
    json_output["start_time"] = str(datetime.now())
    json_output["simulation_start"] = str(start_date)
    json_output["simulation_end"] = str(start_date + timedelta(days=days_to_simulate))

    # read config files
    user_roles_filename = args.user_roles
    enterprise_filename = args.enterprise
    output_filename = args.post_deploy_output

    if args.seed is not None:
        seed = args.seed
    else:
        seed = random.randint(1, 10000)

    random.seed(seed)

    user_roles, enterprise, built = load_configs(
        user_roles_filename,
        enterprise_filename,
        output_filename
    )

    # create users
    users = create_users(user_roles, enterprise)
    json_output['users'] = users

    # create login pattern
    logins = simulate_logins(start_date, days_to_simulate, users, enterprise)
    json_output['logins'] = logins
    json_output['seed'] = seed

    # deploy users to domain if given info
    if output_filename is not None:
        print("Deploying users ...")
        deploy_users = role_domains.deploy_users(users, built)
        json_output['deploy_users'] = deploy_users

    json_output["end_time"] = str(datetime.now())

    with open("logins.json", "w") as f:
        json.dump(json_output, f, default=str)

    return


if __name__ == '__main__':
    fake = Faker()
    sys.exit(main())
