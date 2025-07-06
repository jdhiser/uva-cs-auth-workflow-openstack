#!/usr/bin/env python

import logging
import traceback
import sys
import json
import role_register
import role_domains
import role_human
import role_moodle
import role_fs
import argparse
import os
from datetime import datetime
from joblib import Parallel, delayed

use_parallel = True
verbose = not use_parallel


def load_json(filename):
    with open(filename) as f:
        # Read the file
        file = json.load(f)

    return file


def extract_creds(enterprise_built, name):
    details = next(filter(lambda x: name == x['name'], enterprise_built['deployed']['nodes']))
    addresses = details['addresses']
    control_ipv4_addr = addresses[0]['addr']
    game_ipv4_addr = addresses[-1]['addr']
    print("  ipv4 addr (control): " + str(control_ipv4_addr))
    print("  ipv4 addr (game): " + str(game_ipv4_addr))

    if 'password' in details:
        password = details['password']
        print("  password: " + str(password))
    else:
        password = None
        print("  password: No password set")
    return control_ipv4_addr, game_ipv4_addr, password


def register_windows(enterprise, enterprise_built, only):
    ret = {}
    access_list = []
    windows_nodes = list(filter(lambda x: 'windows' in x['roles'], enterprise['nodes']))
    windows_nodes = [x for x in windows_nodes if only is None or x['name'] in only]
    for node in windows_nodes:
        name = node['name']
        print("  Registering windows on " + name)
        control_ipv4_addr, game_ipv4_addr, password = extract_creds(enterprise_built, name)
        access_list.append(
            {"name": name, "control_addr": control_ipv4_addr, "game_addr": game_ipv4_addr, "password": str(password)}
        )

    if use_parallel:
        # parallel
        results = Parallel(n_jobs=10, backend="threading")(delayed(role_register.register_windows_instance)(i) for i in access_list)
        ret['register_windows'] = results
    else:
        # sequential
        results = []
        for access in access_list:
            results.append(role_register.register_windows_instance(access))

    return ret


def join_domains(cloud_config, enterprise, enterprise_built, only):
    ret = {}
    access_list = []
    nodes = list(filter(lambda x: 'endpoint' in x['roles'], enterprise['nodes']))
    nodes = [x for x in nodes if only is None or x['name'] in only]
    leader_details = enterprise_built['setup']['setup_domains']['domain_leaders']
    for node in nodes:
        name = node['name']
        domain = node['domain']
        if domain is None:
            print("No domain (" + str(domain) + ") to join for " + name)
            continue
        print("Joining domain on " + name)
        control_ipv4_addr, game_ipv4_addr, password = extract_creds(enterprise_built, name)
        access_list.append({
            "cloud_config": cloud_config,
            "node": node,
            "domain_leader": leader_details[domain],
            "control_addr": control_ipv4_addr,
            "game_addr": game_ipv4_addr,
            "password": str(password),
            'domain': domain
        })

    if use_parallel:
        # parallel
        results = Parallel(n_jobs=10, backend="threading")(delayed(role_domains.join_domain)(access) for access in access_list)
    else:
        # sequential
        results = []
        for access in access_list:
            results.append(role_domains.join_domain(access))

    ret['join_domains'] = results

    return ret


def deploy_human(cloud_config, enterprise, enterprise_built, only):
    ret = {}
    access_list = []
    nodes = enterprise['nodes']
    nodes = [x for x in nodes if only is None or x['name'] in only]
    results = []
    for node in nodes:
        name = node['name']
        control_ipv4_addr, game_ipv4_addr, password = extract_creds(enterprise_built, name)
        access_list.append({
            "node": node,
            "control_addr": control_ipv4_addr,
            "cloud_config": cloud_config,
            "game_addr": game_ipv4_addr,
            "password": str(password)
        })

    if use_parallel:
        # parallel
        results = Parallel(n_jobs=10, backend="threading")(delayed(role_human.deploy_human)(access) for access in access_list)
    else:
        # sequential
        for access in access_list:
            print("Setting up human plugin on " + access['node']['name'])
            results.append(role_human.deploy_human(access))

    ret['setup_human'] = results

    return ret


def setup_moodle_idps(cloud_config, enterprise, enterprise_built, only):
    ret = {}
    access_list = []
    idps = list(filter(lambda x: 'idp' in x['roles'], enterprise['nodes']))
    idps = [x for x in idps if only is None or x['name'] in only]
    leader_details = enterprise_built['setup']['setup_domains']['domain_leaders']
    for node in idps:
        name = node['name']
        domain = node['domain']
        if domain is None:
            print("No domain for IDP {} to configure against".format(name))
            continue
        print("Initial setup of IDP against domain on " + name)
        control_ipv4_addr, game_ipv4_addr, password = extract_creds(enterprise_built, name)
        access_list.append({
            "node": node,
            "cloud_config": cloud_config,
            "domain_leader": leader_details[domain],
            "control_addr": control_ipv4_addr,
            "game_addr": game_ipv4_addr,
            "password": str(password)
        })

    results = []
    if use_parallel:
        # parallel
        results = Parallel(n_jobs=10, backend="threading")(delayed(role_moodle.setup_moodle_idp)(access) for access in access_list)
    else:
        # sequential
        for access in access_list:
            print("Setting up IDP on " + access['node']['name'])
            results.append(role_moodle.setup_moodle_idp(access))

    ret['setup_moodle_idp'] = results

    return ret


def setup_moodle_sps(cloud_config, enterprise, enterprise_built, only):
    ret = {}
    access_list = []
    sps = list(filter(lambda x: 'sp' in x['roles'], enterprise['nodes']))
    sps = [x for x in sps if only is None or x['name'] in only]
    leader_details = enterprise_built['setup']['setup_domains']['domain_leaders']
    for node in sps:
        name = node['name']
        domain = node['domain']
        if domain is None:
            print("No domain for SP {} to configure against".format(name))
            continue
        print("Configuring SP against domain on " + name)
        control_ipv4_addr, game_ipv4_addr, password = extract_creds(enterprise_built, name)
        access_list.append({
            "node": node,
            "domain_leader": leader_details[domain],
            "cloud_config": cloud_config,
            "control_addr": control_ipv4_addr,
            "game_addr": game_ipv4_addr,
            "password": str(password)
        })

    results = []
    if use_parallel:
        # parallel
        results = Parallel(n_jobs=10, backend="threading")(delayed(role_moodle.setup_moodle_sp)(access) for access in access_list)
    else:
        # sequential
        for access in access_list:
            print("Setting up SP on " + access['node']['name'])
            results.append(role_moodle.setup_moodle_sp(access))

    ret['setup_moodle_sp'] = results

    return ret


def setup_moodle_idps_part2(cloud_config, enterprise, enterprise_built, only):
    ret = {}
    access_list = []
    idps = list(filter(lambda x: 'idp' in x['roles'], enterprise['nodes']))
    idps = [x for x in idps if only is None or x['name'] in only]
    leader_details = enterprise_built['setup']['setup_domains']['domain_leaders']
    for node in idps:
        name = node['name']
        domain = node['domain']
        if domain is None:
            print("No domain for IDP {} to configure against".format(name))
            continue
        print("Final setup of IDP against domain on " + name)
        control_ipv4_addr, game_ipv4_addr, password = extract_creds(enterprise_built, name)
        access_list.append({
            "node": node,
            "cloud_config": cloud_config,
            "domain_leader": leader_details[domain],
            "control_addr": control_ipv4_addr,
            "game_addr": game_ipv4_addr,
            "password": str(password)
        })

    results = []
    if use_parallel:
        # parallel
        results = Parallel(n_jobs=10, backend="threading")(delayed(role_moodle.setup_moodle_idp_part2)(access) for access in access_list)
    else:
        # sequential
        for access in access_list:
            print("Setting up IDP, part2, on " + access['node']['name'])
            results.append(role_moodle.setup_moodle_idp_part2(access))

    ret['setup_moodle_idp'] = results

    return ret


def deploy_domain_controllers(cloud_config, enterprise, enterprise_built, only):
    """
    Sets up Active Directory forests, domain controllers, and certificate servers (root and subordinate).
    Also links subordinate certificate authorities to their respective root CAs.
    """

    os.makedirs("tmp", exist_ok=True)

    ret = {}
    leader_details = {}

    # Step 1: Deploy AD forests (root DCs)
    forest_leaders = list(filter(lambda x: 'domain_controller_leader' in x['roles'], enterprise['nodes']))
    for leader in forest_leaders:
        name = leader['name']
        domain = leader['domain']
        print(f"Setting up domain controller with new forest on {name} for domain {domain}")
        control_ipv4_addr, game_ipv4_addr, password = extract_creds(enterprise_built, name)
        if only is None or name in only:
            results = role_domains.deploy_forest(cloud_config, name, control_ipv4_addr, game_ipv4_addr, password, domain)
        else:
            results = {"msg": "skipping setup of domain controller leader as requested"}
        leader_details[domain] = {
            "name": name,
            "control_addr": [control_ipv4_addr],
            "game_addr": [game_ipv4_addr],
            "admin_pass": password
        }
        ret[f"forest_setup_{name}"] = results

    # Step 2: Add additional domain controllers (replicas)
    followers = list(filter(lambda x: 'domain_controller' in x['roles'], enterprise['nodes']))
    for follower in followers:
        name = follower['name']
        domain = follower['domain']
        print(f"Setting up domain controller on {name} for domain {domain}")
        control_ipv4_addr, game_ipv4_addr, password = extract_creds(enterprise_built, name)
        if only is None or name in only:
            results = role_domains.add_domain_controller(
                cloud_config, leader_details[domain], name, control_ipv4_addr, game_ipv4_addr, password, domain
            )
        else:
            results = {"msg": "skipping setup of domain controller follower as requested."}
        leader_details[domain]['control_addr'].append(control_ipv4_addr)
        leader_details[domain]['game_addr'].append(game_ipv4_addr)
        ret[f"additional_dc_setup_{name}"] = results

    # Step 3: Deploy root CAs
    root_cas = list(filter(lambda x: 'ad-root-certificate-server' in x['roles'], enterprise['nodes']))
    for node in root_cas:
        name = node['name']
        domain = node['domain']
        print(f"Setting up root certification server {name} in domain {domain}")
        control_ipv4_addr, game_ipv4_addr, password = extract_creds(enterprise_built, name)
        if only is None or name in only:
            results = role_domains.setup_root_ca(node, control_ipv4_addr, game_ipv4_addr, password, leader_details[domain], cloud_config, enterprise, enterprise_built)
        else:
            results = {"msg": "skipping setup of root certification server as requested."}
        leader_details[domain].setdefault("root_certification_server", {"control_addr": [], "game_addr": []})
        leader_details[domain]["root_certification_server"]["control_addr"].append(control_ipv4_addr)
        leader_details[domain]["root_certification_server"]["game_addr"].append(game_ipv4_addr)
        leader_details[domain]["root_ca_name"] = name
        ret[f"setup_root_adcs_{name}"] = results

    # Step 4: Deploy subordinate CAs
    sub_cas = list(filter(lambda x: 'ad-subordinate-certificate-server' in x['roles'], enterprise['nodes']))
    for node in sub_cas:
        name = node['name']
        domain = node['domain']
        print(f"Setting up subordinate certification server {name} in domain {domain}")
        control_ipv4_addr, game_ipv4_addr, password = extract_creds(enterprise_built, name)
        if only is None or name in only or leader_details[domain]["root_ca_name"] in only:
            results = role_domains.setup_subordinate_ca(node, control_ipv4_addr, game_ipv4_addr, password, leader_details[domain], cloud_config, enterprise, enterprise_built)
            sub_info = {
                "node": node,
                "control_ip": control_ipv4_addr,
                "game_ip": game_ipv4_addr,
                "password": password,
                "domain": domain,
                "enterprise_url": cloud_config['enterprise_url']
            }
            root_info = {
                'control_addr': leader_details[domain]["root_certification_server"]["control_addr"][0],
                'admin_pass': leader_details[domain]['admin_pass']
            }

            print(f"Linking subordinate CA {node['name']} to root CA in domain {domain}")
            result = role_domains.link_subordinate_to_root(root_info, sub_info)
            ret[f"link_subordinate_{node['name']}"] = result
        else:
            results = {"msg": "skipping setup of subordinate certification server as requested."}
        leader_details[domain].setdefault("subordinate_certification_server", {"control_addr": [], "game_addr": []})
        leader_details[domain]["subordinate_certification_server"]["control_addr"].append(control_ipv4_addr)
        leader_details[domain]["subordinate_certification_server"]["game_addr"].append(game_ipv4_addr)
        ret[f"setup_subordinate_adcs_{name}"] = results

    ret["domain_leaders"] = leader_details
    return ret


def setup_fileservers(cloud_config, enterprise, enterprise_built, only):
    ret = {}
    access_list = []
    nodes = list(filter(lambda x: 'fileserver' in x['roles'], enterprise['nodes']))
    nodes = [x for x in nodes if only is None or x['name'] in only]
    for node in nodes:
        name = node['name']
        domain = node['domain']
        enterprise_built['setup']['setup_domains']['domain_leaders'][domain]['fileserver'] = node
        leader_details = enterprise_built['setup']['setup_domains']['domain_leaders']
        if domain is None:
            print("No domain (" + str(domain) + ") to join for " + name)
            continue
        print("Joining domain on " + name)
        control_ipv4_addr, game_ipv4_addr, password = extract_creds(enterprise_built, name)
        access_list.append({
            "cloud_config": cloud_config,
            "node": node,
            "domain_leader": leader_details[domain],
            "control_addr": control_ipv4_addr,
            "game_addr": game_ipv4_addr,
            "password": str(password),
            'domain': domain
        })

    if use_parallel:
        # parallel
        results = Parallel(n_jobs=10, backend="threading")(delayed(role_fs.setup_fileserver)(access) for access in access_list)
    else:
        # sequential
        results = []
        for access in access_list:
            results.append(role_fs.setup_fileserver(access))

    ret['join_domains'] = results

    return ret


def setup_enterprise(cloud_config, to_build, built, only):
    built['setup'] = {}
    built['setup']['windows_register'] = register_windows(to_build, built, only)
    built['setup']['setup_domains'] = deploy_domain_controllers(cloud_config, to_build, built, only)
    built['setup']['setup_fileservers'] = setup_fileservers(cloud_config, to_build, built, only)
    built['setup']['join_domains'] = join_domains(cloud_config, to_build, built, only)
    built['setup']['deploy_human'] = deploy_human(cloud_config, to_build, built, only)
    built['setup']['setup_moodle_idps'] = setup_moodle_idps(cloud_config, to_build, built, only)
    built['setup']['setup_moodle_sps'] = setup_moodle_sps(cloud_config, to_build, built, only)
    built['setup']['setup_moodle_idps_part2'] = setup_moodle_idps_part2(cloud_config, to_build, built, only)


def main():

    # Create an ArgumentParser object
    parser = argparse.ArgumentParser(description="A script to configure deployed machines.")
    parser.add_argument("deploy_output", help="Path to the deploy-output.py file")
    parser.add_argument("-o", "--only", action="append",
                        help="Specify that not all nodes should be configured, only specified node (can be repeated).")

    # Suppress noisy socket messages
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)

    args = parser.parse_args()

    json_output = {}
    try:
        setup_output_filename = args.deploy_output
        setup_output = load_json(setup_output_filename)

        json_output = setup_output
        json_output["setup-start_time"] = str(datetime.now())

        enterprise_built = setup_output['enterprise_built']
        enterprise = setup_output['enterprise_to_build']
        cloud_config = setup_output['backend_config']

        print("Setting up nodes.")

        setup_enterprise(cloud_config, enterprise, enterprise_built, args.only)
        print("Setting up nodes, completed.")

        json_output['enterprise'] = enterprise
        json_output['enterprise_built'] = enterprise_built
        json_output["setup-end_time"] = str(datetime.now())

        print("Enterprise setup.  Writing output to post-deploy-output.json.  Run simulate-logins.py next.")

    except Exception as _:   # noqa: F841
        traceback.print_exc()
        print("Exception occured while setting up enterprise.  Dumping results to post-deploy-output.json anyhow.")
        return 1

    with open("post-deploy-output.json", "w") as f:
        json.dump(json_output, f)

    return 0


if __name__ == '__main__':
    sys.exit(main())
