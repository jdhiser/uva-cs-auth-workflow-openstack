#!/usr/bin/env python

import log_setup  # noqa: F401  -- patches print() to prefix wall-clock timestamps
import logging
import traceback
import sys
import json
import role_register
import role_domains
import role_human
import role_iis
import role_moodle
import role_fs
import argparse
import os
from datetime import datetime
from joblib import Parallel, delayed

# Force line-buffered stdout/stderr so progress shows up live when piped
# through tee or captured to a log, without needing PYTHONUNBUFFERED=1 or -u.
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

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
    print(f"  [{name}] ipv4 addr (control): {control_ipv4_addr}")
    print(f"  [{name}] ipv4 addr (game): {game_ipv4_addr}")

    if 'password' in details:
        password = details['password']
        print(f"  [{name}] password: {password}")
    else:
        password = None
        print(f"  [{name}] password: No password set")
    return control_ipv4_addr, game_ipv4_addr, password


def register_windows(enterprise, enterprise_built, only):
    ret = {}
    access_list = []
    windows_nodes = list(filter(lambda x: 'windows' in x['roles'], enterprise['nodes']))
    windows_nodes = [x for x in windows_nodes if only is None or x['name'] in only]
    # Pull leader_details if a prior post-deploy already set up the domains;
    # on a fresh first run this will be empty. register_windows_instance uses
    # this to confirm domain membership when local-admin SSH fails.
    domain_leaders = (
        (enterprise_built or {}).get('setup', {}).get('setup_domains', {}).get('domain_leaders', {}) or {}
    )
    for node in windows_nodes:
        name = node['name']
        print("  Registering windows on " + name)
        control_ipv4_addr, game_ipv4_addr, password = extract_creds(enterprise_built, name)
        domain = node.get('domain')
        leader_admin_password = (domain_leaders.get(domain) or {}).get('admin_pass') if domain else None
        access_list.append(
            {
                "name": name,
                "control_addr": control_ipv4_addr,
                "game_addr": game_ipv4_addr,
                "password": str(password),
                "domain": domain,
                "leader_admin_password": leader_admin_password,
            }
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
    leader_details = enterprise_built['setup']['setup_domains']['domain_leaders']
    for node in nodes:
        name = node['name']
        domain = node.get('domain')
        control_ipv4_addr, game_ipv4_addr, password = extract_creds(enterprise_built, name)
        access_list.append({
            "node": node,
            "control_addr": control_ipv4_addr,
            "cloud_config": cloud_config,
            "game_addr": game_ipv4_addr,
            "password": str(password),
            "domain": domain,
            "domain_leader": leader_details[domain]
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


def _deploy_forest_leaders(cloud_config, enterprise, enterprise_built, only, leader_details, ret):
    """Phase 1: deploy AD forest roots (e.g. dc1). Must complete before anything else."""
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


def _deploy_followers(cloud_config, enterprise, enterprise_built, only, leader_details, ret):
    """Add additional domain controllers (dc2, ...). Depends on forest leader."""
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


def _deploy_root_cas(cloud_config, enterprise, enterprise_built, only, leader_details, ret, skip_join=False):
    """Deploy root CAs. Depends on forest leader. Writes root_certification_server/root_ca_name."""
    root_cas = list(filter(lambda x: 'ad-root-certificate-server' in x['roles'], enterprise['nodes']))
    for node in root_cas:
        name = node['name']
        domain = node['domain']
        print(f"Setting up root certification server {name} in domain {domain}")
        control_ipv4_addr, game_ipv4_addr, password = extract_creds(enterprise_built, name)
        if only is None or name in only:
            results = role_domains.setup_root_ca(node, control_ipv4_addr, game_ipv4_addr, password, leader_details[domain], cloud_config, enterprise, enterprise_built, skip_join=skip_join)
        else:
            results = {"msg": "skipping setup of root certification server as requested."}
        leader_details[domain].setdefault("root_certification_server", {"control_addr": [], "game_addr": []})
        leader_details[domain]["root_certification_server"]["control_addr"].append(control_ipv4_addr)
        leader_details[domain]["root_certification_server"]["game_addr"].append(game_ipv4_addr)
        leader_details[domain]["root_ca_name"] = name
        ret[f"setup_root_adcs_{name}"] = results


def _deploy_sub_cas(cloud_config, enterprise, enterprise_built, only, leader_details, ret, skip_join=False):
    """Deploy subordinate CAs and link them to root CAs. Depends on root_ca for the domain."""
    sub_cas = list(filter(lambda x: 'ad-subordinate-certificate-server' in x['roles'], enterprise['nodes']))
    for node in sub_cas:
        name = node['name']
        domain = node['domain']
        print(f"Setting up subordinate certification server {name} in domain {domain}")
        control_ipv4_addr, game_ipv4_addr, password = extract_creds(enterprise_built, name)
        if only is None or name in only or leader_details[domain]["root_ca_name"] in only:
            results = role_domains.setup_subordinate_ca(node, control_ipv4_addr, game_ipv4_addr, password, leader_details[domain], cloud_config, enterprise, enterprise_built, skip_join=skip_join)
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
        leader_details[domain]["subordinate_certification_server"]["node"] = node
        leader_details[domain]["subordinate_certification_server"]["control_addr"].append(control_ipv4_addr)
        leader_details[domain]["subordinate_certification_server"]["game_addr"].append(game_ipv4_addr)
        ret[f"setup_subordinate_adcs_{name}"] = results


def _deploy_iis(cloud_config, enterprise, enterprise_built, only, leader_details, ret, skip_join=False):
    """Deploy IIS servers. Joins the domain and requests a cert from the SubCA, so depends on SubCA."""
    iis_servers = list(filter(lambda x: 'iis' in x['roles'], enterprise['nodes']))
    for node in iis_servers:
        name = node['name']
        domain = node['domain']
        print(f"Setting up IIS server on {name} in domain {domain}")
        control_ipv4_addr, game_ipv4_addr, password = extract_creds(enterprise_built, name)
        subca_node = leader_details[domain]["subordinate_certification_server"]["node"]
        if only is None or name in only:
            results = role_iis.setup_iis(node, control_ipv4_addr, game_ipv4_addr, password, subca_node, leader_details[domain], cloud_config, enterprise, enterprise_built, skip_join=skip_join)
        else:
            results = {"msg": "skipping setup of IIS server as requested."}
        ret[f"setup_iis_{name}"] = results


def _parallel_join_ca_iis(cloud_config, enterprise, enterprise_built, only, leader_details, ret):
    """
    Phase 2.B.1: pre-join rootca / subca / iis to the domain in parallel.

    Each of these nodes only needs dc1 (the forest leader) to be up before it
    can join. After parallel joins complete, the caller runs the dependent
    install steps sequentially with skip_join=True.

    Save: each join_domain_windows is ~5-7 min wall-clock (mostly Add-Computer
    retry loop + reboot wait). Running three in parallel cuts the chain's
    join cost from ~18 min to ~6 min.
    """
    target_roles = ['ad-root-certificate-server', 'ad-subordinate-certificate-server', 'iis']
    nodes_to_join = []
    for node in enterprise['nodes']:
        if any(r in node['roles'] for r in target_roles):
            nodes_to_join.append(node)
    nodes_to_join = [n for n in nodes_to_join if only is None or n['name'] in only]

    if not nodes_to_join:
        return

    def _join_one(node):
        name = node['name']
        domain = node['domain']
        enterprise_name = cloud_config['enterprise_url']
        fqdn_domain_name = domain + '.' + enterprise_name
        leader_admin_password = leader_details[domain]['admin_pass']
        game_leader_addrs = leader_details[domain]['game_addr']
        control_ipv4_addr, game_ipv4_addr, password = extract_creds(enterprise_built, name)
        domain_ips = str(game_leader_addrs).replace("[", "").replace("]", "").replace("'", "\"")
        print(f"  [phase-2-join] Joining {name} to domain {domain} (parallel)")
        return name, role_domains.join_domain_windows(
            name, leader_admin_password, control_ipv4_addr, game_ipv4_addr,
            domain_ips, fqdn_domain_name, domain, password,
        )

    results = Parallel(n_jobs=len(nodes_to_join), backend="threading")(
        delayed(_join_one)(node) for node in nodes_to_join
    )
    for name, result in results:
        ret[f"phase2_join_{name}"] = result


def deploy_domain_controllers(cloud_config, enterprise, enterprise_built, only):
    """
    Sets up Active Directory forests, domain controllers, and certificate servers (root and subordinate).
    Also links subordinate certificate authorities to their respective root CAs.
    Also sets up an IIS server.

    Dependency graph (per domain):

        forest leader (dc1)   [phase 1]
            ├──> follower DC (dc2)                          [phase 2 branch A]
            └──> root CA  ──> subordinate CA  ──> IIS       [phase 2 branch B]

    Phase 2's two branches run concurrently. dc2 typically takes ~15-20 min
    (Install-ADDSDomainController + reboot + AD startup); the CA→IIS chain
    takes ~30-40 min. Running them in parallel saves the shorter branch's
    duration — roughly 15-20 min off pd1's critical path.

    Thread safety: branches mutate `leader_details[domain]` and `ret` on
    non-overlapping keys (followers touches control_addr/game_addr lists +
    additional_dc_setup_*; the CA/IIS chain touches
    root_certification_server/subordinate_certification_server/root_ca_name +
    setup_root_adcs_*/setup_subordinate_adcs_*/setup_iis_*). dict-key
    operations under the GIL are atomic enough here. We also use
    backend="threading" so the worker processes share these dicts directly.
    """

    os.makedirs("tmp", exist_ok=True)

    ret = {}
    leader_details = {}

    _deploy_forest_leaders(cloud_config, enterprise, enterprise_built, only, leader_details, ret)

    def branch_followers():
        _deploy_followers(cloud_config, enterprise, enterprise_built, only, leader_details, ret)

    def branch_ca_iis():
        # 2.B.1: parallel domain-join for rootca/subca/iis (only depends on dc1).
        _parallel_join_ca_iis(cloud_config, enterprise, enterprise_built, only, leader_details, ret)
        # 2.B.2: install services in dependency order (rootca -> subca+link -> iis),
        # skipping the now-already-done join_domain_windows step inside each.
        _deploy_root_cas(cloud_config, enterprise, enterprise_built, only, leader_details, ret, skip_join=True)
        _deploy_sub_cas(cloud_config, enterprise, enterprise_built, only, leader_details, ret, skip_join=True)
        _deploy_iis(cloud_config, enterprise, enterprise_built, only, leader_details, ret, skip_join=True)

    if use_parallel:
        Parallel(n_jobs=2, backend="threading")([
            delayed(branch_followers)(),
            delayed(branch_ca_iis)(),
        ])
    else:
        branch_followers()
        branch_ca_iis()

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


def build_workflows_zip():
    """
    Rebuild Downloads/workflows.zip from the pinned `human` submodule on
    every post-deploy run. role_human's install_human_{linux,windows}
    upload this zip to each endpoint; if it goes stale (e.g. someone
    edited human/pyhuman/* but didn't repack), every node ends up with
    out-of-date workflow code. Doing the repack here makes the submodule
    the single source of truth -- no separate update-zip.sh step to
    remember.

    The deployed zip's layout is flat (app/..., data/..., human.py,
    requirements.txt at the root); the submodule wraps the same tree in
    a pyhuman/ directory. Strip that prefix when zipping.
    """
    workflow_root = os.path.dirname(os.path.abspath(__file__))
    pyhuman_dir = os.path.join(workflow_root, 'human', 'pyhuman')
    zip_path = os.path.join(workflow_root, 'Downloads', 'workflows.zip')
    if not os.path.isdir(pyhuman_dir):
        raise RuntimeError(
            f"Submodule directory not found: {pyhuman_dir}. "
            f"Did you forget `git submodule update --init --recursive`?"
        )
    os.makedirs(os.path.dirname(zip_path), exist_ok=True)
    # Build a deterministic flat zip by enumerating the dirs we ship.
    # Match the directory list of the historical workflows.zip:
    # app/workflows, app/utility, data, human.py, requirements.txt.
    import zipfile
    members = []
    for sub in ['app/workflows', 'app/utility', 'data']:
        full = os.path.join(pyhuman_dir, sub)
        if not os.path.isdir(full):
            continue
        for root, _, files in os.walk(full):
            for f in files:
                if f.startswith('.') or f.startswith('_'):
                    continue
                abs_path = os.path.join(root, f)
                rel = os.path.relpath(abs_path, pyhuman_dir)
                members.append((abs_path, rel))
    for f in ['human.py', 'requirements.txt']:
        abs_path = os.path.join(pyhuman_dir, f)
        if os.path.isfile(abs_path):
            members.append((abs_path, f))
    if not members:
        raise RuntimeError(f"No files found to zip in {pyhuman_dir}")
    # Atomic rewrite so a partial zip never leaks to install_human.
    tmp_zip = zip_path + ".tmp"
    with zipfile.ZipFile(tmp_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
        for abs_path, rel in sorted(members, key=lambda p: p[1]):
            zf.write(abs_path, arcname=rel)
    os.replace(tmp_zip, zip_path)
    print(f"Built {zip_path} from {pyhuman_dir} ({len(members)} files)")


def setup_enterprise(cloud_config, to_build, built, only):
    built['setup'] = {}
    # Always (re)build the workflows.zip shipped to endpoints from the
    # `human` submodule -- single source of truth, no chance of a stale
    # zip from an older edit slipping into the deploy.
    build_workflows_zip()
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
    rc = 0
    try:
        setup_output_filename = args.deploy_output
        setup_output = load_json(setup_output_filename)

        # If a previous post-deploy run left partial state behind for the
        # SAME deploy (matching OpenStack node IDs), merge its
        # enterprise_built['setup'] so re-run idempotency probes can see
        # leader_admin_password etc. We compare node IDs (not just mtime) so
        # a stale post-deploy-output.json from a prior cleanup+deploy cycle
        # is detected and ignored — the new deploy-output.json has fresh
        # OpenStack server IDs that won't match.
        try:
            if os.path.exists("post-deploy-output.json"):
                prior = load_json("post-deploy-output.json")
                cur_ids = sorted(
                    n.get('id') for n in setup_output.get('enterprise_built', {}).get('nodes', [])
                    if n.get('id')
                )
                prior_ids = sorted(
                    n.get('id') for n in prior.get('enterprise_built', {}).get('nodes', [])
                    if n.get('id')
                )
                if cur_ids and cur_ids == prior_ids:
                    prior_setup = prior.get('enterprise_built', {}).get('setup')
                    if prior_setup:
                        setup_output.setdefault('enterprise_built', {}).setdefault('setup', {})
                        setup_output['enterprise_built']['setup'].update(prior_setup)
                        print("[INFO] Merged prior setup state from post-deploy-output.json (matching node IDs) for idempotency.")
                elif prior_ids:
                    print("[INFO] Ignoring post-deploy-output.json (node IDs differ from current deploy; likely stale from prior cleanup).")
        except Exception as e:
            print(f"[WARN] Could not merge prior post-deploy-output.json: {e}")

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
        sys.stdout.flush()
        sys.stderr.flush()
        traceback.print_exc()
        print("Exception occured while setting up enterprise.  Dumping partial results to post-deploy-output.json so a re-run can pick up where we left off.")
        sys.stdout.flush()
        sys.stderr.flush()
        # Best-effort: snapshot enterprise_built / enterprise so a re-run gets
        # leader_admin_password etc. for idempotency probes.
        try:
            json_output['enterprise'] = enterprise  # noqa: F821 — set above unless load_json failed
            json_output['enterprise_built'] = enterprise_built  # noqa: F821
        except NameError:
            pass
        json_output["setup-end_time"] = str(datetime.now())
        json_output["setup-failed"] = True
        rc = 1

    # Always write post-deploy-output.json so a re-run can see the partial
    # state (notably: setup_domains.domain_leaders with admin_pass), which the
    # idempotency probes rely on.
    try:
        with open("post-deploy-output.json", "w") as f:
            json.dump(json_output, f)
    except Exception as e:
        print(f"[WARN] Could not write post-deploy-output.json: {e}")

    return rc


if __name__ == '__main__':
    sys.exit(main())
