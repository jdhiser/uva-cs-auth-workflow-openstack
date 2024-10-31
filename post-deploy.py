#!/usr/bin/env python


import traceback
import sys
import json
import role_register
import role_domains
import role_human
import role_moodle
from datetime import datetime
from joblib import Parallel, delayed

use_parallel=False
verbose=not use_parallel



def load_json(filename):
    with open(filename) as f:
        # Read the file
        file = json.load(f)

    return file


def extract_creds(enterprise_built,name):
    details = next(filter( lambda x: name == x['name'], enterprise_built['deployed']['nodes']))
    addresses = details['addresses']
    control_ipv4_addr = addresses[0]['addr']
    game_ipv4_addr = addresses[1]['addr']
    print("  ipv4 addr (control): " + str(control_ipv4_addr))
    print("  ipv4 addr (game): " + str(game_ipv4_addr))

    if 'password' in details:
        password = details['password']
        print("  password: " + str(password))
    else:
        password = None
        print("  password: No password set")
    return control_ipv4_addr,game_ipv4_addr,password

def register_windows(cloud_config,enterprise,enterprise_built):
    ret={}
    access_list=[]
    windows_nodes = list(filter(lambda x: 'windows' in x['roles'], enterprise['nodes']))
    for node in windows_nodes:
        name = node['name']
        print("  Registering windows on " + name)
        control_ipv4_addr,game_ipv4_addr,password = extract_creds(enterprise_built,name)
        access_list.append({"name": name, "control_addr": control_ipv4_addr, "game_addr": game_ipv4_addr, "password": str(password)})

    if use_parallel:
        # parallel
        results = Parallel(n_jobs=10)(delayed(role_register.register_windows_instance)(i) for i in access_list)
        ret['register_windows']=results
    else:
        # sequential
        results = []
        for access in access_list:
            results.append(role_register.register_windows_instance(access))

        
    return ret

def join_domains(cloud_config,enterprise,enterprise_built):
    ret={}
    access_list=[]
    nodes = list(filter(lambda x: 'endpoint' in x['roles'], enterprise['nodes']))
    leader_details=enterprise_built['setup']['setup_domains']['domain_leaders']
    for node in nodes:
        name = node['name']
        domain = node['domain']
        if domain == None: 
            print("No domain (" + str(domain) + ") to join for " + name)
            continue
        print("Joining domain on " + name)
        control_ipv4_addr,game_ipv4_addr,password = extract_creds(enterprise_built,name)
        access_list.append(
                {
                    "cloud_config": cloud_config, 
                    "node": node, 
                    "domain_leader": leader_details[domain], 
                    "control_addr": control_ipv4_addr, 
                    "game_addr": game_ipv4_addr, 
                    "password": str(password), 
                    'domain': domain })


    if use_parallel:
        # parallel
        results = Parallel(n_jobs=10)(delayed(role_domains.join_domain)(access) for access in access_list)
    else:
        # sequential
        results = []
        for access in access_list:
            results.append(role_domains.join_domain(access))


    ret['join_domains']=results
        
    return ret

def deploy_human(cloud_config,enterprise,enterprise_built):
    ret={}
    access_list=[]
    nodes = enterprise['nodes']
    results = []
    for node in nodes:
        name = node['name']
        control_ipv4_addr,game_ipv4_addr,password = extract_creds(enterprise_built,name)
        access_list.append({
            "node": node, 
            "control_addr": control_ipv4_addr, 
            "cloud_config": cloud_config, 
            "game_addr": game_ipv4_addr, 
            "password": str(password) 
        })

    if use_parallel:
	    # parallel
	    results = Parallel(n_jobs=10)(delayed(role_human.deploy_human)(access) for access in access_list)
    else:
        # sequential
        for access in access_list:
            print("Setting up human plugin on " + access['node']['name'])
            results.append(role_human.deploy_human(access))

    ret['setup_human']=results
        
    return ret


def setup_moodle_idps(cloud_config,enterprise,enterprise_built):
    ret={}
    access_list=[]
    idps = list(filter(lambda x: 'idp' in x['roles'], enterprise['nodes']))
    leader_details=enterprise_built['setup']['setup_domains']['domain_leaders']
    for node in idps:
        name = node['name']
        domain = node['domain']
        if domain == None: 
            print("No domain for IDP {} to configure against".format(name))
            continue
        print("Configuring IDP against domain on " + name)
        control_ipv4_addr,game_ipv4_addr,password = extract_creds(enterprise_built,name)
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
        results = Parallel(n_jobs=10)(delayed(role_moodle.setup_moodle_idp)(access) for access in access_list)
    else:
        # sequential
        for access in access_list:
            print("Setting up IDP on " + access['node']['name'])
            results.append(role_moodle.setup_moodle_idp(access))

    ret['setup_moodle_idp']=results
        
    return ret

def setup_moodle_sps(cloud_config,enterprise,enterprise_built):
    ret={}
    access_list=[]
    sps = list(filter(lambda x: 'sp' in x['roles'], enterprise['nodes']))
    leader_details=enterprise_built['setup']['setup_domains']['domain_leaders']
    for node in sps:
        name = node['name']
        domain = node['domain']
        if domain == None: 
            print("No domain for SP {} to configure against".format(name))
            continue
        print("Configuring SP against domain on " + name)
        control_ipv4_addr,game_ipv4_addr,password = extract_creds(enterprise_built,name)
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
        results = Parallel(n_jobs=10)(delayed(role_moodle.setup_moodle_sp)(access) for access in access_list)
    else:
        # sequential
        for access in access_list:
            print("Setting up SP on " + access['node']['name'])
            results.append(role_moodle.setup_moodle_sp(access))

    ret['setup_moodle_sp']=results
        
    return ret

def setup_moodle_idps_part2(cloud_config,enterprise,enterprise_built):
    ret={}
    access_list=[]
    idps = list(filter(lambda x: 'idp' in x['roles'], enterprise['nodes']))
    leader_details=enterprise_built['setup']['setup_domains']['domain_leaders']
    for node in idps:
        name = node['name']
        domain = node['domain']
        if domain == None: 
            print("No domain for IDP {} to configure against".format(name))
            continue
        print("Configuring IDP against domain on " + name)
        control_ipv4_addr,game_ipv4_addr,password = extract_creds(enterprise_built,name)
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
        results = Parallel(n_jobs=10)(delayed(role_moodle.setup_moodle_idp_part2)(access) for access in access_list)
    else:
        # sequential
        for access in access_list:
            print("Setting up IDP, part2, on " + access['node']['name'])
            results.append(role_moodle.setup_moodle_idp_part2(access))

    ret['setup_moodle_idp']=results
        
    return ret



def setup_enterprise(cloud_config,to_build,built):
    built['setup']={}
    built['setup']['windows_register'] = register_windows(cloud_config,to_build,built)
    built['setup']['setup_domains'] = deploy_domain_controllers(cloud_config,to_build,built)
    built['setup']['join_domains'] = join_domains(cloud_config,to_build,built)
    built['setup']['deploy_human'] = deploy_human(cloud_config,to_build,built)
    built['setup']['setup_moodle_idps'] = setup_moodle_idps(cloud_config,to_build,built)
    built['setup']['setup_moodle_sps'] = setup_moodle_sps(cloud_config,to_build,built)
    built['setup']['setup_moodle_idps_part2'] = setup_moodle_idps_part2(cloud_config,to_build,built)



def deploy_domain_controllers(cloud_config,enterprise,enterprise_built):
    ret={}
    leaders = list(filter(lambda x: 'domain_controller_leader' in x['roles'], enterprise['nodes']))
    leader_details={}
    for leader in leaders:
        name = leader['name']
        domain = leader['domain']
        print("Setting up domain controller with new forest on " + name + " for domain " + domain)
        control_ipv4_addr,game_ipv4_addr,password = extract_creds( enterprise_built,name)
        #access_list.append({"name": name})
        #access_list.append({"name": name, "addr": ipv4_addr})
        results=role_domains.deploy_forest(cloud_config,name,control_ipv4_addr,game_ipv4_addr,password, domain)
        leader_details[domain]={"name": str(name), "control_addr": [control_ipv4_addr], "game_addr": [game_ipv4_addr], "admin_pass": str(password)}
        ret["forest_setup_"+name]=results

    followers = list(filter(lambda x: 'domain_controller' in x['roles'], enterprise['nodes']))
    for follower in followers:
        domain = follower['domain']
        name = follower['name']
        print("Setting up domain controller on " + name + ' for domain ' + domain)
        control_ipv4_addr,game_ipv4_addr,password = extract_creds( enterprise_built,name)
        results=role_domains.add_domain_controller(cloud_config,leader_details[domain], name,control_ipv4_addr,game_ipv4_addr,password, domain)
        leader_details[domain]['control_addr'].append(control_ipv4_addr)
        leader_details[domain]['game_addr'].append(game_ipv4_addr)
        ret["additional_dc_setup_"+name]=results
        
    ret["domain_leaders"] = leader_details    
    return ret

def main():

    if len(sys.argv) != 2:
        print("Usage:  " + sys.argv[0] + " deploy-output.json")
        sys.exit(1)

    json_output = {}
    try:
        setup_output_filename = sys.argv[1]
        setup_output = load_json(setup_output_filename)

        json_output = setup_output
        json_output["setup-start_time"] = str(datetime.now())

        enterprise_built = setup_output['enterprise_built']
        enterprise = setup_output['enterprise_to_build']
        cloud_config = setup_output['backend_config']

        print("Setting up nodes.")

        setup_enterprise(cloud_config,enterprise,enterprise_built)
        print("Setting up nodes, completed.")

        json_output['enterprise'] = enterprise
        json_output['enterprise_built'] = enterprise_built
        json_output["setup-end_time"] = str(datetime.now())

        print("Enterprise setup.  Writing output to post-deploy-output.json.")

    except:
        traceback.print_exc()
        print("Exception occured while setting up enterprise.  Dumping results to post-deploy-output.json anyhow.")

    with open("post-deploy-output.json", "w") as f:
        json.dump(json_output,f)

    return

if __name__ == '__main__':
    # if args are passed, do main line.
#    if len(sys.argv) != 1:
        sys.exit(main())


#    # otherwise do development of next step.
#    with open("output.json") as f:
#        # Read the file
#        output = json.load(f)
#
#    built=output['enterprise_built']
#    to_build=output['enterprise_to_build']
#    cloud_config=output['backend_config']
#
#    join_ret = join_domains(cloud_config,to_build,built)
#
#    output['enterprise_built']['setup']['join_domains'] = join_ret
#
#    with open("dev_output.json", "w") as f:
#        json.dump(output,f)
#


