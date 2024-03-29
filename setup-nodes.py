#!/usr/bin/env python


import traceback
import sys
import json
import role_register
import role_domains
from datetime import datetime
from openstack_cloud import OpenstackCloud
from joblib import Parallel, delayed



def load_configs(cloud_config_filename, enterprise_filename):
    with open(cloud_config_filename) as f:
        # Read the file
        cloud_config = json.load(f)

    with open(enterprise_filename) as f:
        # Read the file
        enterprise =  json.load(f)


    return cloud_config, enterprise

def deploy_enterprise(cloud_config,enterprise):
    ret = {}
    ret["deploy_start"] = str(datetime.now())
    match cloud_config['cloud_type'].lower():
        case 'openstack':
           print("Using openstack cloud") 
           cloud =  OpenstackCloud(cloud_config)
        case _:
            print("Cannot find cloud type: " + cloud_config['cloud_type'])

    ret['deployed'] = cloud.deploy_enterprise(enterprise)

    ret["deploy_end"] = str(datetime.now())
    return ret

def extract_creds(enterprise_built,name):
    details = next(filter( lambda x: name == x['name'], enterprise_built['deployed']['nodes']))
    addresses = details['addresses']
    ipv4_addr = addresses[0]['addr']
    print("  ipv4 addr: " + str(ipv4_addr))

    if 'password' in details:
        password = details['password']
        print("  password: " + str(password))
    else:
        password = None
        print("  password: No password set")
    return ipv4_addr,password

def register_windows(cloud_config,enterprise,enterprise_built):
    ret={}
    access_list=[]
    windows_nodes = list(filter(lambda x: 'windows' in x['roles'], enterprise['nodes']))
    for node in windows_nodes:
        name = node['name']
        print("  Registering windows on " + name)
        ipv4_addr,password = extract_creds(enterprise_built,name)
        access_list.append({"name": name, "addr": ipv4_addr, "password": str(password)})

    # sequential
    #results = []
    #for access in access_list:
    #    results.append(role_register.register_windows_instance(access))

    # parallel
    results = Parallel(n_jobs=10)(delayed(role_register.register_windows_instance)(i) for i in access_list)
    ret['register_windows']=results
        
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
        ipv4_addr,password = extract_creds(enterprise_built,name)
        access_list.append({"cloud_config": cloud_config, "node": node, "domain_leader": leader_details[domain], "addr": ipv4_addr, "password": str(password), 'domain': domain })

    # sequential
    #results = []
    #for access in access_list:
    #    results.append(role_domains.join_domain(access))

    # parallel
    results = Parallel(n_jobs=10)(delayed(role_domains.join_domain)(access) for access in access_list)

    ret['join_domains']=results
        
    return ret

def setup_enterprise(cloud_config,to_build,built):
    built['setup']={}
    built['setup']['windows_register'] = register_windows(cloud_config,to_build,built)
    built['setup']['setup_domains'] = deploy_domain_controllers(cloud_config,to_build,built)
    built['setup']['join_domains'] = join_domains(cloud_config,to_build,built)



def deploy_domain_controllers(cloud_config,enterprise,enterprise_built):
    ret={}
    leaders = list(filter(lambda x: 'domain_controller_leader' in x['roles'], enterprise['nodes']))
    leader_details={}
    for leader in leaders:
        name = leader['name']
        domain = leader['domain']
        print("Setting up domain controller with new forest on " + name + " for domain " + domain)
        ipv4_addr,password = extract_creds( enterprise_built,name)
        #access_list.append({"name": name})
        #access_list.append({"name": name, "addr": ipv4_addr})
        results=role_domains.deploy_forest(cloud_config,name,ipv4_addr,password, domain)
        leader_details[domain]={"name": str(name), "addr": [ipv4_addr], "admin_pass": str(password)}
        ret["forest_setup_"+name]=results

    followers = list(filter(lambda x: 'domain_controller' in x['roles'], enterprise['nodes']))
    for follower in followers:
        domain = follower['domain']
        name = follower['name']
        print("Setting up domain controller on " + name + ' for domain ' + domain)
        ipv4_addr,password = extract_creds( enterprise_built,name)
        results=role_domains.add_domain_controller(cloud_config,leader_details[domain], name,ipv4_addr,password, domain)
        leader_details[domain]['addr'].append(ipv4_addr)
        ret["additional_dc_setup_"+name]=results
        
    ret["domain_leaders"] = leader_details    
    return ret

def main():

    if len(sys.argv) != 3:
        print("Usage:  python " + sys.argv[0] + " cloud_config.json enterprise.json")
        sys.exit(1)

    json_output = {}
    try:
        json_output["start_time"] = str(datetime.now())
        cloud_config_filename = sys.argv[1]
        enterprise_filename  = sys.argv[2]
        cloud_config,enterprise = load_configs(cloud_config_filename, enterprise_filename)

        print("Deploying nodes.")
        enterprise_built = deploy_enterprise(cloud_config,enterprise)
        print("Deploying nodes, completed.")

        json_output['backend_config'] = cloud_config
        json_output['enterprise_to_build'] = enterprise
        print("Setting up nodes.")

        setup_enterprise(cloud_config,enterprise,enterprise_built)
        print("Setting up nodes, completed.")

        json_output['enterprise_built'] = enterprise_built
        json_output["end_time"] = str(datetime.now())

        print("Enterprise built.  Writing output to setup-output.json.")
    except:
        traceback.print_exc()
        print("Exception occured while setting up enterprise.  Dumping results to setup-output.json anyhow.")

    with open("setup-output.json", "w") as f:
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


