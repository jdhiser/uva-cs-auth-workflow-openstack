#!/usr/bin/env python


import traceback
import sys
import json
from datetime import datetime
from openstack_cloud import OpenstackCloud



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

def main():

    if len(sys.argv) != 3:
        print("Usage:  python " + sys.argv[0] + " cloud_config.json enterprise.json")
        sys.exit(1)

    json_output = {}
    try:
        json_output["deploy_start_time"] = str(datetime.now())
        cloud_config_filename = sys.argv[1]
        enterprise_filename  = sys.argv[2]
        cloud_config,enterprise = load_configs(cloud_config_filename, enterprise_filename)

        print("Deploying nodes.")
        enterprise_built = deploy_enterprise(cloud_config,enterprise)
        print("Deploying nodes, completed.")

        json_output['backend_config'] = cloud_config
        json_output['enterprise_to_build'] = enterprise
        json_output['enterprise_built'] = enterprise_built

        json_output["deploy_end_time"] = str(datetime.now())

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


