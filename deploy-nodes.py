#!/usr/bin/env python

import argparse
import traceback
import sys
import json
from datetime import datetime
from openstack_cloud import OpenstackCloud

import urllib3
urllib3.disable_warnings()


def load_configs(cloud_config_filename, enterprise_filename):
    with open(cloud_config_filename) as f:
        # Read the file
        cloud_config = json.load(f)

    with open(enterprise_filename) as f:
        # Read the file
        enterprise = json.load(f)

    return cloud_config, enterprise


def deploy_enterprise(cloud_config, enterprise):
    ret = {"deploy_start": str(datetime.now())}
    match cloud_config['cloud_type'].lower():
        case 'openstack':
            print("Using openstack cloud")
            cloud = OpenstackCloud(cloud_config)
        case _:
            raise Exception(f"Cannot find cloud type: {cloud_config['cloud_type']}")

    ret['deployed'] = cloud.deploy_enterprise(enterprise)

    ret["deploy_end"] = str(datetime.now())
    return ret


def query_enterprise(cloud_config, enterprise):
    ret = {"deploy_start": str(datetime.now())}
    match cloud_config['cloud_type'].lower():
        case 'openstack':
            print("Using openstack cloud")
            cloud = OpenstackCloud(cloud_config)
        case _:
            raise Exception(f"Cannot find cloud type: {cloud_config['cloud_type']}")

    ret['deployed'] = cloud.query_enterprise(enterprise)

    ret["deploy_end"] = str(datetime.now())
    return ret


def main():

    parser = argparse.ArgumentParser(
        prog=sys.argv[0],
        description="Create stacks on openstack"
    )

    parser.add_argument(
        "-c", "--cloud_config_file", required=False,
        help="Path of cloud-config file"
    )

    parser.add_argument(
        "-e", "--enterprise_config_file", required=False,
        help="Path of enterprise-config file"
    )

    parser.add_argument(
        "-q", "--query_only", required=False, action="store_true",
        help="Perform queries only"
    )

    args = parser.parse_args()

    json_output = {}
    try:
        json_output["deploy_start_time"] = str(datetime.now())
        cloud_config, enterprise_config = load_configs(args.cloud_config_file, args.enterprise_config_file)

        print("Deploying nodes.")
        enterprise_built = query_enterprise(cloud_config, enterprise_config) if args.query_only \
            else deploy_enterprise(cloud_config, enterprise_config)

        print("Deploying nodes, completed.")

        json_output['backend_config'] = cloud_config
        json_output['enterprise_to_build'] = enterprise_config
        json_output['enterprise_built'] = enterprise_built

        json_output["deploy_end_time"] = str(datetime.now())

        print("Enterprise built.  Writing output to deploy-output.json.")
    except Exception as _:   # noqa: F841
        traceback.print_exc()
        print("Exception occured while setting up enterprise.  Dumping results to deploy-output.json anyhow.")

    with open("deploy-output.json", "w") as f:
        json.dump(json_output, f, indent=4, sort_keys=True)

    return


if __name__ == '__main__':
    # if args are passed, do main line.
    # if len(sys.argv) != 1:
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
