#!/usr/bin/env python


import log_setup  # noqa: F401  -- patches print() to prefix wall-clock timestamps
import sys
import json
from datetime import datetime
from openstack_cloud import OpenstackCloud


def load_output(output_filename):
    with open(output_filename) as f:
        # Read the file
        output = json.load(f)

    return output


def cleanup_enterprise(cloud_config, enterprise):
    ret = {}
    ret["cleanup_start"] = str(datetime.now())
    match cloud_config['cloud_type'].lower():
        case 'openstack':
            print("Using openstack cloud")
            cloud = OpenstackCloud(cloud_config)
        case _:
            print("Cannot find cloud type: " + cloud_config['cloud_type'])

    ret['cleanup'] = cloud.cleanup_enterprise(enterprise)

    ret["cleanup_end"] = str(datetime.now())
    return ret


def main():

    if len(sys.argv) != 2:
        print("Usage: " + sys.argv[0] + " post-deploy-output.json ")
        sys.exit(1)

    output_filename = sys.argv[1]
    json_output = load_output(output_filename)
    cloud_config = json_output['backend_config']
    enterprise = json_output['enterprise_to_build']
    json_output["cleanup_start_time"] = str(datetime.now())

    print("Cleaning up nodes.")
    cleanup_results = cleanup_enterprise(cloud_config, enterprise)
    print("Cleaning up, completed.")

    json_output['cleanup_results'] = cleanup_results
    json_output["cleanup_end_time"] = str(datetime.now())

    print("Enterprise cleaned.  Writing output to cleanup-output.json.")
    with open("cleanup-output.json", "w") as f:
        json.dump(json_output, f)

    return


if __name__ == '__main__':
    main()
