#!/bin/bash 

WORKFLOWS="browse_iis moodle"
IMPACTS="confidentiality availability integrity"
SEEDS="1 2"
CLOUD_CONFIG="cloud-configs/axes-proj1-ubuntu.json"
ENTERPRISE_CONFIG="enterprise-configs/cyberfortress-enterprise-full.json"
USER_ROLES="user_roles/user-roles.json"
LOGINS="./logins.json"
POST_DEPLOY_OUTPUT="post-deploy-output.json"

main()
{
	local NODES="$(cat $ENTERPRISE_CONFIG |jq .nodes[].name -r)"

	for workflow in $WORKFLOWS
	do
		for impact in $IMPACTS
		do
			for node in $NODES
			do
				for seed in $SEEDS
				do
					local outpath="logs/

					./clean-nodes.py $POST_DEPLOY_OUTPUT || true
					./deploy-nodes.py  -c $CLOUD_CONFIG -e $ENTERPRISE_CONFIG
					./post-deploy.py  deploy-output.json
					./simulate-logins.py $USER_ROLES $ENTERPRISE $POST_DEPLOY_OUTPUT
					./collect-logs.py -p $POST_DEPLOY_OUTPUT --enterprise-json $ENTERPRISE  $workflow -P  -v --logins $LOGINS -o $outpath
					./clean-nodes.py post-deploy-output.json
				done
			done

		done
	done
}

main "$@"
