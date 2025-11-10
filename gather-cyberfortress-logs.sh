#!/bin/bash 

set -Eeuo pipefail

# config parameters
WORKFLOWS=(browse_iis moodle)
#IMPACTS=(none confidentiality availability integrity)
IMPACTS=(none)
SEEDS=(1 2)
CLOUD_CONFIG="cloud-configs/axes-proj1-ubuntu.json"
ENTERPRISE_CONFIG="enterprise-configs/cyberfortress-enterprise-full.json"
OUTPATH_BASE="/mnt/data/gather-workflows"


# #define's for how the workflow works
USER_ROLES="user-roles/user-roles.json"
LOGINS="./logins.json"
POST_DEPLOY_OUTPUT="post-deploy-output.json"
DEPLOY_OUTPUT="deploy-output.json"

do_workflow()
{
	local workflow="$1"
	local impact="$2"
	local impact_node="$3"
	local workflow_node="$4"
	local seed="$5"

	local outpath="$OUTPATH_BASE/workflow=$workflow.impact=$impact.impact_node=$impact_node.workflow_node=$workflow_node.seed=$seed"

	./cleanup-nodes.py "$DEPLOY_OUTPUT" || true
	sleep 1m # time for cleanup to finish
	./deploy-nodes.py  -c "$CLOUD_CONFIG" -e "$ENTERPRISE_CONFIG"
	sleep 5m  # wait for machines to deploy
	./post-deploy.py  "$DEPLOY_OUTPUT"
	./simulate-logins.py --seed "$seed" "$USER_ROLES" "$ENTERPRISE_CONFIG" "$POST_DEPLOY_OUTPUT"
	if [[ $impact = none ]]
	then
		./collect-logs.py -p "$POST_DEPLOY_OUTPUT" --enterprise-json "$ENTERPRISE_CONFIG" -w "$workflow" -P  -v --logins "$LOGINS" -o "$outpath"
	else
		./collect-logs.py -p "$POST_DEPLOY_OUTPUT" --enterprise-json "$ENTERPRISE_CONFIG" --impact "$impact_node=$impact" -w "$workflow_node=$workflow" -P  -v --logins "$LOGINS" -o "$outpath"
	fi
	./cleanup-nodes.py "$POST_DEPLOY_OUTPUT"
}

main()
{
	# record some paths
	mapfile -t impact_nodes < <(jq -r '.nodes[].name' "$ENTERPRISE_CONFIG")
	mapfile -t workflow_nodes < <(jq -r '.nodes[] | select(.roles | index("endpoint")) | .name' "$ENTERPRISE_CONFIG")

	local metapath="$OUTPATH_BASE/meta"

	# save some metadata
	mkdir -p "$metapath"
	echo "$WORKFLOWS" > "$metapath/workflows"
	echo "$IMPACTS" > "$metapath/impacts"
	echo "$SEEDS" > "$metapath/seeds"
	cp "$CLOUD_CONFIG" "$metapath/cloud-config.json"
	cp "$ENTERPRISE_CONFIG" "$metapath/enterprise-config.json"
	cp "$USER_ROLES" "$metapath/user-roles.json"


	# deploy, provision, simulate and  
	for workflow in "${WORKFLOWS[@]}"
	do
		for workflow_node in "${workflow_nodes[@]}"
		do
			for seed in "${SEEDS[@]}"
			do
				for impact in "${IMPACTS[@]}"
				do
					if [[ $impact == none ]]
					then
						do_workflow "$workflow" "$impact" "" "$workflow_node" "$seed"
					else
						for impact_node in "${impact_nodes[@]}"
						do
							do_workflow "$workflow" "$impact" "$impact_node" "$workflow_node" "$seed"
						done
					fi
				done
			done

		done
	done
}

main "$@"
