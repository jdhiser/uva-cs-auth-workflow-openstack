#!/bin/bash 

WORKFLOWS="browse_iis"
IMPACTS="confidentiality availability integrity"
NODES=" dc1 dc2 iis rootca subca win10-eng win10-fin win10-hr"

main()
{

	for workflow in $WORKFLOWS
	do
		for impact in $IMPACTS
		do
			for node in $NODES
			do
				./clean-nodes.py post-deploy-output.json
				./deploy-nodes.py 
				./collect-logs.py -p post-deploy-output.json --enterprise-json enterprise-configs/cyberfortress-enterprise.json  -w browse_iis -o iis-workflow  -P  -v --logins ./logins.json
				./clean-nodes.py post-deploy-output.json
			done

		done
	done




}

main "$@"
