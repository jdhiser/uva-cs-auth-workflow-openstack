#!/bin/bash

main()
{
	./setup.sh

	set -x
	pwd
	ls
	ls cicd/

	source cicd/cs-workflow-rc
	openstack image list --insecure


}

main "$@"
