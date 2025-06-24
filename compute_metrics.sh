#!/bin/bash


compute_availability_for_ssh() 
{
	ssh_attempts_linux=$(grep -i "To linux node" $Workflow_log | wc -l)
	ssh_failed_linux=$(grep "Failed connect to user" $Workflow_log | grep -i "linux" | grep "FAILED" | wc -l )
	ssh_success_linux=$(grep "ssh successful" $Workflow_log | grep -i "linux" | wc -l )
	ssh_availability_linux=$(echo "scale=4; ($ssh_attempts_linux - $ssh_failed_linux) / $ssh_attempts_linux" | bc)

	ssh_attempts_windows=$(grep -i "To windows node" $Workflow_log | wc -l)
	ssh_failed_windows=$(grep "Failed connect to user" $Workflow_log | grep -i "windows" | grep "FAILED" | wc -l )
	ssh_success_windows=$(grep "ssh successful" $Workflow_log | grep -i "windows" | wc -l )
	ssh_availability_windows=$(echo "scale=4; ($ssh_attempts_windows - $ssh_failed_windows) / $ssh_attempts_windows" | bc)

	echo
	echo "=== Metrics for ssh linux"
	echo "SSH-linux: availability=$ssh_availability_linux"
	echo "SSH-linux: num_started=$ssh_attempts_linux"
	echo "SSH-linux: num_success=$ssh_success_linux"
	echo "SSH-linux: num_err=$ssh_failed_linux"

	echo
	echo "=== Metrics for ssh windows"
	echo "SSH-windows: availability=$ssh_availability_windows"
	echo "SSH-windows: num_started=$ssh_attempts_windows"
	echo "SSH-windows: num_success=$ssh_success_windows"
	echo "SSH-windows: num_err=$ssh_failed_windows"

	ssh_attempts=$((ssh_attempts_linux + ssh_attempts_windows))
	ssh_failed=$((ssh_failed_linux + ssh_failed_windows))
	ssh_success=$((ssh_success_linux + ssh_success_windows))
	ssh_availability=$(echo "scale=4; ($ssh_attempts-$ssh_failed) / $ssh_attempts" | bc)

	echo
	echo "=== Metrics for ssh windows and linux"
	echo "SSH: availability=$ssh_availability"
	echo "SSH: num_started=$ssh_attempts"
	echo "SSH: num_success=$ssh_success"
	echo "SSH: num_err=$ssh_failed"
}

compute_availability_for_workflow() 
{
	workflow_name=$1

	start_count=$( grep workflow_name $Workflow_log | grep -v step_name | grep $workflow_name | grep '"start"' | wc -l )
	success_count=$( grep workflow_name $Workflow_log | grep -v step_name | grep $workflow_name | grep '"success"' | wc -l )
	err_count=$( grep workflow_name $Workflow_log | grep -v step_name | grep $workflow_name | grep error | wc -l )

	availability=$( echo "scale=4; $success_count / $start_count" | bc )
	
	echo
	echo "=== Metrics for $workflow_name"
	echo "Workflow $workflow_name: availability=$availability"
	echo "Workflow $workflow_name: num_started=$start_count"
	echo "Workflow $workflow_name: num_success=$success_count"
	echo "Workflow $workflow_name: num_err=$err_count"
}

compute_availability_for_workflow_by_steps() 
{
	workflow_name=$1

	start_count=$( grep workflow_name $Workflow_log | grep step_name | grep $workflow_name | grep '"start"' | wc -l )
	success_count=$( grep workflow_name $Workflow_log | grep step_name | grep $workflow_name | grep '"success"' | wc -l )
	err_count=$( grep workflow_name $Workflow_log | grep step_name | grep $workflow_name | grep error | wc -l )

	availability=$( echo "scale=4; $success_count / $start_count" | bc )
	
	echo
	echo "=== Metrics for $workflow_name by steps"
	echo "Workflow $workflow_name steps: availability=$availability"
	echo "Workflow $workflow_name steps: num_started=$start_count"
	echo "Workflow $workflow_name steps: num_success=$success_count"
	echo "Workflow $workflow_name steps: num_err=$err_count"
}

compute_availability_for_all_workflows() 
{
	workflow_name=$1

	start_count=$( grep workflow_name $Workflow_log | grep -v step_name | grep '"start"' | wc -l )
	success_count=$( grep workflow_name $Workflow_log | grep -v step_name | grep '"success"' | wc -l )
	err_count=$( grep workflow_name $Workflow_log | grep -v step_name | grep status | grep error | wc -l )

	availability=$( echo "scale=4; $success_count / $start_count" | bc )
	
	echo
	echo "=== Metrics for all workflows"
	echo "All workflows: availability=$availability"
	echo "All workflows: num_started=$start_count"
	echo "All workflows: num_success=$success_count"
	echo "All workflows: num_err=$err_count"
}

compute_availability_for_all_workflows_by_steps() 
{
	workflow_name=$1

	start_count=$( grep workflow_name $Workflow_log | grep step_name | grep '"start"' | wc -l )
	success_count=$( grep workflow_name $Workflow_log | grep step_name | grep '"success"' | wc -l )
	err_count=$( grep workflow_name $Workflow_log | grep step_name | grep status | grep error | wc -l )

	availability=$( echo "scale=4; $success_count / $start_count" | bc )
	
	echo
	echo "=== Metrics for all workflows by steps"
	echo "All workflow steps: availability=$availability"
	echo "All workflow steps: num_started=$start_count"
	echo "All workflow steps: num_success=$success_count"
	echo "All workflow steps: num_err=$err_count"
}

main()
{
	if [ -z "$1" ]; then
		echo "Usage: $0 <Workflow_log_file>"
		exit 1
	fi

	Workflow_log=$1

	if [ ! -f "$Workflow_log" ]; then
		echo "Workflow log file \"$Workflow_log\" does not exist"
		exit 1
	fi

	compute_availability_for_ssh

	workflows=$(grep workflow_name $Workflow_log | jq -r .workflow_name | sort | uniq |  paste -sd ' ')
	for workflow_name in $workflows
	do
		compute_availability_for_workflow $workflow_name
		compute_availability_for_workflow_by_steps $workflow_name
	done

	compute_availability_for_all_workflows
	compute_availability_for_all_workflows_by_steps

	echo 
	echo "Metrics computed for workflows: ssh ${workflows}"
}

main "$@"
