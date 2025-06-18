# Workflows 

This tool helps setup and deploy an enterprise of compute nodes and users with various roles, domains, etc.
Also included is the ability to simulate workloads on the deployed infrastructure.

## 🏗️ System Workflow Overview

This toolchain provisions a simulated enterprise environment, populates it with domain-controlled users and systems, and then drives realistic login and activity patterns to emulate real-world usage. The workflow is designed for reproducibility, testing, and security research.

---

### 1. **Environment Preparation**

#### `setup.sh`

Sets up the local Python environment and required tools.

* Installs Python dependencies (`requirements.txt`)
* Prepares OpenStack CLI access (assumes access via `os_env_file`)
* Ensures you can communicate with the cloud backend and deploy nodes

✅ *Run this once per machine setup or when dependencies change.*

---

### 2. **Infrastructure Deployment**

#### `deploy-nodes.py`

Deploys virtual machines and resources into the specified OpenStack cloud using:

* A **cloud configuration** (`cloud-configs/*.json`) specifying backend details, keypairs, image and instance mappings, etc.
* An **enterprise configuration** (`enterprise-configs/*.json`) that defines machines, roles (e.g., domain controllers, endpoints), and desired domain topology.

✅ *Output: `deploy-output.json` containing deployed node metadata.*

---

### 3. **Post-deployment Configuration**

#### `post-deploy.py`

Configures services on the deployed infrastructure:

* Joins Windows nodes to domains
* Promotes domain controllers
* Configures file servers, IdPs, SPs, etc.
* Ensures endpoints are reachable and functional

✅ *Output: `post-deploy-output.json`, which feeds into later stages.*

---

### 4. **Login Schedule Generation**

#### `simulate-logins`

Generates a synthetic but plausible login schedule for the enterprise:

* Models user behavior (e.g., shift-based logins, weekend activity)
* Outputs a `logins.json` file describing who logs in, where, and when

✅ *Input: `post-deploy-output.json`
✅ Output: `logins.json`*

---

### 5. **Login Emulation**

#### `emulate-logins.py`

Performs the actual remote login behavior described in `logins.json`.

* SSHs or RDPs into the appropriate machines
* Triggers login sequences
* Optionally starts background activity emulation

✅ *Real traffic, logs, and artifacts are generated across the environment.*

---

### 6. **(Optional) Impact Simulation**

#### `impact` (custom modules)

Modules that simulate security-impacting behaviors:

* E.g., misconfigurations, password leaks, impersonation, etc.
* Can be selectively applied to test detection systems

✅ *Augments realism for cybersecurity research.*

---

### 7. **Log Aggregation & Analysis**

#### `post_process_logs`

Parses and normalizes logs from across the environment:

* Aggregates logs from endpoints and servers
* Optionally extracts features or metrics for ML/security tools
* Prepares ground-truth labels for supervised experiments

✅ *Final output: Cleaned datasets, metadata, and evaluation artifacts.*


## Usage


### Site Configuration

Written in python and assumes to be running on Linux with ssh access to the nodes created, make sure you have dependencies setup properly:

```
$ ./setup.sh
$ pip install -r requirements.txt
```

The deploy scripts use [Designate](https://docs.openstack.org/designate/latest/) to handle DNS resolution, required for the Shibboleth workflow.  
Shibboleth and Moodle will not work without the proper DNS resolution.


### Infrastructure Setup

Then, you can deploy and configure an enterprise:

```
$ ./deploy-nodes.py -c cloud-configs/cloud-config.json -e enterprise-configs/enterprise-tiny.json
$ ./post-deploy.py deploy-output.json
```

This deploys the infrastructure, setups up domain controllers, etc.  Output is written to `deploy-output.json` and `post-deploy-output.json`.  
These files needs to be passed to later stages.
If `post-deploy-nodes.py` fails,  it is OK to re-run and see if the failure was temporary (e.g., a remote repository being unavailable or a network interference issue).

Some sample enterprises are included.  See [`enterprise.md`](./enterprise-configs/enterprise.md) for more details about these
files and how to create your own.

Sample cloud configurations are included (e.g., `mtx.json` and `shen.json`).  These are for
two Openstack deployments at UVA.  While this is setup to support any cloud infrastructure to deploy an enterprise,
only Openstack is currently supported.  See [`cloud-config.md`](./cloud-configs/cloud-config.md) for more details about writing
your own configuration.

To sanity check that your ssh keys and DNS are configured properly, you should be able to ping the various machines setup in your cloud config and enterprise config files, as well as ssh without a password into Linux VMs. 

For example, if the `enterprise_url` field in your cloud config is `castle.os`, and you have a Linux machine named `linep1` in your enterprise config,
you should be able to:

1. `ping linep1.castle.os`
2. `nslookup <name>.castle.os` # where *name* is any machine name defined in your enterprise config file
3. `ssh ubuntu@linep1.castle.os`

### Simulation

Next, you can generate logins for the deployed infrastructure:

```
$ ./simulate-logins.py  user-roles/user-roles.json enterprise-configs/enterprise-tiny.json
```

This generates users and estimates a login behavior for these users based on settings in the enterprise.json file
and user-roles.json file via a stochastic simulation.  
See additional details on the user-roles in [user-roles.md](./user-roles/user-roles.md).
Output is written to logins.json, used in later stages.

If you also want to emulate logins (next section), you will also need to install users into the enterprise.  You can do that by adding the enterprise description created when deploying the enterprise to the `simulate-logins` command.

```
$ ./simulate-logins.py  user-roles/user-roles.json enterprise-configs/web-wf.json post-deploy-output.json
```


### Emulation

Next, you can emulate the simulated logins:

```
$ ./emulate-logins.py  post-deploy-output.json logins.json 
```

If you want to do "fast" emulation for debugging, you can add the ``--fast-debug`` option.  You may also want to tell python not to buffer the output and redirect all output to a file:

```
$ python -u ./emulate-logins.py  post-deploy-output.json logins.json  --fast-debug 2>&1 | stdbuf -o0 -e0 tee workflow.log
```

If you want to specify a seed for more deterministic emulation results:

```
$ python -u ./emulate-logins.py  post-deploy-output.json logins.json  --fast-debug --seed 42 2>&1 |tee workflow.log
```

If you would like to replay the same set of configuration parameters from logins.json, i.e., same users and relative login times, 
specify the --rebase-time option. This will calculate a time offset to add to all timestamps in logins.json, so that login actions
are performed relative to the current timestamp. 

```
$ python -u ./emulate-logins.py  post-deploy-output.json logins.json  --rebase-time 2>&1 | stdbuf -o0 -e0 tee workflow.log
```

### Generating Impacts on the Emulation

The `impact.py` script applies targeted cybersecurity impacts to specific nodes in a deployed enterprise, using the configuration from `post-deploy-output.json`.

#### Basic Usage

```bash
$ ./impact.py -i <type>=<node> -c post-deploy-output.json [--parallel] [--verbose]
```

#### Arguments

* `-i`, `--impact <type>=<node>`: **(required, repeatable)**
  Specifies a particular impact to simulate. The format is:

  * `confidentiality=node-name`
  * `integrity=node-name`
  * `availability=node-name`

  You can specify this argument multiple times to apply multiple impacts.

* `-c`, `--config`: **(required)**
  Path to the `post-deploy-output.json` file that describes the infrastructure.

* `--parallel`: Optional. Run multiple impact simulations in parallel.

* `--verbose`: Optional. Enable detailed logging output for debugging and traceability.

#### Example

```bash
$ ./impact.py -i confidentiality=endpoint1 -i integrity=dc1 -c post-deploy-output.json --parallel
```

This applies a confidentiality impact to `endpoint1` and an integrity impact to `dc1`, running them in parallel.

Use `impact.py --help` to view this help screen at any time.

#### Supported Impact Types

* **`availability`**
  Simulates service disruption:

  * Stops critical services like `apache2`, `jetty`, `smb`, or Active Directory (NTDS)
  * Behavior varies by role (SP, IdP, domain controller, file server)

* **`confidentiality`**
  Simulates data exposure by installing a root-permissioned backdoor to the machine where data can be leaked. The password is `pownd`. On Linux machines, the account is `impactroot`; on Windows machines, the account is `impactadmin`.

* **`integrity`**
  Simulates unauthorized modification:

  * On SP: modifies the site name from "Moodle" to "Pwnd"
  * On IdP: modifies the "Forgot password" link text to "You've been pwnd"
  * On other machines: modifies the MOTD to include a "pwnd" message

### Cleanup

Lastly, cleanup/destroy the infrastructure:

```
./cleanup-nodes.py deploy-output.json
```

Caution:  this destroy/deletes all nodes and infrastructures that were setup in prior steps.  Use with caution.


# Debugging

Most python scripts have a "verbose" variable near the top of the file.  
If you're having trouble with some aspect of the deployment, etc., you can try turning that on to see if verbose output 
is helpful with the problem.  Also, by default setup happens in parallel by default, and the post-deploy.py script has a `use_parallel`
option that can be used to do sequential setup, which far improves the ability to debug at the expense of significantly more
setup time.


# Deploying in Vanderbilt CAGE2 infrastructure.


This aspect is now handled by the castle-vm `gradlew` command.  See documentation there.

# Collecting Metrics
After you run a workflow (and assuming you redirected output to `workflow.log`), you can compute availability metrics:

```
./compute_metrics.sh workflow.log
```

The output should look like:

```
=== Metrics for ssh linux
SSH-linux: availability=1.0000
SSH-linux: num_started=5
SSH-linux: num_success=4
SSH-linux: num_err=0

=== Metrics for ssh windows
SSH-windows: availability=1.0000
SSH-windows: num_started=2
SSH-windows: num_success=2
SSH-windows: num_err=0

=== Metrics for ssh windows and linux
SSH: availability=1.0000
SSH: num_started=7
SSH: num_success=6
SSH: num_err=0

=== Metrics for Moodle
Workflow Moodle: availability=.8000
Workflow Moodle: num_started=5
Workflow Moodle: num_success=4
Workflow Moodle: num_err=1

=== Metrics for Moodle by steps
Workflow Moodle steps: availability=.9642
Workflow Moodle steps: num_started=28
Workflow Moodle steps: num_success=27
Workflow Moodle steps: num_err=0
```

## Computing additional metrics
Workflow statistics are emitted as the emulation runs. They are of the form: 

```
{"timestamp": "2024-12-13T16:38:52.048017", "workflow_name": "Moodle", "status": "start", "message": "Starting step BrowseCourse:CGC", "hostname": "linep1", "pid": 13828, "step_name": "BrowseCourse:CGC"}
{"timestamp": "2024-12-13T16:38:55.035040", "workflow_name": "Moodle", "status": "start", "message": "Starting step BrowseCourse:MoodlePDF", "hostname": "linep1", "pid": 13828, "step_name": "BrowseCourse:MoodlePDF"}
{"timestamp": "2024-12-13T16:38:59.042169", "workflow_name": "Moodle", "status": "success", "message": "Step BrowseCourse:MoodlePDF successful", "hostname": "linep1", "pid": 13828, "step_name": "BrowseCourse:MoodlePDF"}
{"timestamp": "2024-12-13T16:39:05.555751", "workflow_name": "Moodle", "status": "success", "message": "Step BrowseCourse:CGC successful", "hostname": "linep1", "pid": 13828, "step_name": "BrowseCourse:CGC"}
{"timestamp": "2024-12-13T16:39:05.557954", "workflow_name": "Moodle", "status": "start", "message": "Starting step BrowseCourse:RAMPART", "hostname": "linep1", "pid": 13828, "step_name": "BrowseCourse:RAMPART"}
{"timestamp": "2024-12-13T16:39:08.408369", "workflow_name": "Moodle", "status": "success", "message": "Step BrowseCourse:RAMPART successful", "hostname": "linep1", "pid": 13828, "step_name": "BrowseCourse:RAMPART"}
```

There are two kinds of stats collected: (1) workflow-level, (2) workflow but at the step level. The step-level workflows have a `step_name` defined, whereas the workflow level stats do not.

To go beyond the availability metrics reported by `compute_metrics.sh`, highly recommend to write a python program to ingest all the JSON-formatted stats in the log file, e.g., in `workflow.log`

