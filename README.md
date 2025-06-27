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

`monitor_confidentiality.py` can run concurrently with emulate-logins.py to collect 
confidentiality metrics.  It can be launched before, during, or after emulation.

---

### 6. **(Optional) Impact Simulation**

#### `impact` (custom modules)

Modules that simulate security-impacting behaviors:

* E.g., misconfigurations, password leaks, impersonation, etc.
* Can be selectively applied to test detection systems

✅ *Augments realism for cybersecurity research.*

---

### 7. **Log Aggregation & Analysis**

#### `compute-metrics` and `post-process-logs

Parses and normalizes logs from across the environment:

* Aggregates logs from endpoints and servers
* Optionally extracts features or metrics for ML/security tools
* Prepares ground-truth labels for supervised experiments

✅ *Final output: Cleaned datasets, metadata, and evaluation artifacts.*




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
If `post-deploy.py` fails,  it is OK to re-run and see if the failure was temporary (e.g., a remote repository being unavailable or a network interference issue).

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

If you want to do "fast" emulation for debugging, you can add the ``--fast-debug`` option.  
You may also want to tell python not to buffer the output and redirect all output to a file:

```
$ PYTHONUNBUFFERED=1 ./emulate-logins.py  post-deploy-output.json logins.json  --fast-debug 2>&1 | stdbuf -o0 -e0 tee workflow.log
```

If you want to specify a seed for more deterministic emulation results:

```
$ ./emulate-logins.py  post-deploy-output.json logins.json  --seed 42 
```

If you would like to replay the same set of configuration parameters from logins.json, i.e., same users and relative login times, 
specify the --rebase-time option. This will calculate a time offset to add to all timestamps in logins.json, so that login actions
are performed relative to the current timestamp. 

```
$ ./emulate-logins.py  post-deploy-output.json logins.json  --rebase-time 
```

Of course you can combine these:
```
$ PYTHONUNBUFFERED=1 ./emulate-logins.py  post-deploy-output.json logins.json  --seed 42 --rebase-time --fast-debug 2>&1 | stdbuf -o0 -e0 tee workflow.log
```

You may optionally run `monitor_confidentiality.py` during emulation to track ongoing privileged access across the testbed.  See the section on Confidentiality.

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

For continuous validation of confidentiality impacts, see `monitor_confidentiality.py`.


### Confidentiality Impact Monitoring Module

This module monitors deployed enterprise nodes to compute a "confidentiality
score" that reflects the ability of an attacker to gain privileged access via
known backdoor accounts (`impactroot` on Linux, `impactadmin` on Windows).

#### Purpose
It provides ongoing telemetry on whether nodes:
- Are completely inaccessible (score = 1.0)
- Allow SSH but deny privilege escalation (score = 0.5)
- Allow full privileged access (score = 0.0)

This helps quantify the effectiveness of confidentiality impacts.

#### Example Usage
```bash
$ python monitor_confidentiality.py \
    --post-deploy-output post-deploy-output.json \
    --time-interval 300 \
    --output impacts.jsonl \
    --verbose
```

This will:
- Connect to each node listed in `post-deploy-output.json`
- Attempt login using the known backdoor credentials
- Evaluate if sudo access is allowed
- Append JSON-formatted result summaries to `impacts.jsonl` every 5 minutes

#### Output Format
Each log entry includes:
```json
{
  "timestamp": "2025-06-19T14:05:00.123456",
  "total_nodes": 12,
  "average_confidentiality_score": 0.25,
  "count_score_0": 9,
  "count_score_0.5": 2,
  "count_score_1": 1,
  "scores": {
    "linep1": {
      "confidentiality_score": 0.0,
      "status": "ssh and sudo successful"
    },
    "linep2": {
      "confidentiality_score": 0.5,
      "status": "ssh ok, sudo failed"
    },
    "win7": {
      "confidentiality_score": 1.0,
      "status": "ssh failed"
    }
  }
}
```

This output can be used to:
- Track the real-time security state of the testbed
- Trigger alerts if compromised nodes become accessible again
- Validate proper deployment of `impact_confidentiality` modules

#### Digital Exhaust
Login attempts performed by this monitor leave traces in system logs, which can
be useful for forensic analysis or evaluating intrusion detection systems.

On Linux nodes:
- SSH login attempts will be logged to `/var/log/auth.log`
- Successful or failed `sudo` attempts will also appear in this log

On Windows nodes:
- Remote login and administrative activity may appear in Windows Event Logs
  under Security (Event Viewer > Windows Logs > Security)




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
./compute-metrics.py workflow.log
```

The output should look like:

```
{
  "metric_type": "workflow_summary",
  "report": {
    "Moodle": {
      "workflow": {
        "availability_average": 0.8182,
        "availability_total": 11,
        "availability_success": 9,
        "availability_error": 1,
        "integrity_average": 0.1,
        "integrity_total": 10,
        "integrity_success": 1,
        "integrity_failure": 9
      },
      "steps": {
        "availability_average": 0.973,
        "availability_total": 37,
        "availability_success": 36,
        "availability_error": 0,
        "integrity_average": 0.1111,
        "integrity_total": 36,
        "integrity_success": 4,
        "integrity_failure": 32
      }
    },
    "ShibbolethBrowser": {
      "workflow": {
        "availability_average": 0.0,
        "availability_total": 14,
        "availability_success": 0,
        "availability_error": 14,
        "integrity_average": 0.2143,
        "integrity_total": 14,
        "integrity_success": 3,
        "integrity_failure": 11
      },
      "steps": {
        "availability_average": 0.5,
        "availability_total": 6,
        "availability_success": 3,
        "availability_error": 11,
        "integrity_average": 0.0,
        "integrity_total": 14,
        "integrity_success": 0,
        "integrity_failure": 14
      }
    }
  }
}
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

There are two kinds of stats collected: (1) workflow-level, (2) workflow but at the 
step level. The step-level workflows have a `step_name` defined, whereas 
the workflow level stats do not.

To go beyond the integrity and availability metrics reported by `compute-metrics.py`, we 
highly recommend to write a python program to ingest all the JSON-formatted stats 
in the log file, e.g., in `workflow.log`.  We provide post-process-logs.py as an exemplar 
of how to process logs.  This script processes the logs by timestamp into, for example,
60 seconds bins and prints stats for each bin.


### Reproducibility & Reuse

This workflow is designed with reproducibility and controlled experimentation in
mind. It supports deterministic input generation, repeatable infrastructure
provisioning, and modular simulation and monitoring phases.

#### Key Features

- **Deterministic Login Behavior**
  - Use `--seed <int>` with `simulate-logins.py` or `emulate-logins.py` to
    produce consistent login behavior across runs.

- **Timestamp Rebasing**
  - Use `--rebase-time` with `emulate-logins.py` to shift all login timestamps
    relative to the current time. This allows replay of the same login plan
    with updated timestamps.

- **Configurable Output Targets**
  - Most tools (e.g., `simulate-logins.py`, `monitor_confidentiality.py`)
    accept custom output paths and filenames, enabling parallel experiments.

- **Replay-Friendly Artifacts**
  - Files like `logins.json`, `post-deploy-output.json`, and impact results are
    stable and can be reused in downstream steps without re-execution.


#### Suggested Reuse Patterns

- Generate login plans once, reuse many times:
  ```bash
  $ ./simulate-logins.py ... > login-plan.json
  $ ./emulate-logins.py post-deploy-output.json login-plan.json
  $ ./emulate-logins.py post-deploy-output.json login-plan.json --rebase-time
  ```

- Split monitor from emulation:
  ```bash
  $ python monitor_confidentiality.py --output impacts-run1.jsonl &
  $ python emulate-logins.py post-deploy-output.json login-plan.json
  ```

- Use consistent seeds for reproducibility:
  ```bash
  $ ./simulate-logins.py --seed 1234 ...
  $ ./emulate-logins.py --seed 1234 ...
  ```

This approach ensures traceability, repeatability, and clean ground-truth
labeling for research and detection validation.

