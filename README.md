# Workflows 

This tool helps setup and deploy an enterprise of compute nodes and users with various roles, domains, etc.
Also included is the ability to simulate workloads on the deployed infrastructure.

## Usage


### Site Configuration

Written in python and assumes to be running on Linux, make sure you have dependencies setup properly.

```
$ ./setup.sh
$ pip install -r requirements.txt
```


### Infrastructure Setup

Then, you can generate an enterprise:

```
$ python ./setup-nodes.py cloud_config.json enterprise-tiny.json
```

This deploys the infrastructure, setups up domain controllers, etc.  Output is written to `output.json`.  This file needs to be passed to later stages.

Three enterprises are included, `enterprise-{tiny,med,large}.json`.  See [`enterprise.md`](./enterprise/enterprise.md) for more details about these
files and how to create your own.

Two cloud configurations are included (`mtx.json` and `shen.json`).  These are for
two Openstack deployments at UVA.  While this is setup to support any cloud infrastructure to deploy an enterprise,
only Openstack is currently supported.  See [`cloud-config.md`](./cloud-config/cloud-config.md) for more details about writing
your own configuration.

### Simulation

Next, you can generate logins for the deployed infrastrcuture:

```
$ python ./simulate-logins.py  user-roles.json enterprise-tiny.json
```

This generates users and estimates a login behavior for these users based on settings in the enterprise.json file
and user-roles.json file via a stocastic simulation.  
See additional details on the user-roles in [user-roles.md](./user-roles/user-roles.md).
Output is written to logins.json, used in later stages.


### Emulation

Next, you can emulate the simulated logins:

```
$ python ./simulate-logins.py  enterprise-tiny.json logins.json
```
More description TBD, still in development.


### Cleanup

Lastly, cleanup/destroy the infrastructure:

```
python ./cleanup-nodes.py output.json
```

Caution:  this destroy/deletes all nodes and infrastructures that were setup in prior steps.  Use with caution.


