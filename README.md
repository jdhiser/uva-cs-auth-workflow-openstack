# Workflows 

This tool helps setup and deploy an enterprise of compute nodes and users with various roles, domains, etc.
Also included is the ability to simulate workloads on the deployed infrastructure.

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
$ ./deploy-nodes.py cloud-config.json enterprise-tiny.json
$ ./post-deploy-nodes.py deploy-output.json
```

This deploys the infrastructure, setups up domain controllers, etc.  Output is written to `deploy-output.json` and `post-deploy-output.json`.  
These files needs to be passed to later stages.
If `post-deploy-nodes.py` fails,  it is OK to re-run and see if the failure was temporary (e.g., a remote repository being unavailable or a network interference issue).

Some sample enterprises are included.  See [`enterprise.md`](./enterprise/enterprise.md) for more details about these
files and how to create your own.

Sample cloud configurations are included (e.g., `mtx.json` and `shen.json`).  These are for
two Openstack deployments at UVA.  While this is setup to support any cloud infrastructure to deploy an enterprise,
only Openstack is currently supported.  See [`cloud-config.md`](./cloud-config/cloud-config.md) for more details about writing
your own configuration.

### Simulation

Next, you can generate logins for the deployed infrastrcuture:

```
$ ./simulate-logins.py  user-roles.json enterprise-tiny.json
```

This generates users and estimates a login behavior for these users based on settings in the enterprise.json file
and user-roles.json file via a stocastic simulation.  
See additional details on the user-roles in [user-roles.md](./user-roles/user-roles.md).
Output is written to logins.json, used in later stages.

If you also want to emulate logins (next section), you will also need to install users into the enterprise.  You can do that by adding the enterprise description created when deploying the enterprise to the `simulate-logins` command.

```
$ ./simulate-logins.py  user-roles/user-roles.json enterprise-config/web-wf.json post-deploy-output.json
```


### Emulation

Next, you can emulate the simulated logins:

```
$ ./emulate-logins.py  post-deploy-output.json logins.json 
```

If you want to do "fast" emulation for debugging, you can add the ``--fast-debug`` option.  You may also want to tell python not to buffer the output and redirect all output to a file:

```
$ python -u ./emulate-logins.py  post-deploy-output.json logins.json  --fast-debug 2>&1 |tee workflow.log
```



### Cleanup

Lastly, cleanup/destroy the infrastructure:

```
./cleanup-nodes.py output.json
```

Caution:  this destroy/deletes all nodes and infrastructures that were setup in prior steps.  Use with caution.


# Debugging

Most python scripts have a "verbose" variable near the top of the file.  
If you're having trouble with some aspect of the deployment, etc., you can try turning that on to see if verbose output 
is helpful with the problem.  Also, by default setup happens in parallel, and the post-deploy.py script has a `use_parallel`
option that can be used to do sequential setup, which far improves the ability to debug at the expense of significantly more
setup time.


# Deploying in Vanderbilt CAGE2 infrastructure.

## Setup:

In the openstack project you'll be using for the Moodle workfloe, you'll need to allocate a node on which
to run the deployment and provisioning.  To do this do the following:

* Currently, we have created a new network in openstack (`green-network`), and a new subnet
  (10.10.50.0/24 - `green-subnet`) in this network.
  > NOTE: Be sure there is a DNS nameserver in the subnet, and set it with the following command:
  >
  > `openstack subnet set --dns-nameserver <dns-nameserver-ip-address>` <subnet-id>
* In this new subnet, we created a new instance using the `Ubuntu22.04` image (a minimal Ubuntu 22.04 image),
  and called the image `workflow-manager`.

In the `ubuntu` account (i.e. the default user account) of the `workflow-manager` host:

* Copy the following files into the account:
  1. The private key you use to access github into the `.ssh` directory (which is under the ubuntu user's home
     directory).
  2. The `castle-control` private key from the <castle-vm> project into the `.ssh`
     directory as well.  It is located at:
     ```
     <castle-vm-root>/CreateVMs/VelociraptorVMs/secrets/castle-control
     ```
        >NOTE: **BEFORE COPYING THE `castle-control` KEY, MAKE SURE IT IS IN RSA FORMAT**.  If it is not in RSA
        >format, use the following command to convert it:
        > 
        >`ssh-keygen -p -N "" -m PEM -f <path-to-castle-control-key>`
  3. The `<openstack-project-name>-openrc.sh` file, which used to authenticate openstack shell commands to openstack,
     into the ubuntu user's home directory. `<openstack-project-name>` is the name of the openstack project you're using
     for the Moodle workflow.


* **EVERY TIME YOU LOG IN** you will need to execute the following commands:
  ```
  . ~/<openstack-project-name>-openrc.sh
  eval $(ssh-agent)
  ssh-add ~/.ssh/castle-control
  ```

or put them in the `.bashrc` file.

Now, execute the following commands:

```commandline
cd
mkdir -p Git
cd Git
git clone git@github.com:CASTLEGym/uva-cs-auth-workflow-openstack.git
cd uva-cs-auth-workflow-openstack
```

> NOTE: You may have to checkout a particular branch, i.e.
> ```commandline
> git checkout <branch-name>
> ```

## Running deployment:

To run deployment, run

```commandline
./deploy-nodes.py <arguments>
```

as above.

Once `deploy-node.py` finishe successfully, it should render output similar to that below

```commandline
Setting up nodes.
  Registering windows on dc1
  ipv4 addr (control): 10.10.50.44
  ipv4 addr (game): 10.10.50.44
  password: 2n0A1db40MYy3DdDPdd7
  Registering windows on dc2
  ipv4 addr (control): 10.10.50.114
  ipv4 addr (game): 10.10.50.114
  password: wS8cVHIjJBHyN65vchwi
  Registering windows on winep1
  ipv4 addr (control): 10.10.50.195
  ipv4 addr (game): 10.10.50.195
  password: yolcnB2f1arqlaLXByld
```

**THESE PASSWORDS ARE VERY IMPORTANT.**  Below is a table of the hosts and their corrsponding passwords according to
this output:

| hostname | password             |
|----------|----------------------|
| dc1      | 2n0A1db40MYy3DdDPdd7 |
| dc2      | wS8cVHIjJBHyN65vchwi |
| winep1   | yolcnB2f1arqlaLXByld |

**For each of these hosts**, do the following:

1. Log in to the host:
   ```commandline
   ssh -l administrator <hostname>
   ``` 

2. Enter the password for the host when prompted.

3. A command-prompt will execute once you've logged in to the host.  Execute a powershell by executing the
   `powershell` command:
   ```commandline
   powershell
   ```
4. Execute the `ipconfig command`:
   ```commandline
   ipconfig
   ```
   It will render output similar to the following:
   ```commandline
   Windows IP Configuration


   Ethernet adapter <NETADAPTER NAME>:

      Connection-specific DNS Suffix  . : <DNS SUFFIX>
      Link-local IPv6 Address . . . . . : XXXX::XXXX:XXXX:XXXX:XXXX%4
      IPv4 Address. . . . . . . . . . . : XXX.XXX.XXX.XXX
      Subnet Mask . . . . . . . . . . . : XXX.XXX.XXX.XXX
      Default Gateway . . . . . . . . . : XXX.XXX.XXX.XXX
   ```

5. Using the `<NETADAPTER-NAME>` from the output of the `ipconfig` command above, execute the following command:
   ```commandline
   rename-netadapter -name <NETADAPTER-NAME> -newname "Ethernet Instance 0"
   ```

6. Enter the `exit` command to exit the powershell:
   ```commandline
   exit
   ```

7. Enter the `exit` command again to exit the command-prompt and log out of the host:
   ```commandline
   exit
   ```


* Run `post-deploy.py` to get a `post-deploy-output.json`.  
Use a enterprise configuration file that matches the VU deployment you wish to run the workflow on.
(E.g. cage2-ssh for the ssh workflow, or cage2-shib for the shib and Moodle workflows.)
Run `clean-nodes.py` to remove all nodes.

* Clone `git@github.com:CASTLEGym/castle-vm.git`.  

* Check out the `develop` branch, follow the README to deploy and provision the CAGE2 environment (including the UVA workflow stacks).
Make sure you follow the section at the end of the README about deploying workflows.

* Log into the "workflow" VM, and clone this repository.

* Copy the post-deploy-output.json from the first step to the workflow VM.  Modify it such that the addresses 
array matches the CAGE2 addresses assigned in the heat template. This modification can be done manually
by adding the control and game IPs to the addresses array in the JSON for each machine in the game.  
For cage2, this can be done with the convenience script called `convert-to-vu-cage2.py`.
```
cd /path/to/uva-workflows
./convert-to-vu-cage2.py ../../castle-vm/CreateVMs/VelociraptorVMs/secrets/castle-control
cd /path/to/castle-vm
ssh-keygen -f "/home/jdh8d/.ssh/known_hosts" -R "workflow.castle.os"
scp -i CreateVMs/VelociraptorVMs/secrets/castle-control CreateVMs/VelociraptorVMs/secrets/castle-control ubuntu@workflow.castle.os:~/.ssh
scp -i CreateVMs/VelociraptorVMs/secrets/castle-control ~/.ssh/id_rsa ubuntu@workflow.castle.os:~/.ssh
scp -i CreateVMs/VelociraptorVMs/secrets/castle-control ../uva_workflows/uva-cs-auth-workflow-openstack/deploy-output-vu-cage2.json ubuntu@workflow.castle.os:~/deploy-output.json 
ssh -i CreateVMs/VelociraptorVMs/secrets/castle-control ubuntu@workflow.castle.os
git clone git@github.com:jdhiser/uva-cs-auth-workflow-openstack.git workflow
mv deploy-output.json  workflow
cd workflow
git checkout -b pi_meeting_oct_2024
./setup.sh
mv ~/.ssh/castle-control ~/.ssh/id_rsa
./post-deploy.py deploy-output.json

```


* Set up DNS entries for the key machines (dc1.castle.os, service.castle.os, identity.castle.os).  DNS 
entries should point at the game addresses, not the control addresses.  
(TODO: Automate this leverage the the heat templates from the castle-vm repo.  
While I can do this with designate automatically, I'm not sure that works for VU yet.)

* Run post-deploy.py with the modified post-deploy-output.json to configure the HEAT-template deployed nodes.  

* Simulate and emulate logins from the workflow VM as per normal (described above).

# Debugging

It's python code, debug with your favorite debugger.  However, it's worth noting that 
most files have a "verbose" global variable so you can turn on verbose logging output 
for that file only.  Further, there is a `use_parallel` in the post-deploy script to 
sequentialize the deployment of nodes, which makes the verbose output much clearer.

Almost all input/output from remote machines is captured to the output file of every step.
You can load the output file into any JSON viewer (recommend something like Firefox)
and browse to output for each step.  These outputs can help diagnose connection issues,
etc.

