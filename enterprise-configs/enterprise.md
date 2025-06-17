

# Configuraiton Documentation

## Top level items

 * `os_env_file` - string.  The full path to a file that sets the environment to be able to access an openstack project.  
This file is `source`d (i.e., ran in the current shell) to set the environment.  It can just set env variables (prefered)
or prompt the user for things like passwords (less preferred), etc.


* `nodes` - array of node.  The list of nodes to be allocated.  See subfield `node`.


##  Sub-fields

* `node` - object.  Subfields are:
**  a `name` - string.The name of the node. (required)
** an `os` - string. Specify the os to use. (required)
** `domain` - string. the windows domain that the machine should join, or no domain if the file is empty. (optional)
** `size` - string. the size of an instance.

* `name` - string.  THe name of an object.

* `os` - string. The name of an os, must be one of `win2k22`, `jammy`.

* `domain` - string. The name of the Windows domain that the node should join.

* 'size' - string. The size of parent opbject.

* `roles` - array of string.  The roles this machine should play.  
** `windows` -- register the instance with skms.  Specifies logins should be via password.
** `domain_controller_leader` -- install a domain controller with a new forest for active directory.
** `domain_controller` -- join an existing domain (requires a domain_controller_leader.
** `linux` -- specifies login should be via ssh key for Ubuntu 22/Jammy.
** `centos7` -- specifies login should be via ssh key for CentOS 7.
** `endpoint` -- specifies that this is an endpoint that should have human emulation.
** `idp` -- specifies that this machine is an Identity Provider.  Shibboleth will be configured.
** `sp` -- specifies that this machine is a Service Provider.  Shib. and Moodle will be configured.
** `fs` -- specifies that this machine is a file server.  endpoint nodes will be configured to 
   mount domain-users' home directories.  The domain specified here much match the endpoint's domain.


# Sample Files

* `enterprise-tiny.json` -  Sample enterprise with the smallest number of nodes possible to demonstrate a domain controller (DC).
* `enterprise-med.json` -  Sample enterprise with a modest number of nodes possible to demonstrate a DC.
* `enterprise-large.json` -  Sample enterprise with the largest number of nodes possible to demonstrate a DC, possibly representing a small workplace.

* `cage2.json` - The CyBORG CAGE Challenge 2 configuration, enhanced with 2 DCs to demonstrate an authentication workflow.
* `enterprise-dcstress.json` - a bunch of DCs configured to stress test the setup tools.
* `shib-only.json` - A sample with DCs and a shibboleth Identity Provider (IdP) and Service Provider (SP).
* `dc-only.json` - A sample with only DCs to test that domain controller setup is successful.
* `web-wf.json` - A sample workflow with DCs, IdP and SP, along with end points to test the web authentication workflow.

