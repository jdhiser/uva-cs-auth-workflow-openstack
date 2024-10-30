

# Configuraiton Documentation

## Top level items
 * `cloud_type` - string.  The backend type used for creating an enterprise.  Must be one of "openstack".

 * `os_env_file` - string.  The full path to a file that sets the environment to be able to access an openstack project.  
This file is `source`d (i.e., ran in the current shell) to set the environment.  It can just set env variables (prefered)
or prompt the user for things like passwords (less preferred), etc.

 * `private_key_file` - string.  The path to the private key used in keypair (as listed below).

 * `external_network` - string.  The openstack network to use to create the deployed nodes.  It is assumed
 that this network can access the internet for deploying packages, etc.  It is also assumed that the DNS
 settings for this network can access the Designate-provided DNS records in openstack.  Further, it is assumed
 that the workflow manager can access this network with direct SSH access.

 * `keypair` - string. The openstack keypair to be installed in the node.  It is assumed that the paramiko ssh client can
 access the private key for this keypair in the standard way.  If the key is not in a place where `ssh` can typically
 access, you can use `ssh-agent` to import the key thusly:

	```
	eval $(ssh-agent)
	ssh-add /path/to/key
	```

 * `image_map` - object.  This object maps high-level image types to openstack image names.

 * `instance_size_map` - object.  This object maps high-level instance size names to openstack flavor names.

 * `security-group` - string. The security group to use when creating nodes.  It is recommended that you create a rule
 where all traffic is allowed, but at a minimum, SSH, HTTP, HTTPS, LDAP and Active Directory must be allowed.

 * `enterprise_url` - string.  The url for your enterprise that's used to create a domain.
 For now, recommend that this stays as `castle.os` due to pre-built images having this hard-coded in several places.


##  Sub-fields



# Sample files

* `mtx.json` - config for mega-techx1 as administrator.
* `shen.json` - config for shen-23 as administrator.
* `shen-proj1.json` - config for shen-23 as project 1.
