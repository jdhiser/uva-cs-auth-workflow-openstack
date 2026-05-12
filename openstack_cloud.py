import argparse
import os
import time
from keystoneauth1.identity import v3
from keystoneauth1 import session
from novaclient import client as nova_client
from designateclient.v2 import client as designate_client
from collections import defaultdict
from neutronclient.v2_0 import client as neutronclient
import glanceclient
import openstack
from openstack import exceptions as os_exc
import re
from joblib import Parallel, delayed


class OpenstackCloud:

    def __init__(self, cloud_config):
        self.cloud_config = cloud_config
        self.conn = None
        self.network_name = None
        self.project_id = os.environ.get('OS_PROJECT_ID')
        self.project_name = os.environ.get('OS_PROJECT_NAME')
        self.verify = 'OS_CACERT' in os.environ
        self.enterprise_url = None

        self.sess = self.get_session()
        self.nova_sess = nova_client.Client(version=2.4, session=self.sess)
        self.servers = self.query_servers()
        self.glclient = glanceclient.Client(version="2", session=self.sess)
        self.neutronClient = neutronclient.Client(session=self.sess)
        self.designateClient = designate_client.Client(session=self.sess)

    def get_session(self):
        options = argparse.ArgumentParser(description='Awesome OpenStack App')
        self.conn = openstack.connect(options=options, verify=self.verify)

        project = self.conn.identity.find_project(self.project_id)
        self.project_name = project.name
        self.enterprise_url = f"{self.project_name.lower()}.os"

        self.cloud_config['enterprise_url'] = self.enterprise_url

        """Return keystone session"""

        # Extract environment variables set when sourcing the openstack RC file.
        user_domain = os.environ.get('OS_USER_DOMAIN_NAME')
        user = os.environ.get('OS_USERNAME')
        password = os.environ.get('OS_PASSWORD')
        auth_url = os.environ.get('OS_AUTH_URL')

        # Create user / password based authentication method.
        # https://goo.gl/VxD2FQ
        auth = v3.Password(user_domain_name=user_domain,
                           username=user,
                           password=password,
                           project_id=self.project_id,
                           project_name=self.project_name,
                           auth_url=auth_url)

        # Create OpenStack keystoneauth1 session.
        # https://goo.gl/BE7YMt
        sess = session.Session(auth=auth, verify=self.verify)

        return sess

    def query_servers(self):
        """Query list of servers.
        Returns a dictionary of server dictionaries with the key being the
        server name
        """
        servers = defaultdict()
        nova_servers = self.nova_sess.servers.list()

        for idx, server in enumerate(nova_servers):
            server_dict = server.to_dict()
            servers[server_dict['name']] = server_dict
        return servers

    def find_zone(self):
        zones = self.designateClient.zones.list()
        for zone in zones:
            if zone['name'] == f"{self.enterprise_url}.":
                return zone
        return None

    def check_deploy_ok(self, enterprise):
        zone = self.find_zone()
        if zone is not None:
            print(f"Zone {self.enterprise_url} already exists as: {zone}.")
            return False

        server_name_set = {x['name'].strip() for x in self.servers.values()}
        deploy_name_set = {x['name'].strip() for x in enterprise['nodes']}
        deployed_name_set = deploy_name_set.intersection(server_name_set)
        if len(deployed_name_set) != 0:
            for name in deployed_name_set:
                print(f"Found that server {name} already exists.")
            return False
        return True

    def query_deploy_ok(self, enterprise):
        zone = self.find_zone()
        if zone is None:
            print(f"Zone does not exist. Creating: {self.enterprise_url}.")
            self.designateClient.zones.create(f"{self.enterprise_url}.", email="root@" + self.enterprise_url)
        else:
            print(f"Zone \"{self.enterprise_url}\" exists.  Deleting and re-creating ...")
            self.designateClient.zones.delete(self.enterprise_url + ".")
            while self.find_zone() is not None:
                time.sleep(30)
            self.designateClient.zones.create(f"{self.enterprise_url}.", email="root@" + self.enterprise_url)

        server_name_set = {x['name'].strip() for x in self.servers.values()}
        deploy_name_set = {x['name'].strip() for x in enterprise['nodes']}
        undeployed_name_set = deploy_name_set - server_name_set
        if len(undeployed_name_set) != 0:
            for name in undeployed_name_set:
                print(f"Found that server {name} does not exist.")
                return False
        return True

    def os_to_image(self, os_name):

        if os_name not in self.cloud_config['image_map']:
            return os_name
        return self.cloud_config['image_map'][os_name]

    def size_to_flavor(self, size_name):
        if 'instance_size_map' not in self.cloud_config:
            return size_name

        return self.cloud_config['instance_size_map'].get(size_name, size_name)

    def find_image_by_name(self, name, for_node=None):
        images = self.glclient.images.list()
        found_image = None
        for image in images:
            if image['name'] == name and found_image is None:
                found_image = image
            elif image['name'] == name and found_image is not None:
                str_value = "Duplicate images named " + name
                raise NameError(str_value)
        if found_image is None:
            str_value = "Image not found: " + name
            raise NameError(str_value)
        prefix = f"[{for_node}] " if for_node else ""
        print(f"  {prefix}Found image '{name}' id: {found_image['id']}")
        return found_image

    def get_network_id(self, name_or_id):
        """
        Resolve a Neutron network's UUID from a name or UUID.
        Returns the UUID string, or None if not found.
        Lookup order:
          1) Heat resource map (if a stack resource matches exactly)
          2) Direct UUID lookup (if it looks like a UUID)
          3) Name lookup via the Network proxy
        """
        # 1) Try Heat stack resources that belong to this project and are prefixed with the project name
        project = self.conn.identity.find_project(self.project_id)
        project_name = project.name

        stack_resource_map = {
            stack.name: list(self.conn.orchestration.resources(stack.name))
            for stack in self.conn.list_stacks()
            if stack.location.project.id == self.project_id and stack.name.startswith(f"{project_name}_")
        }

        for resource_list in stack_resource_map.values():
            for resource in resource_list:
                # If the caller passed the logical resource id from Heat, match it
                if resource.id == name_or_id and getattr(resource, "physical_resource_id", None):
                    return resource.physical_resource_id

        # 2) If it looks like a UUID, try a direct lookup-by-id
        uuid_like = re.compile(r"^[0-9a-fA-F-]{36}$")
        if uuid_like.match(name_or_id):
            try:
                net = self.conn.get_network_by_id(name_or_id)
                if net:
                    # net may be dict-like or a resource; normalize to string id
                    return getattr(net, "id", net.get("id"))
            except os_exc.ResourceNotFound:
                # fall through to name lookup
                pass

        # 3) Use the modern network proxy to resolve by name (or id)
        # Prefer strict lookup first
        try:
            net = self.conn.network.find_network(name_or_id, ignore_missing=False)
            return net.id
        except os_exc.ResourceNotFound:
            # Try a broader search (exact name match among all visible networks)
            matches = [n for n in self.conn.network.networks(name=name_or_id)]
            if len(matches) == 1:
                return matches[0].id
            elif len(matches) > 1:
                # Prefer a unique shared/external network if possible
                def is_shared_or_external(n):
                    # neutron attrs: "router:external" can be on .is_router_external or in .to_dict()
                    ext = getattr(n, "is_router_external", None)
                    if ext is None:
                        ext = n.to_dict().get("router:external", False)
                    return getattr(n, "is_shared", False) or bool(ext)

                shared_ext = [n for n in matches if is_shared_or_external(n)]
                if len(shared_ext) == 1:
                    return shared_ext[0].id
                # Ambiguous
                names = ", ".join(f"{n.name}({n.id})" for n in matches)
                raise RuntimeError(f"Multiple networks match '{name_or_id}': {names}. Please specify the UUID.")
            else:
                return None

    def find_network_by_name(self, name, for_node=None):
        ret = self.neutronClient.list_networks()
        networks = ret['networks']
        found_network = None
        for network in networks:
            found = network['id'] == name or network['name'] == name
            if found and found_network is None:
                found_network = network
            elif found and found_network is not None:
                str_value = f"Duplicate networks named {name}"
                raise NameError(str_value)
        if found_network is None:
            str_value = f"Network not found: {name}"
            raise NameError(str_value)
        prefix = f"[{for_node}] " if for_node else ""
        print(f"  {prefix}Found network '{name}' id: {found_network['id']}")
        return found_network

    def create_nodes(self, enterprise, ret, parallel=10):
        """
        Create all enterprise nodes via Nova. With `parallel > 1`, runs up to
        `parallel` create_server calls concurrently via joblib (threading
        backend), since each call is dominated by API-call latency + the
        defensive 30-second sleep after submission.

        Hoists the security-group validation out of the per-node loop (it's
        constant across nodes) so we don't re-list groups per node.
        """

        ret['nodes'] = []

        if not ret['check_deploy_ok']:
            errstr = "  Found that one or more nodes already exist, aborting deploy."
            raise RuntimeError(errstr)

        # Validate security group once — same for every node.
        security_group = self.cloud_config['security_group']
        all_groups = self.conn.list_security_groups()
        project_groups = [x for x in all_groups if x.name == security_group or x.id == security_group]
        if not len(project_groups) == 1:
            errstr = "Found 0 or more than 1 security groups called " + security_group + "\n" + str(project_groups)
            raise RuntimeError(errstr)

        keypair = self.cloud_config['keypair']

        def _create_one(node):
            name = node['name']
            print("Creating node named " + name)
            os_name = node['os']
            size = node.get('size', "small")
            domain = node.get('domain', "")

            image = self.os_to_image(os_name)
            flavor = self.size_to_flavor(size)

            network = node.get('network', self.cloud_config['external_network'])

            nova_image = self.find_image_by_name(image, for_node=name)
            nova_net = self.find_network_by_name(network, for_node=name)
            self.network_name = nova_net['name']
            nova_nics = [{'net-id': nova_net['id']}]
            nova_instance = self.conn.create_server(
                name=name,
                image=image,
                flavor=flavor,
                key_name=keypair,
                security_groups=[security_group],
                nics=nova_nics
            )
            time.sleep(30)
            print("  [" + name + "] Server has id " + nova_instance.id)
            nova_instance = self.nova_sess.servers.get(nova_instance.id)
            return {
                'name': name,
                'flavor': flavor,
                'size': size,
                'os': os_name,
                'domain': domain,
                'image': image,
                'security_group': security_group,
                'network': network,
                'keypair': keypair,
                'nova_image': nova_image,
                'nova_nics': nova_nics,
                'is_ready': False,
                'nova_status': nova_instance.status,
                'id': nova_instance.id,
                'enterprise_description': node
            }

        nodes = enterprise['nodes']
        if parallel and parallel > 1 and len(nodes) > 1:
            print(f"Creating {len(nodes)} nodes with up to {parallel} in parallel...")
            results = Parallel(n_jobs=min(parallel, len(nodes)), backend="threading")(
                delayed(_create_one)(node) for node in nodes
            )
        else:
            results = [_create_one(node) for node in nodes]

        ret['nodes'] = list(results)
        return ret

    def query_nodes(self, enterprise, ret):

        ret['nodes'] = []

        if not ret['check_deploy_ok']:
            errstr = "  Found that one or more nodes already exist, aborting deploy."
            raise RuntimeError(errstr)

        for node in enterprise['nodes']:
            name = node['name']
            print("Querying node named " + name)
            os_name = node['os']
            size = node.get('size', "small")
            domain = node.get('domain', "")
            keypair = self.cloud_config['keypair']

            image = self.os_to_image(os_name)
            flavor = self.size_to_flavor(size)
            security_group = self.cloud_config.get('security_group', '')
            if security_group:
                all_groups = self.conn.list_security_groups()
                project_groups = [
                    x for x in all_groups
                    if (x.location.project.id == self.project_id and x.name == security_group) or x.id == security_group
                ]
                if not len(project_groups) == 1:
                    print(f"[warn] Expected exactly 1 security group called '{security_group}', "
                          f"found {len(project_groups)}; continuing anyway")

            network_name = node.get('network', self.cloud_config['external_network'])

            nova_image = self.find_image_by_name(image, for_node=name)
            # nova_flavor = self.nova_sess.flavors.find(name=flavor)

            network_id = self.get_network_id(network_name)
            if network_id is None:
                raise Exception(f"Could not find network id for \"{network_name}\" network.")

            nova_nics = [{'net-id': network_id}]
            nova_instance = self.servers[name]
            print("  [" + name + "] Server has id " + nova_instance['id'])
            # print(dir(nova_instance))
            new_node = {
                'name': name,
                'flavor': flavor,
                'size': size,
                'os': os_name,
                'domain': domain,
                'image': image,
                'security_group': security_group,
                'network': network_name,
                'keypair': keypair,
                'nova_image': nova_image,
                'nova_nics': nova_nics,
                'is_ready': False,
                'nova_status': nova_instance['status'],
                'id': nova_instance['id'],
                'enterprise_description': node
            }
            ret['nodes'].append(new_node)
        return ret

    def wait_for_ready(self, ret):
        """
        Wait up to 10 minutes for all nodes to reach ACTIVE.
        Returns ret even if timeout is reached.
        """

        waiting = True
        while waiting:

            print("Waiting for instances to be ready. Sleeping 30 seconds...")
            time.sleep(30)

            waiting = False

            for node in ret['nodes']:
                if node.get('is_ready') is None:
                    continue

                id_value = node['id']
                nova_instance = self.nova_sess.servers.get(id_value)
                node['nova_status'] = nova_instance.status

                if nova_instance.status == 'ACTIVE':
                    print("Node " + node['name'] + " is ready!")
                    node['is_ready'] = True
                elif nova_instance.status == 'BUILD':
                    waiting = True
                else:
                    errstr = (
                        f"Node {node['name']} is neither BUILDing nor ACTIVE. "
                        "Assuming error has occurred."
                    )
                    raise RuntimeError(errstr)

        print("All nodes are ready")
        return ret

    def collect_info(self, enterprise, enterprise_built):
        ret = enterprise_built
        start_time = time.time()
        for node in enterprise_built['nodes']:
            id_value = node['id']
            name = node['name']
            enterprise_node = next(filter(lambda x: name == x['name'], enterprise['nodes']))
            nova_instance = self.nova_sess.servers.get(id_value)
            network_name = self.cloud_config['external_network']

            address_list = []
            for key, value in nova_instance.addresses.items():

                new_value = [address for address in value if address['OS-EXT-IPS:type'] == 'fixed']
                if key == network_name:
                    address_list.insert(0, new_value[0])
                else:
                    address_list.append(new_value[0])

            node['addresses'] = address_list

            if 'windows' not in enterprise_node['roles']:
                print("Skipping password retrieve for non-windows node " + name)
                continue

            timeout_seconds = 10 * 60  # 10 minutes
            while True:
                # Timeout check
                elapsed = time.time() - start_time
                if elapsed >= timeout_seconds:
                    print("Timeout waiting for nodes to become ready. Hoping we can log in with a key.")
                    break
                nova_instance = self.nova_sess.servers.get(id_value)
                node['password'] = nova_instance.get_password(private_key=self.cloud_config['private_key_file'])
                if node['password'] == '':
                    print("Waiting for password for node " + name + ".")
                    time.sleep(30)
                else:
                    break

        return ret

    def create_zones(self, ret):
        print("Creating DNS zone " + self.enterprise_url)
        ret['create_zones'] = \
            self.designateClient.zones.create(self.enterprise_url + ".", email="root@" + self.enterprise_url, ttl=60)
        return ret

    def query_zones(self, ret):
        print("Querying DNS zone " + self.enterprise_url)
        ret['create_zones'] = self.designateClient.zones.get(f"{self.enterprise_url}.")
        return ret

    def create_dns_names(self, ret):
        zone = ret['create_zones']['id']

        for node in ret['nodes']:
            to_deploy_name = node['name']
            addresses = node['addresses']

            # The DNS records must contain the GAME addresses (if they exist).
            # Otherwise, any time an end point tries to refer to the node, it will use
            # The control address, and send all the data over the control network.
            address = addresses[-1]['addr']
            print(f"Creating DNS zone {to_deploy_name}.{self.enterprise_url} = {address} ")
            try:
                node['dns_setup'] = self.designateClient.recordsets.create(zone, to_deploy_name, 'A', [address])
            except designate_client.exceptions.Conflict as _:  # noqa: F841
                print(f"WARNING:  already a DNS record for {to_deploy_name}")
        return ret

    def deploy_enterprise(self, enterprise, parallel=10):
        for i in range(100):
            try:
                ret = {'check_deploy_ok': self.check_deploy_ok(enterprise)}
                break
            except Exception:
                pass

        if not ret['check_deploy_ok']:
            errstr = "Found that deploying the network will conflict with existing setup."
            raise RuntimeError(errstr)
        ret = self.create_zones(ret)
        ret = self.create_nodes(enterprise, ret, parallel=parallel)
        ret = self.wait_for_ready(ret)
        ret = self.collect_info(enterprise, ret)
        ret = self.create_dns_names(ret)
        return ret

    def query_enterprise(self, enterprise):
        ret = {'check_deploy_ok': self.query_deploy_ok(enterprise)}
        if not ret['check_deploy_ok']:
            errstr = "Found that the network is not fully deployed."
            raise RuntimeError(errstr)
        ret = self.query_zones(ret)
        ret = self.query_nodes(enterprise, ret)
        ret = self.collect_info(enterprise, ret)
        ret = self.create_dns_names(ret)
        return ret

    def cleanup_enterprise(self, enterprise):
        zone = self.find_zone()
        if zone is not None:
            self.designateClient.zones.delete(zone['id'])

        for node in enterprise['nodes']:
            to_deploy_name = node['name']
            for instance_key in self.servers:
                instance_name = self.servers[instance_key]['name']
                if to_deploy_name.strip() == instance_name.strip():
                    print("Removing server " + instance_name + ".")
                    self.nova_sess.servers.delete(self.servers[instance_key]['id'])
