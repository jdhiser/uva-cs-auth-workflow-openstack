from shell_handler import ShellHandler

verbose = False

human_plugin_version="Downloads/pyhuman-moodle.zip"


def node_to_default_user(node):
    user = ""
    if 'windows' in node['roles']:
        user='Administrator'
    elif 'centos7' in node['roles']:
        user='centos'
    elif 'centos9' in node['roles']:
        user='cloud-user'
    elif 'linux' in node['roles']:
        user='ubuntu'
    else:
        print(f"Cannot map roles to user name.  Roles={node['roles']}")
    return user

def install_human_windows(node,user,control_ipv4_addr,password, cloud_config):
    stdout=[]
    stderr=[]
    exit_status=[]
    return {"node": node, "stdout": stdout, "stderr": stderr, "exit_status": exit_status}

def install_human_linux(node,user,control_ipv4_addr,password, cloud_config):
    print(f"Installing as user {user}")
    shell = ShellHandler(control_ipv4_addr,user,password, verbose=verbose)
    shell.put_file(human_plugin_version, '/tmp/pyhuman.zip')

    enterprise_url=cloud_config['enterprise_url']

    cmd=(
        'set -x ;' +
        'sudo rm -rf /opt/pyhuman; ' + 
        'sudo mkdir -p /opt/pyhuman; ' + 
        'cd /opt/pyhuman; ' + 
        'sudo env DEBIAN_FRONTEND=noninteractive apt install -y python3 python3-pip virtualenv xvfb unzip; ' +
        'sudo unzip /tmp/pyhuman.zip; ' + 
        'sudo sed -i "s/castle.os/{}/" /opt/pyhuman/app/workflows/browse_shibboleth.py /opt/pyhuman/app/workflows/moodle.py ;'.format(enterprise_url) + 
        'sudo virtualenv -p python3 /opt/pyhuman;'
        'sudo /opt/pyhuman/bin/python3 -m pip install -r requirements.txt; ' +
        'cd /tmp; ' + 
        'sudo wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb; ' +
        'sudo dpkg -i google-chrome-stable_current_amd64.deb; ' +
        'sudo env DEBIAN_FRONTEND=noninteractive apt install -f -y; ' +
        'sudo rm /tmp/pyhuman.zip /tmp/*.deb;'   +
        'sudo chmod 777 /home '
    )

    stdout,stderr,exit_status = shell.execute_cmd(cmd)


    return {"node": node, "stdout": stdout, "stderr": stderr, "exit_status": exit_status}

def deploy_human(obj):
    cloud_config=obj['cloud_config']
    node=obj['node']
    user=node_to_default_user(node)
    control_ipv4_addr=obj['control_addr']
    password=obj['password']

    if user == "Administrator":
        return install_human_windows(node,user,control_ipv4_addr,password,cloud_config)
    elif user == "ubuntu":
        return install_human_linux(node,user,control_ipv4_addr,password,cloud_config)
    else:
        msg=(f"No information for how to install human on node with username='{user}'")
        print(msg)
        return msg


