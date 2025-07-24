from shell_handler import ShellHandler

verbose = False

# human_plugin_version = "Downloads/pyhuman-moodle.zip"
human_plugin_version = "Downloads/workflows.zip"


def node_to_default_user(node):
    user = ""
    if 'windows' in node['roles']:
        user = 'Administrator'
    elif 'centos7' in node['roles']:
        user = 'centos'
    elif 'centos9' in node['roles']:
        user = 'cloud-user'
    elif 'linux' in node['roles']:
        user = 'ubuntu'
    else:
        print(f"Cannot map roles to user name.  Roles={node['roles']}")
    return user


def install_human_windows(node, user, control_ipv4_addr, password, cloud_config):
    stdout = []
    stderr = []
    exit_status = []
    return {"node": node, "stdout": stdout, "stderr": stderr, "exit_status": exit_status}


def install_human_linux(node, user, control_ipv4_addr, password, cloud_config):
    print(f"Installing human plugin support as user {user} on node {node['name']} ")
    shell = ShellHandler(control_ipv4_addr, user, password=None, verbose=verbose, retries=1)
    shell.put_file(human_plugin_version, '/tmp/pyhuman.zip')

    enterprise_url = cloud_config['enterprise_url']

    packages = 'python3 python3-pip virtualenv xvfb unzip build-essential git autotools-dev autoconf libncursesw5-dev libtool autoconf automake bison flex libevent-dev ncurses-dev golang-go ninja-build gettext libtool libtool-bin autoconf automake cmake g++ pkg-config unzip curl doxygen gnutls-dev libgnutls28-dev pkg-config build-essential groff-base libpipeline-dev libgdbm-dev groff libtool m4 xz-utils lzip'
    cmd = f"""
        set -x
        sudo rm -rf /opt/pyhuman
        sudo mkdir -p /opt/pyhuman
        cd /opt/pyhuman
        sudo env DEBIAN_FRONTEND=noninteractive apt update
        sudo env DEBIAN_FRONTEND=noninteractive apt install -y {packages}
        sudo unzip /tmp/pyhuman.zip
        sudo sed -i "s/castle.os/{enterprise_url}/" /opt/pyhuman/app/workflows/browse_shibboleth.py /opt/pyhuman/app/workflows/moodle.py
        sudo sed -i "s/project1.os/{enterprise_url}/" /opt/pyhuman/app/workflows/browse_shibboleth.py /opt/pyhuman/app/workflows/moodle.py
        sudo virtualenv -p python3 /opt/pyhuman
        sudo /opt/pyhuman/bin/python3 -m pip install -r requirements.txt
        cd /tmp
        if ! which google-chrome > /dev/null 2>&1
        then
            sudo wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
            sudo dpkg -i google-chrome-stable_current_amd64.deb
        fi
        sudo env DEBIAN_FRONTEND=noninteractive apt install -f -y
        sudo rm -f /tmp/pyhuman.zip /tmp/*.deb
        sudo chmod 777 /home
    """

    stdout, stderr, exit_status = shell.execute_bash_multiline(cmd, filename="install_human", verbose=verbose)

    return {"node": node, "stdout": stdout, "stderr": stderr, "exit_status": exit_status}


def deploy_human(obj):
    cloud_config = obj['cloud_config']
    node = obj['node']
    user = node_to_default_user(node)
    control_ipv4_addr = obj['control_addr']
    password = obj['password']

    if user == "Administrator":
        return install_human_windows(node, user, control_ipv4_addr, password, cloud_config)
    elif user == "ubuntu":
        return install_human_linux(node, user, control_ipv4_addr, password, cloud_config)
    else:
        msg = (f"No information for how to install human on node with username='{user}'")
        print(msg)
        return msg
