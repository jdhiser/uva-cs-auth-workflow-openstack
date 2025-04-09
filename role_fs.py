
import time
from shell_handler import ShellHandler
# from password import generate_password


verbose = True


def setup_fileserver(obj):
    cloud_config = obj['cloud_config']
    node = obj['node']
    name = node['name']
    domain_name = obj['domain']
    enterprise_name = cloud_config['enterprise_url']
    fqdn_domain_name = domain_name + '.' + enterprise_name
    leader = obj['domain_leader']
    leader_admin_password = leader['admin_pass']
    game_leader_addrs = leader['game_addr']
    control_ipv4_addr = obj['control_addr']
    game_ipv4_addr = obj['game_addr']
    password = obj['password']
    roles = node['roles']
    islinux = len(list(filter(lambda role: 'linux' == role, roles))) == 1

    domain_ips = str(game_leader_addrs).replace("[", "").replace(']', '').replace("'", '"')

    if islinux:
        print("Linux setting up fileserver on node " + name)
        return setup_fileserver_linux(name, leader_admin_password, control_ipv4_addr, game_ipv4_addr, domain_ips, fqdn_domain_name, domain_name, password, enterprise_name)
    else:
        errstr = "  No filesystem setup for node " + name
        raise RuntimeError(errstr)


def setup_fileserver_linux(name, leader_admin_password, control_ipv4_addr, game_ipv4_addr, domain_ips, fqdn_domain_name, domain_name, password, enterprise_name):
    netplan_config_path = '/etc/netplan/50-cloud-init.yaml'
    chrony_config_path = '/etc/chrony/chrony.conf'
    domain_ips_formated = str(domain_ips).replace('[', '').replace(']', '').replace('"', '')
    domain_ips_space_sep = domain_ips_formated.replace(",", " ")

    cmd = f"""
bash << 'EOT' 2>&1 | sudo tee -a /var/log/fileserver_setup.log
set -x
sudo apt update && sudo env DEBIAN_FRONTEND=noninteractive apt install -y dnsutils iputils-ping traceroute telnet tcpdump python-is-python3 chrony samba winbind krb5-user libnss-winbind libpam-winbind  ntpdate smbclient
sudo sed -i '/pool ntp.ubuntu.com        iburst maxsources 4/i pool {fqdn_domain_name}        iburst maxsources 5' {chrony_config_path}
sudo timedatectl set-timezone America/New_York
sudo systemctl enable chrony
sudo systemctl restart chrony

sudo sed -i '/dhcp4: true/a \            nameservers:\\n                addresses: [ {domain_ips_formated} ]' {netplan_config_path}
sudo netplan apply
sudo mkdir -p /srv/samba/homes
sudo chmod 0755 /srv/samba/homes
sudo tee /etc/samba/smb.conf << EOF
[global]
    username map = /etc/samba/user.map
    security = ads
    realm = {fqdn_domain_name.upper()}
    workgroup = {domain_name.upper()}
    idmap config * : backend = tdb
    idmap config * : range = 3000-7999
    idmap config {domain_name.upper()} : backend = rid
    idmap config {domain_name.upper()} : schema_mode = rfc2307
    idmap config {domain_name.upper()} : range = 100000-999999
    winbind use default domain = yes
    winbind enum users = yes
    winbind enum groups = yes
    template homedir = /srv/homedirs/%U
    template shell = /bin/bash
    kerberos method = secrets and keytab

[homes]
    comment = Home Directories
    path = /srv/homedirs/%U
    valid users = %S
    browseable = yes
    read only = no
    create mask = 0700
    directory mask = 0700
    root preexec = /usr/sbin/mkhomedir_helper %U
EOF

sudo tee /etc/nsswitch.conf << 'EOF'
passwd:         compat systemd winbind
group:          compat systemd winbind
shadow:         files
gshadow:        files

hosts:          files dns
networks:       fileF

protocols:      db files
services:       db files
ethers:         db files
rpc:            db files

netgroup:       nis
EOF

sudo ntpdate {fqdn_domain_name}

count=1
while ! sudo net ads join -U Administrator -S {fqdn_domain_name} --password {leader_admin_password}
do
    echo failed domain join, sleeping 5s and retrying
    sudo netplan apply
    sleep 5
    (( count ++ ))
    if (( count > 50 ))
    then
        echo domain join failed, not retrying.
        exit 1
    fi
done

echo {leader_admin_password} | kinit administrator@{fqdn_domain_name.upper()}
for i in {domain_ips_space_sep}
do
        nsupdate -g << EOF
        server $i
        update add {name}.{fqdn_domain_name}. 3600 A {game_ipv4_addr}
        send
        quit
EOF
done

sudo tee /etc/pam.d/common-session << EOF
session [default=1]     pam_permit.so
session requisite       pam_deny.so
session required        pam_permit.so
session required        pam_mkhomedir.so skel=/etc/skel umask=0077 home=/srv/homedirs/%u
session optional        pam_umask.so
session required        pam_unix.so
session optional        pam_winbind.so
session optional        pam_systemd.so
EOF

sudo systemctl restart smbd nmbd winbind

EOT
"""

    shell = ShellHandler(control_ipv4_addr, "ubuntu", None)
    stdout, stderr, exit_status = shell.execute_cmd(cmd, verbose=verbose)

    # wait for services to be ready.
    time.sleep(5)

    test_install = f"echo {leader_admin_password} | smbclient -L //localhost/ -U administrator"
    stdout2, stderr2, exit_status2 = shell.execute_cmd(test_install, verbose=verbose)

    if stdout2 is None or 'homes           Disk      Home Directories' not in str(stdout2):
        print("setup_filerserver_stdout:" + str(stdout))
        print("setup_filerserver_stderr:" + str(stderr))
        print("verify_fileserver_stdout:" + str(stdout2))
        print("verify_fileserver_stderr:" + str(stderr2))
        errstr = 'Cannot find fileserver share for home directories on ' + name
        raise RuntimeError(errstr)

    return {
        "setup_fileserver": {"setup-cmd": cmd, "stdout": stdout, "stderr": stderr, "exit_status": exit_status},
        "verify_fileserver": {"stdout": stdout2, "stderr": stderr2, "exit_status": exit_status2}
    }


def mount_home_directories_linux(obj):
    cloud_config = obj['cloud_config']
    node = obj['node']
    name = node['name']
    domain_name = obj['domain']
    enterprise_name = cloud_config['enterprise_url']
    fqdn_domain_name = domain_name + '.' + enterprise_name
    leader = obj['domain_leader']
    leader_admin_password = leader['admin_pass']
    # game_leader_addrs = leader['game_addr']
    control_ipv4_addr = obj['control_addr']
    # game_ipv4_addr = obj['game_addr']
    # password = obj['password']
    # roles = node['roles']
    # islinux = len(list(filter(lambda role: 'linux' == role, roles))) == 1
    fs_name = "fs"

    print(f"Setting up home directory mounts on {name} with admin_password={leader_admin_password}");

    cmd = f"""

bash << 'EOT' 2>&1 | sudo tee -a /var/log/mount_fileserver.log
set -x
## install and configure autofs/cifs
sudo apt update && sudo env DEBIAN_FRONTEND=noninteractive apt install autofs cifs-utils smbclient -y

sudo tee /etc/auto.master << 'EOF'
/home/{fqdn_domain_name.lower()} /etc/auto.home.sh --timeout=300 --ghost
EOF

sudo tee /etc/auto.home.sh << 'EOF'
#!/bin/bash
# Usage: /etc/auto.home.sh <username>
USER="$1"



echo "checking user, USER=$USER" >> /tmp/automount.log
if getent -s files passwd "$USER" >/dev/null 2>&1
then
        echo "Skipping local user, USER=$USER" >> /tmp/automount.log
        exit 0  # Skip mounting for local users
fi

# Get UID and GID from SSSD
myUID=$(id -u "$USER" 2>/dev/null)
myGID=$(id -g "$USER" 2>/dev/null)


echo "Detected domain user: USER=$USER, UID=$myUID, GID=$myGID" >> /tmp/automount.log
# Exit if user not found
[ -z "$myUID" ] && exit 1

# Define mount options
echo -fstype=cifs,vers=3.1.1,rw,sec=krb5,cruid=$myUID,noserverino,uid=$myUID,gid=$myGID,file_mode=0700,dir_mode=0700 ://{fs_name}.{fqdn_domain_name.lower()}/$USER

EOF


## Update sssd to use home dirs.

sudo cp /etc/sssd/sssd.conf  sssd.conf.bak

sudo tee /etc/sssd/sssd.conf << EOF
[sssd]
domains = {fqdn_domain_name.lower()}
config_file_version = 2
services = nss, pam

[domain/{fqdn_domain_name.lower()}]
default_shell = /bin/bash
krb5_store_password_if_offline = True
ldap_use_tokengroups = False
krb5_use_fast = try
dyndns_update = True
cache_credentials = True
krb5_realm = {fqdn_domain_name.upper()}
realmd_tags = manages-system joined-with-adcli
id_provider = ad
override_homedir = /home/%d/%u
fallback_homedir = /home/%d/%u
ad_domain = {fqdn_domain_name.lower()}
use_fully_qualified_names = False
ldap_id_mapping = True
access_provider = ad
krb5_auth_timeout = 60
EOF



sudo tee  /etc/pam.d/common-session << EOF
session [default=1]                     pam_permit.so
session requisite                       pam_deny.so
session required                        pam_permit.so
session optional                        pam_umask.so
session required                        pam_unix.so
session optional                        pam_sss.so
session optional                        pam_systemd.so
session optional                        pam_exec.so /usr/local/bin/wait_for_home.sh
EOF



sudo tee /usr/local/bin/wait_for_home.sh << 'EOF'
#!/bin/bash

show_message()
{'{'}
        logger -t "wait_for_home" "$1"
        echo -e "\nlogger: $1" >> /tmp/wait_for_home.log
{'}'}

main()
{'{'}

        # Get the username from PAM
        if [[ ! -z $PAM_USER ]]
        then
                USERNAME="$PAM_USER"
                # Fetch the home directory from /etc/passwd or SSSD/LDAP
                HOME=$(getent passwd "$USERNAME" | cut -d: -f6)
        else
                USERNAME=$USER
        fi

        if [[ $HOME != /home/castle* ]];
        then
                show_message "[ $(date) ] Skipping home dir check for local user."
                exit 0
        fi
        # Trigger autofs mount by accessing $HOME
        ls "$HOME" >/dev/null 2>&1
        # Wait until mounted (check every 1 second, timeout after 30 seconds)
        local timeout=30
        while [[ $timeout -gt 0 && ! -d "$HOME" ]]; do
                show_message "[ $(date) ] Waiting for home directory to mount."
                sleep 5
                ((timeout--))
        done

        if [[  -d "$HOME" ]]
        then
                show_message "[ $(date) ] Home directory successfully mounted."
                cd $HOME
                exit 0
        else
                show_message "[ $(date) ] Home directory not mounted, timed out."
                exit 1
        fi
{'}'}

main "$@"
EOF


sudo tee /etc/samba/smb.conf << 'EOF'

[global]
    security = ads
    realm = {fqdn_domain_name.upper()}
    workgroup = {domain_name.upper()}
    idmap config * : backend = tdb
    idmap config * : range = 3000-7999
    idmap config {domain_name.upper()} : backend = rid
    idmap config {domain_name.upper()} : schema_mode = rfc2307
    idmap config {domain_name.upper()} : range = 100000-999999
    winbind use default domain = yes
    winbind enum users = yes
    winbind enum groups = yes
    template homedir = /srv/homedirs/%U
    template shell = /bin/bash
    kerberos method = secrets and keytab
EOF


sudo tee /etc/krb5.conf << 'EOF'
[libdefaults]
    rdns=false
    default_realm = {fqdn_domain_name.upper()}
    kdc_timesync = 1
    ccache_type = 4
    proxiable = true
    dns_lookup_kdc = true
    dns_lookup_realm = false
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    default_ccache_name = KEYRING:persistent:%{'{'}uid{'}'}

    fcc-mit-ticketflags = true
    udp_preference_limit = 0
EOF


sudo chmod +x /usr/local/bin/wait_for_home.sh
sudo chmod +x /etc/auto.home.sh
echo {leader_admin_password} | kinit administrator@{fqdn_domain_name.upper()}



# trace cifs.upcall for cert. validation:

if [[ ! -e /usr/sbin/cifs.upcall.real ]]
then
    sudo mv /usr/sbin/cifs.upcall /usr/sbin/cifs.upcall.real
    sudo tee /usr/sbin/cifs.upcall <<EOF
#!/bin/bash
echo "\$@" >> /tmp/cifs.upcall.debug.log
export KRB5_TRACE=/tmp/krb5.trace.log.$$
exec /usr/sbin/cifs.upcall.real "\$@"
EOF
    sudo chmod +x /usr/sbin/cifs.upcall
fi

sudo systemctl restart autofs sssd
EOT
    """

    shell = ShellHandler(control_ipv4_addr, "ubuntu", None)
    stdout, stderr, exit_status = shell.execute_cmd(cmd, verbose=verbose)

    # wait for services to be ready.
    time.sleep(15)

    shell = ShellHandler(control_ipv4_addr, "administrator", leader_admin_password)

    test_setup = "pwd"
    stdout2, stderr2, exit_status2 = shell.execute_cmd(test_setup, verbose=verbose)

    if stdout2 is None or f'/home/{fqdn_domain_name.lower()}/administrator' not in str(stdout2):
        print("mount_home_directories_stdout:" + str(stdout))
        print("mount_home_directories_stderr:" + str(stderr))
        print("verify_home_directories_stdout:" + str(stdout2))
        print("verify_home_directories_stderr:" + str(stderr2))
        errstr = 'Cannot find fileserver share for home directories on ' + name
        raise RuntimeError(errstr)

    return {
        "setup_fileserver": {"setup-cmd": cmd, "stdout": stdout, "stderr": stderr, "exit_status": exit_status},
        "verify_fileserver": {"stdout": stdout2, "stderr": stderr2, "exit_status": exit_status2}
    }
