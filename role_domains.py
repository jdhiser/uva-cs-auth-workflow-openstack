import time
import socket
import paramiko
import role_fs
from shell_handler import ShellHandler
# from password import generate_password


domain_safe_mode_password = 'hello!321'  # generate_password(12)
verbose = False


def deploy_forest(cloud_config, name, control_ipv4_addr, game_ipv4_addr, password, domain):

    user = 'Administrator'
    domain_name = domain + '.' + cloud_config['enterprise_url']
    print("  Setting safe-mode password for domain to " + password)

    cmd = (
        "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\NtpServer /v Enabled /t REG_DWORD /d 1 /f; "
        "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters /v Type /t REG_SZ /d NTP /f; "
        "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Config /v AnnounceFlags /t REG_DWORD /d 5 /f; "
        "tzutil /s 'Eastern Standard Time' ;  "
        "w32tm /config /manualpeerlist:'pool.ntp.org,0x1' /syncfromflags:manual /reliable:yes /update; "
        "net stop w32time; "
        "net start w32time; "
        "w32tm /resync /force; "
        "w32tm /config /manualpeerlist:\"time.google.com 0.pool.ntp.org 1.pool.ntp.org\" /syncfromflags:manual /reliable:yes /update ;"
        "net stop w32time ;"
        "net start w32time ;"
        "w32tm /resync ;"
        "w32tm /query /status ;"
        "Install-windowsfeature AD-domain-services ; "
        "Import-Module ADDSDeployment ;  "
        "$secure=ConvertTo-SecureString -asplaintext -string {} -force ; "
        "Install-ADDSForest -domainname {} -SafeModeAdministratorPassword $secure -verbose -NoRebootOnCompletion:$true -Force:$true ; "
        "wget https://www.python.org/ftp/python/3.12.1/python-3.12.1-embed-amd64.zip -Outfile python.zip; "
        "Expand-Archive -force .\\python.zip; "
        "mv python c:\\ ; "
        "icacls \"c:\\python\" /grant:r \"users:(RX)\" /C ; "
        "$oldpath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path; "
        "$newpath = \"$oldpath;C:\python\" ; "
        "Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newpath "
    ).format(domain_safe_mode_password, domain_name)

    if verbose:
        print("  Register forest command:" + cmd)

    shell = ShellHandler(control_ipv4_addr, user, password)
    stdout, stderr, exit_status = shell.execute_powershell(cmd, verbose=verbose)
    try:
        shell.execute_powershell('Restart-computer -force', verbose=verbose)
    except socket.error:
        pass

    time.sleep(10)
    status_received = False
    attempts = 0
    while not status_received and attempts < 60:
        try:
            attempts += 1
            print("  Waiting for reboot of domain controller leader with ip={}.".format(control_ipv4_addr))
            shell = ShellHandler(control_ipv4_addr, user, password)
            stdout2, stderr2, exit_status2 = shell.execute_powershell("get-addomain", verbose=verbose)
            output = str(stdout2) + str(stderr2)
            if f'DNSRoot                            : {domain_name}' not in output:
                print("  Connected, but did not get domain info.  Trying again...")
                # server is starting up, try again.
                status_received = False
                time.sleep(10)
            else:
                print("  Success:  Domain detected!")
                status_received = True
        except (
            paramiko.ssh_exception.SSHException,
            paramiko.ssh_exception.NoValidConnectionsError,
            ConnectionResetError,
            TimeoutError
        ) as e:
            print(f"  Exception {type(e).__name__} detected, trying again...")
            time.sleep(10)
            pass

    if 'ReplicaDirectoryServers' not in str(stdout2):
        print("Stdout2: " + str(stdout2))
        print("Stderr2: " + str(stderr2))
        errstr = 'Cannot get domain information from ' + name
        raise RuntimeError(errstr)

    print("  Reboot Complete.  Waiting for domain controller service to start.")
    # wait for domain controller to be up/ready.

    remove_control_network_from_dns_cmd = (
        "set-dnsclient -interfacealias 'control-adapter' -registerthisconnectionsaddress 0 ; "
        " $srv=$(get-dnsserversetting -all) ;"
        f" $srv.ListeningIPAddress=@( {game_ipv4_addr} ) ;"
        " set-dnsserversetting -inputobject $srv; "
        " ipconfig /flushdns  ; "
        " ipconfig /registerdns  ; "
        " dcdiag /fix  "
    )
    shell = ShellHandler(control_ipv4_addr, user, password)
    stdout3, stderr3, exit_status3 = shell.execute_powershell(remove_control_network_from_dns_cmd, verbose=verbose)

    return {
        "deploy_forest_results": {"name": name, "control_addr": control_ipv4_addr, "game_addr": game_ipv4_addr, "password": password, "domain": domain},
        "install_forest": {"stdout": stdout, "stderr": stderr, "exit_status": exit_status},
        "verify_forest": {"stdout": stdout2, "stderr": stderr2, "exit_status": exit_status2},
        "cleanup_control_from_dns": {"stdout": stdout3, "stderr": stderr3, "exit_status": exit_status3},
        "domain_safe_mode_password": domain_safe_mode_password
    }


def add_domain_controller(cloud_config, leader_details, name, control_ipv4_addr, game_ipv4_addr, password, domain):
    user = 'Administrator'
    domain_name = domain + '.' + cloud_config['enterprise_url']
    leader_admin_password = leader_details['admin_pass']
    game_leader_ip = leader_details['game_addr'][0]
    control_leader_ip = leader_details['control_addr'][0]
    print('  domain-controller leader (control): ' + control_leader_ip)
    print('  domain-controller leader (game): ' + game_leader_ip)
    print('  domain-controller password: ' + leader_admin_password)

    pycmd = (
        "wget https://www.python.org/ftp/python/3.12.1/python-3.12.1-embed-amd64.zip -Outfile python.zip; "
        "Expand-Archive -force .\python.zip; "
        "mv python c:\\ ; "
        "icacls \"c:\\python\" /grant:r \"users:(RX)\" /C ; "
    )

    adcmd = (
        "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\NtpServer /v Enabled /t REG_DWORD /d 1 /f; "
        "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters /v Type /t REG_SZ /d NTP /f; "
        "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Config /v AnnounceFlags /t REG_DWORD /d 5 /f; "
        "tzutil /s 'Eastern Standard Time' ;  "
        "w32tm /config /manualpeerlist:'pool.ntp.org,0x1' /syncfromflags:manual /reliable:yes /update; "
        "net stop w32time; "
        "net start w32time; "
        "w32tm /resync /force; "
        "w32tm /config /manualpeerlist:\"time.google.com 0.pool.ntp.org 1.pool.ntp.org\" /syncfromflags:manual /reliable:yes /update ;"
        "net stop w32time ;"
        "net start w32time ;"
        "w32tm /resync ;"
        "w32tm /query /status ;"
        "Install-windowsfeature AD-domain-services ; "
        "Import-Module ADDSDeployment ;  "
        "Set-DnsClientServerAddress -serveraddress ('{}') -interfacealias 'game-adapter' ; "
        "Set-DnsClientServerAddress -serveraddress ('{}') -interfacealias 'control-adapter' ; "
        "$passwd = convertto-securestring -AsPlainText -Force -String '{}' ; "
        "$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist '{}\\administrator',$passwd ; "
        "$secure=ConvertTo-SecureString -asplaintext -string '{}' -force ; "
        "sleep 60; "
        "Install-ADDSDomainController -DomainName {} -SafeModeAdministratorPassword $secure -verbose -NoRebootOnCompletion:$true  -confirm:$false -credential $cred; "
        "$oldpath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path; "
        "$newpath = \"$oldpath;C:\python\" ; "
        "Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newpath "
    ).format(game_leader_ip, game_leader_ip, leader_admin_password, domain_name, domain_safe_mode_password, domain_name)

    if verbose:
        print("  Register as domain comtroller command:" + adcmd)

    try:
        shell = ShellHandler(control_ipv4_addr, user, password)
        stdout2, stderr2, exit_status2 = shell.execute_powershell(pycmd, verbose=verbose)
    except paramiko.ssh_exception.AuthenticationException:
        return {}

    stdout = [stdout2]
    stderr = [stderr2]
    exit_status = [exit_status2]
    attempts = 0
    while attempts < 10:
        shell = ShellHandler(control_ipv4_addr, user, password)
        attempts += 1
#        if name == 'dc3':
#            print('adcmd='+ str(adcmd))
#            sys.exit(1)
        stdout2, stderr2, exit_status2 = shell.execute_powershell(adcmd, verbose=verbose)

        stdout.append(stdout2)
        stderr.append(stderr2)
        exit_status.append(exit_status2)

        # stop if successful
        if 'A domain controller could not be contacted' not in str(stderr2) and 'A domain controller could not be contacted' not in str(stdout2):
            break
        print("  Domain controler registration failed, rebooting and retrying.")
        # print(str(stdout2 + stderr2))
        shell.execute_powershell('Restart-computer -force', verbose=verbose)
        time.sleep(60)

    if attempts > 9:
        raise RuntimeError("Could not join domain on machine " + name)

    try:
        shell = ShellHandler(control_ipv4_addr, user, password)
        shell.execute_powershell('Restart-computer -force', verbose=verbose)
    # we expect a forced reboot  to end in a socket error because the socket will
    # forceably disconnect as the machine reboots.
    except socket.error:
        pass

    print("  Waiting for reboot of windows node with ip={}.".format(control_ipv4_addr))
    time.sleep(10)
    status_received = False
    attempts = 0
    while not status_received and attempts < 60:
        try:
            attempts += 1
            shell = ShellHandler(control_ipv4_addr, user, leader_admin_password)
            stdout2, stderr2, exit_status2 = shell.execute_powershell("get-addomain", verbose=verbose)
            if 'ReplicaDirectoryServers' not in str(stdout2):
                print("Connected, waiting for AD to start up.")
                time.sleep(10)
                continue
            status_received = True
            stdout.append(stdout2)
            stderr.append(stderr2)
            exit_status.append(exit_status2)
        except (
            paramiko.ssh_exception.SSHException,
            paramiko.ssh_exception.NoValidConnectionsError,
            TimeoutError
        ) as e:
            print(f"  SSH exception {type(e).__name__}handled, retrying...")
            time.sleep(10)
            pass

    if "stdout2" not in locals() or 'ReplicaDirectoryServers' not in str(stdout2):
        if "stdout" in locals():
            print("add-dc-stdout:" + str(stdout))
        if "stderr" in locals():
            print("add-dc-stderr:" + str(stderr))
        if "stdout2" in locals():
            print("verify-stdout:" + str(stdout2))
        if "stderr2" in locals():
            print("verify-stderr:" + str(stderr2))
        errstr = 'Cannot get domain information from ' + name
        raise RuntimeError(errstr)

    print("  Reboot Complete")

    return {
        "add_domain_results": {"name": name, "control_addr": control_ipv4_addr, "game_addr": game_ipv4_addr, "password": password, "domain": domain},
        "install_domain_controller": {"stdout": stdout, "stderr": stderr, "exit_status": exit_status},
        "verify_domain_controller": {"stdout": stdout2, "stderr": stderr2, "exit_status": exit_status2}
    }


def join_domain(obj):
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
    iswindows = len(list(filter(lambda role: 'windows' == role, roles))) == 1
    islinux = len(list(filter(lambda role: 'linux' == role, roles))) == 1

    # convert array into string for powershell.
    domain_ips = str(game_leader_addrs).replace("[", "").replace(']', '').replace("'", '"')

    if verbose:
        print("  Domain controller leader:" + leader['name'])
        print("  Domain controller IPs (game):" + str(game_leader_addrs))

    if iswindows:
        print("  Windows join-domain for node " + name)
        return join_domain_windows(name, leader_admin_password, control_ipv4_addr, game_ipv4_addr, domain_ips, fqdn_domain_name, domain_name, password)
    elif islinux:
        print("Linux join-domain for node " + name)
        return join_domain_linux(obj, name, leader_admin_password, control_ipv4_addr, game_ipv4_addr, domain_ips, fqdn_domain_name, domain_name, password, enterprise_name)
    else:
        errstr = "  No endpoint/domain enrollment for node " + name
        raise RuntimeError(errstr)


def join_domain_windows(name, leader_admin_password, control_ipv4_addr, game_ipv4_addr, domain_ips, fqdn_domain_name, domain_name, password):

    print("Windows join-domain for node " + name)

    user = 'Administrator'
    cmd = (
        "$passwd = convertto-securestring -AsPlainText -Force -String {} ; "
        "$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist 'administrator@{}',$passwd ; "
        "Set-DnsClientServerAddress -serveraddress ({}) -interfacealias 'game-adapter' ; "
        "Add-Computer -Credential $cred -domainname {};"
        "wget https://www.python.org/ftp/python/3.12.1/python-3.12.1-embed-amd64.zip -Outfile python.zip; "
        "Expand-Archive -force .\python.zip; "
        "mv python c:\\ ; "
        "icacls \"c:\\python\" /grant:r \"users:(RX)\" /C ; "
        "$oldpath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path; "
        "$newpath = \"$oldpath;C:\python\" ; "
        "Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newpath "

    ).format(leader_admin_password, domain_name, domain_ips, fqdn_domain_name)

    print("  Joining an existing domain: " + domain_name)

    shell = ShellHandler(control_ipv4_addr, user, password)
    stdout, stderr, exit_status = shell.execute_powershell(cmd, verbose=verbose)

    try:
        shell = ShellHandler(control_ipv4_addr, user, password)
        shell.execute_powershell('Restart-computer -force', verbose=verbose)
    except socket.error:
        pass

    print("  Waiting for reboot of windows domain member with ip={}.".format(control_ipv4_addr))
    time.sleep(10)
    status_received = False
    attempts = 0
    stdout2 = ""
    stderr2 = ""
    while not status_received and attempts < 60:
        try:
            attempts += 1
            shell = ShellHandler(control_ipv4_addr, domain_name + '\\' + user, leader_admin_password)
            stdout2, stderr2, exit_status2 = shell.execute_powershell(
                'echo "the domain is $env:userdomain" ', verbose=verbose)
            status_received = True
            print(f"  Reboot Completed for {name} by verifying computer is in the domain")
        except paramiko.ssh_exception.SSHException:
            time.sleep(5)
            pass
        except paramiko.ssh_exception.NoValidConnectionsError:
            time.sleep(5)
            pass
    if stdout2 == "":
        raise RuntimeError("Could not verify machine {} was on domain: unable to connect".format(name))
    if not 'the domain is {}'.format(domain_name.upper()) in str(stdout2):
        print("join_domain_stdout:" + str(stdout))
        print("join_domain_stderr:" + str(stderr))
        print("verify_domain_stdout:" + str(stdout2))
        print("verify_domain_stderr:" + str(stderr2))
        errstr = 'Cannot get domain information from ' + name
        raise RuntimeError(errstr)

    return {
        "join_domain": {"join-cmd": cmd, "stdout": stdout, "stderr": stderr, "exit_status": exit_status},
        "verify_join_domain": {"stdout": stdout2, "stderr": stderr2, "exit_status": exit_status2}
    }


def join_domain_linux(obj, name, leader_admin_password, control_ipv4_addr, game_ipv4_addr, domain_ips, fqdn_domain_name, domain_name, password, enterprise_name):
    netplan_config_path = '/etc/netplan/50-cloud-init.yaml'
    chrony_config_path = '/etc/chrony/chrony.conf'
    domain_ips_formated = str(domain_ips).replace('[', '').replace(']', '').replace('"', '')
    krdb_config_path = '/etc/krb5.conf'

    cmd = f"""
bash << 'EOT' 2>&1 | sudo tee -a /var/log/join_domain.log
set -x

sudo hostnamectl set-hostname {name}.{fqdn_domain_name} --static

# gather IP and network connectivity.
ip a
ping -c 3 google.com
ping -c 3 nova.clouds.archive.ubuntu.com

# set up ssh password to be allowed.
sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/'  /etc/ssh/sshd_config
sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/'  /etc/ssh/sshd_config
sudo sed -i 's/#PasswordAuthentication /PasswordAuthentication /'  /etc/ssh/sshd_config
sudo sed -i 's/KbdInteractiveAuthentication no/KbdInteractiveAuthentication yes/'  /etc/ssh/sshd_config
sudo rm /etc/ssh/sshd_config.d/60-cloudimg-settings.conf

# setup DNS for domain join.
sudo sed -i '/dhcp4: true/a \            nameservers:\\n                addresses: \[ {domain_ips_formated} \]' {netplan_config_path}

# gather output for sanity check.
cat {netplan_config_path}
sudo netplan apply
echo Hostname=$(hostname)
sudo resolvectl status

# install packages.
attempts=0
while (( attempts < 30 ))
do
    if  sudo apt update && sudo env DEBIAN_FRONTEND=noninteractive apt install -y dnsutils iputils-ping traceroute telnet tcpdump python-is-python3 chrony krb5-user realmd sssd sssd-tools adcli samba-common-bin
    then
        echo "Domain packages successfully installed."
        break
    fi
    (( attempts++ ))
    sleep 1
    echo "Failed to install domain packages."
done


# set time/date to eastern and make sure it's right.
sudo timedatectl set-timezone America/New_York
sudo sed -i '/pool ntp.ubuntu.com        iburst maxsources 4/i pool {fqdn_domain_name}        iburst maxsources 5' {chrony_config_path}
sudo systemctl enable chrony
sudo systemctl restart chrony

attempts=0
while (( attempts < 60 ))
do
    if sudo chronyc tracking|grep 'Leap status     : Normal'
    then
        echo "Time sync succesful."
        break
    fi
    echo "Waiting for chrony to sync time."
    sleep 1
    (( attempts++ ))
done

# set up default realm to join domain
sudo sed -i 's/default_realm = .*/default_realm = {enterprise_name.upper()}/' {krdb_config_path}
sudo sed -i '/\\[libdefaults\\]/a \  rdns=false ' {krdb_config_path}

#  try repeatedly to join the domain.  need to do this in case the domain controller is still starting.
count=1
while (( count < 30 ))
do
    echo {leader_admin_password} | sudo kinit administrator@{fqdn_domain_name.upper()}
    res=${'{'}PIPESTATUS[1]{'}'}
    if (( res == 0 ))
    then
        break
    fi
    echo waiting for kinit to succeed
    sudo netplan apply
    sleep 30
    (( count++ ))
done

# gather domain info.
sudo klist

count=1
while (( count < 60 ))
do
        sudo realm discover {fqdn_domain_name}
        res=$?

        # verify that
        if (( res != 0 ))
        then
            echo 'Waiting for realm discover to succeed'
            sleep 30s
            (( count++ ))
            continue
        fi

        echo {leader_admin_password}| sudo realm join -U administrator {fqdn_domain_name.upper()}  -v 2>&1 | sudo tee /var/log/join_output.log
        res=${'{'}PIPESTATUS[1]{'}'}
        if grep "Already joined to this domain" /var/log/join_output.log
        then
            echo "Already in domain!  Sanity checking realm"
        elif (( res != 0 ))
        then
            echo 'Waiting for realm join to succeed'
            sleep 30s
            (( count++ ))
            continue
        else
            echo "Realm discover and join successful. Sanity checking realm"
        fi

        realm list
        break

done

sudo systemctl restart sshd sssd realmd chronyd

attempts=0
while (( attempts < 50 ))
do
    if sudo apt update; then
        echo "apt update succeeded after $((attempts+1)) attempt(s)."
        break
    fi
    echo "Attempt $((attempts+1)) failed. Retrying..."
    sudo netplan apply
    sleep 5
    ((attempts++))
done

if (( attempts == 50 )); then
    echo "apt update failed after 50 attempts."
    exit 1
fi

EOT
"""

    shell = ShellHandler(control_ipv4_addr, 'ubuntu', None)
    stdout, stderr, exit_status = shell.execute_cmd(cmd, verbose=verbose)

    # wait for services to stabilize.
    time.sleep(5)
    status_received = False
    attempts = 0
    stdout2 = None
    stderr2 = None
    exit_status2 = None
    while not status_received and attempts < 30:
        attempts += 1
        try:
            admin_user = 'administrator@' + fqdn_domain_name
            print("  Trying to verify domain-join of {}... creds={}:{}:{}".format(
                name, control_ipv4_addr, admin_user, leader_admin_password))
            shell = ShellHandler(control_ipv4_addr, admin_user, leader_admin_password)
            stdout2, stderr2, exit_status2 = shell.execute_cmd('sudo netplan apply; realm list', verbose=verbose)
            if not 'realm-name: {}'.format(fqdn_domain_name.upper()) in str(stdout2):
                print(f"  Realm list did not return fqdn ({fqdn_domain_name}), retrying.")
                time.sleep(5)
            else:
                status_received = True
        except paramiko.ssh_exception.SSHException:
            print(f"  Waiting domain join to complete for ip={control_ipv4_addr}.")

            time.sleep(5)
            pass
        except paramiko.ssh_exception.NoValidConnectionsError:
            print(f"  Waiting for domain join to complete for {name} with ip={control_ipv4_addr}.")
            time.sleep(5)
            pass

    try:
        stdout2
    except Exception as _:   # noqa: F841
        errstr = 'Connect after reboot.'
        raise RuntimeError(errstr)

    if stdout2 is None or not 'realm-name: {}'.format(fqdn_domain_name.upper()) in str(stdout2):
        print("join_domain_stdout:" + str(stdout))
        print("join_domain_stderr:" + str(stderr))
        print("verify_domain_stdout:" + str(stdout2))
        print("verify_domain_stderr:" + str(stderr2))
        errstr = 'Cannot detect domain information from ' + name
        if stdout2 is None:
            errstr += ". Could not connect"
        else:
            errstr += ". Missing domain information."
        raise RuntimeError(errstr)
    print(f"  Reboot Completed for {name} by verifying computer is in the domain")

    return {
        "mount_home_dirs": role_fs.mount_home_directories_linux(obj),
        "join_domain": {"join-cmd": cmd, "stdout": stdout, "stderr": stderr, "exit_status": exit_status},
        "verify_join_domain": {"stdout": stdout2, "stderr": stderr2, "exit_status": exit_status2}
    }


def deploy_users(users, built):
    deploy_users = {}
    domain_leaders = built['setup']['setup_domains']['domain_leaders']

    domain_commands = {}
    for user in users:
        username = user['user_profile']['username']
        domain = user['domain']
        print("Preparing to install user " + username + " in domain " + domain)
        install_one_user = (
            '$secure=ConvertTo-SecureString -asplaintext -string "{}" -force; '
            'New-ADUser -samaccountname "{}" -name "{}" -accountpassword $secure  -enabled $true'
        ).format(user['user_profile']['password'], user['user_profile']['username'], user['user_profile']['name'])
        if domain in domain_commands:
            domain_commands[domain] += '; ' + install_one_user
        else:
            domain_commands[domain] = install_one_user

    deploy_users['cmds'] = domain_commands
    deploy_users['add_users'] = {}

    for domain in domain_commands:
        cmd = domain_commands[domain]
        controller_name = domain_leaders[domain]['name']
        print(domain_leaders[domain])
        controller_addr = domain_leaders[domain]['control_addr'][0]     # uses control address
        domain_password = domain_leaders[domain]['admin_pass']
        print("Installing users for domain " + domain + " on server " + controller_addr)
        print("  controller name,addr:" + controller_name + "(" + controller_addr + ")")
        qualified_username = 'administrator@' + domain
        shell = ShellHandler(controller_addr, qualified_username, domain_password)
        stdout, stderr, exit_status = shell.execute_powershell(cmd, verbose=verbose)
        deploy_users['add_users'][domain] = {"cmd": cmd, "stdout": stdout, "stderr": stderr, "exit_status": exit_status}

    return deploy_users


def setup_root_ca(node, control_ipv4_addr, game_ipv4_addr, password, leader_details, cloud_config, enterprise, enterprise_built):
    """
    setup_root_ca

    Installs and configures an Enterprise Root CA on a Windows domain controller.

    Parameters:
    - node: dict - Node definition including 'name', 'domain', and 'roles'
    - control_ipv4_addr: str - IPv4 address used for SSH or WinRM access to the node
    - game_ipv4_addr: str - IPv4 address used to reach the node within the simulation/game network
    - password: str - Local administrator password for the target node
    - leader_details: dict - Contains 'admin_pass' and 'game_addr' for the domain leader
    - cloud_config: dict - Contains cloud-wide config options including 'enterprise_url'
    - enterprise: unused, retained for signature compatibility
    - enterprise_built: unused, retained for signature compatibility

    Returns:
    - dict: stdout, stderr, and exit_status from the shell command
    """

    import paramiko
    from shell_handler import ShellHandler

    name = node['name']
    domain_name = node['domain']
    enterprise_name = cloud_config['enterprise_url']
    fqdn_domain_name = domain_name + '.' + enterprise_name
    leader_admin_password = leader_details['admin_pass']
    game_leader_addrs = leader_details['game_addr']
    roles = node['roles']
    iswindows = len(list(filter(lambda role: 'windows' == role, roles))) == 1

    if not iswindows:
        raise RuntimeError("Cannot install AD CS on non-Windows systems")

    join_domain_results = join_domain_windows(
        name,
        leader_admin_password,
        control_ipv4_addr,
        game_ipv4_addr,
        str(game_leader_addrs).replace("[", "").replace("]", "").replace("'", "\""),
        fqdn_domain_name,
        domain_name,
        password
    )
    print(f"  Installing Root AD CS for node {name}")

    # Construct the PowerShell command as a multiline string
    adcs_cmd = """
        Install-WindowsFeature AD-Domain-Services
        Get-ADDomain
        Install-WindowsFeature ADCS-Cert-Authority
        Import-Module ADCSDeployment
        Install-AdcsCertificationAuthority -CAType EnterpriseRootCA `
            -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' `
            -KeyLength 2048 `
            -HashAlgorithmName SHA256 `
            -ValidityPeriod Years -ValidityPeriodUnits 5 `
            -Force
        Write-Host 'AD CS RootCA installation completed.'
        """

    # Create a shell session to the target machine
    shell = ShellHandler(control_ipv4_addr, domain_name + '\\' + 'administrator', leader_admin_password)

    # Execute the multi-line PowerShell command
    try:
        adcs_stdout, adcs_stderr, adcs_exit_status = shell.execute_powershell_multiline(
            adcs_cmd, verbose=verbose, filename='install-rootca.ps1')
    except paramiko.ssh_exception.AuthenticationException as e:
        raise RuntimeError(f"Authentication failed: {e}")

    # Verify Root CA
    verify_cmd = """
        $max = 36
        $i = 0
        while ($i -lt $max) {
            try {
                $output = certutil -CAinfo | Out-String
                Write-Output $output
                if ($output -match 'CertUtil: -CAInfo command completed successfully') {
                    Write-Host '  Verified RootCA was setup properly'
                    exit 0
                }
            } catch {
                Write-Error "Error running certutil: $_"
            }
            Start-Sleep -Seconds 5
            $i += 1
        }
        Write-Error 'AD CS installation issue: could not verify CA certificate within timeout.'
        exit 1
        """

    try:
        verify_stdout, verify_stderr, verify_exit_status = shell.execute_powershell_multiline(
            verify_cmd, verbose=verbose, filename='verify-rootca.ps1')
    except Exception as e:
        raise RuntimeError(f"Failed to verify AD CS: {e}")

    if 'CertUtil: -CAInfo command completed successfully' not in str(verify_stdout):
        print(f"adcs_stdout={adcs_stdout}")
        print(f"adcs_stderr={adcs_stderr}")
        print(f"adcs_exit_status={adcs_exit_status}")
        print(f"verify_stdout={verify_stdout}")
        print(f"verify_stderr={verify_stderr}")
        print(f"verify_exit_status={verify_exit_status}")
        raise RuntimeError("AD CS installation issue, could not verify CA certificate.")

    print("  Verified RootCA was setup properly")

    return {
        "install_adcs": {
            "cmd": adcs_cmd,
            "join_domain_results": join_domain_results,
            "stdout": adcs_stdout,
            "stderr": adcs_stderr,
            "exit_status": adcs_exit_status,
            "verify_stdout": verify_stdout,
            "verify_stderr": verify_stderr,
            "verify_exit_status": verify_exit_status
        }
    }


def setup_subordinate_ca(node, control_ipv4_addr, game_ipv4_addr, password, leader_details, cloud_config, enterprise, enterprise_built):
    """
    setup_subordinate_ca

    Prepares a Subordinate CA by installing the necessary ADCS role.

    Parameters:
    - node: dict - Node definition including 'name', 'domain', and 'roles'
    - control_ipv4_addr: str - IPv4 address used for SSH or WinRM access to the node
    - game_ipv4_addr: str - IPv4 address used to reach the node within the simulation/game network
    - password: str - Local administrator password for the target node
    - leader_details: dict - Contains 'admin_pass' and 'game_addr' for the domain leader
    - cloud_config: dict - Contains cloud-wide config options including 'enterprise_url'
    - enterprise: unused, retained for signature compatibility
    - enterprise_built: unused, retained for signature compatibility

    Returns:
    - dict: stdout, stderr, and exit_status from the shell command
    """

    import paramiko
    from shell_handler import ShellHandler

    name = node['name']
    domain_name = node['domain']
    enterprise_name = cloud_config['enterprise_url']
    fqdn_domain_name = domain_name + '.' + enterprise_name
    leader_admin_password = leader_details['admin_pass']
    game_leader_addrs = leader_details['game_addr']
    roles = node['roles']
    iswindows = len(list(filter(lambda role: 'windows' == role, roles))) == 1

    if not iswindows:
        raise RuntimeError("Cannot install AD CS on non-Windows systems")

    join_domain_results = join_domain_windows(
        name,
        leader_admin_password,
        control_ipv4_addr,
        game_ipv4_addr,
        str(game_leader_addrs).replace("[", "").replace("]", "").replace("'", "\""),
        fqdn_domain_name,
        domain_name,
        password
    )
    print(f"  Installing Subordinate AD CS for node {name}")

    cmd = """
        Install-WindowsFeature AD-Domain-Services
        Get-ADDomain
        Install-WindowsFeature ADCS-Cert-Authority
        Import-Module ADCSDeployment
        Install-AdcsCertificationAuthority -CAType EnterpriseSubordinateCA -Force
        Write-Host 'AD CS SubordinateCA request created.'
    """

    shell = ShellHandler(control_ipv4_addr, domain_name + '\\' + 'administrator', leader_admin_password)
    try:
        adcs_stdout, adcs_stderr, adcs_exit_status = shell.execute_powershell_multiline(
            cmd, filename="install-subca.ps1", verbose=verbose)
    except paramiko.ssh_exception.AuthenticationException as e:
        raise RuntimeError(f"Authentication failed: {e}")

    # Verify Subordinate CA role installed
    verify_cmd = "Get-WindowsFeature ADCS-Cert-Authority"
    try:
        verify_stdout, verify_stderr, verify_exit_status = shell.execute_powershell(verify_cmd, verbose=verbose)
    except Exception as e:
        raise RuntimeError(f"Failed to verify AD CS: {e}")

    if 'Installed' not in str(verify_stdout):
        raise RuntimeError("Could not verify Subordinate AD CS installation completed.")
    print("  Verified SubordinateCA was setup properly")

    return {
        "install_adcs": {
            "cmd": cmd,
            "join_domain_results": join_domain_results,
            "stdout": adcs_stdout,
            "stderr": adcs_stderr,
            "exit_status": adcs_exit_status,
            "verify_stdout": verify_stdout,
            "verify_stderr": verify_stderr,
            "verify_exit_status": verify_exit_status
        }
    }


# Existing link_subordinate_to_root() function retained below
def link_subordinate_to_root(root_info, sub_info):
    """
    Links a subordinate CA to its root CA by signing the subordinate's request on the root CA
    and installing the returned certificate on the subordinate.

    Parameters:
    - root_info: dict with 'control_addr' and admin password of root CA
    - sub_info: dict with 'node', 'control_ip', 'password', etc.

    Returns:
    - dict with stdout/stderr/exit_status from the final install step
    """

    import os
    from shell_handler import ShellHandler

    sub_node = sub_info['node']
    sub_name = sub_node['name']
    sub_ip = sub_info['control_ip']
    domain = sub_info['domain']
    enterprise_url = sub_info['enterprise_url']

    sub_req_file = f"C:\\{sub_name}.{domain}.{enterprise_url}_{domain}-{sub_name.upper()}-CA.req"

    root_ip = root_info['control_addr']
    root_password = root_info['admin_pass']

    tmp_dir = "tmp"
    os.makedirs(tmp_dir, exist_ok=True)

    local_req = os.path.join(tmp_dir, f"{sub_name}.req")
    local_cer = os.path.join(tmp_dir, f"{sub_name}.cer")

    remote_req = f"C:\\tmp\\{sub_name}.req"
    remote_cer = f"C:\\tmp\\{sub_name}.cer"

    sub_shell = ShellHandler(sub_ip, f"{domain}\\Administrator", root_password)
    root_shell = ShellHandler(root_ip, f"{domain}\\Administrator", root_password)

    # Ensure C:\tmp exists on both systems
    sub_shell.execute_cmd("mkdir C:\\tmp", verbose=verbose)
    root_shell.execute_cmd("mkdir C:\\tmp", verbose=verbose)

    # Step 1: Fetch subordinate .req
    sub_shell.get_file(sub_req_file, local_req)

    # Step 2: Send .req to root CA
    root_shell.put_file(local_req, remote_req)

    # Step 3: Submit request on root CA and save .cer
    sign_cmd = f"""
certreq -submit -q -attrib "CertificateTemplate:SubCA "{remote_req}" "{remote_cer}"
Restart-Service certsvc
"""
    stdout, stderr, exit_status = root_shell.execute_powershell_multiline(sign_cmd, verbose=verbose, filename="sign_request.ps1")

    # Step 4: Fetch signed .cer
    root_shell.get_file(remote_cer, local_cer)

    # Step 5: Send cert to subordinate
    sub_shell.put_file(local_cer, "C:\\tmp\\subca.cer")

    # Step 6: Finalize subordinate CA install
    # Step 6: Finalize subordinate CA install without risk of hanging
    install_cmd = """
# Enable tracing for debugging (like bash -x)
Set-PSDebug -Trace 1

Import-Certificate -FilePath "C:\\tmp\\subca.cer" -CertStoreLocation Cert:\\LocalMachine\\CA
Start-Service -Name netlogon, rpcss, eventlog
certutil -urlfetch -verify C:\\tmp\\subca.cer


# Wait for private key to become available
$keyReady = $false
for ($j = 0; $j -lt 30; $j++) {
    $keyOutput = certutil -key | Out-String
    if ($keyOutput -match "AT_KEYEXCHANGE") {
        $keyReady = $true
        break
    }
    Start-Sleep -Seconds 2
}
if (-not $keyReady) {
    Write-Error 'CA private key not available in time'
    exit 1
}

# Attempt certutil -installcert with retries and timeout using Start-Job
$maxRetries = 5
$success = $false
for ($i = 0; $i -lt $maxRetries; $i++) {
    Write-Host "Attempt $($i + 1) to run certutil -installcert..."

    $job = Start-Job -ScriptBlock {
        certutil -installcert -f -v C:\\tmp\\subca.cer
    }

    if (Wait-Job -Job $job -Timeout 60) {
        $output = Receive-Job -Job $job
        $exitCode = $LASTEXITCODE
        Remove-Job -Job $job -Force

        if ($exitCode -eq 0) {
            Write-Host $output
            $success = $true
            break
        } else {
            Write-Warning "certutil failed with exit code $exitCode. Output:"
            Write-Host $output
        }
    } else {
        Stop-Job -Job $job | Out-Null
        Remove-Job -Job $job -Force
        Write-Warning "certutil -installcert attempt $($i + 1) timed out. Retrying..."
    }

    Start-Sleep -Seconds 5
}

if (-not $success) {
    Write-Error "certutil -installcert failed after $maxRetries attempts."
    exit 1
}

# Start the Certificate Services
Start-Service certsvc

# Disable tracing
Set-PSDebug -Trace 0

    """
    install_out, install_err, install_status = sub_shell.execute_powershell_multiline(
        install_cmd, filename="finalize-sub-install.ps1", verbose=verbose)

    # Verify Subordinate CA
    verify_cmd = "certutil -CAinfo"
    try:
        verify_out, verify_err, verify_exit_status = sub_shell.execute_powershell(
            verify_cmd, verbose=verbose)
    except Exception as e:
        raise RuntimeError(f"Failed to verify AD CS: {e}")

    print(f"install_stdout={install_out}")
    print(f"install_stderr={install_err}")
    print(f"install_exit_status={install_status}")
    print(f"verify_stdout={verify_out}")
    print(f"verify_stderr={verify_err}")
    print(f"verify_exit_status={verify_exit_status}")
    if 'CertUtil: -CAInfo command completed successfully' not in str(verify_out):
        print(f"install_stdout={install_out}")
        print(f"install_stderr={install_err}")
        print(f"install_exit_status={install_status}")
        print(f"verify_stdout={verify_out}")
        print(f"verify_stderr={verify_err}")
        print(f"verify_exit_status={verify_exit_status}")
        raise RuntimeError("AD CS installation issue, could not verify CA certificate.")
    print("  Verified Subordinate CA was setup properly")

    return {
        "link_subordinate_to_root": {
            "sign_cert": {
                "stdout": stdout,
                "stderr": stderr,
                "exit_status": exit_status
            },
            "install_cert": {
                "stdout": install_out,
                "stderr": install_err,
                "exit_status": install_status
            },
            "verifyl_cert": {
                "stdout": verify_out,
                "stderr": verify_err,
                "exit_status": verify_exit_status
            }
        }
    }
