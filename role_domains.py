import time
import socket
import paramiko
from shell_handler import ShellHandler
#from password import generate_password


domain_safe_mode_password = 'hello!321' # generate_password(12)
verbose = False

def deploy_forest(cloud_config,name,control_ipv4_addr, game_ipv4_addr,password,domain):

    user='Administrator'
    domain_name = domain + '.' + cloud_config['enterprise_url'] 
    print("Setting safe-mode password for domain to " + password)

    cmd=(
        "Install-windowsfeature AD-domain-services ; "
        "Import-Module ADDSDeployment ;  "
        "$secure=ConvertTo-SecureString -asplaintext -string {} -force ; "
        "Install-ADDSForest -domainname {} -SafeModeAdministratorPassword $secure -verbose -NoRebootOnCompletion:$true -Force:$true ; "
        "wget https://www.python.org/ftp/python/3.12.1/python-3.12.1-embed-amd64.zip -Outfile python.zip; "
        "Expand-Archive -force .\python.zip; "
        "mv python c:\\ ; "
        "icacls \"c:\\python\" /grant:r \"users:(RX)\" /C ; "
        "$oldpath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path; "
        "$newpath = \"$oldpath;C:\python\" ; "
        "Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newpath "
        ).format( domain_safe_mode_password,domain_name)


    if verbose:
        print("  Register forest command:" + cmd)

    shell = ShellHandler(control_ipv4_addr,user,password)
    stdout,stderr,exit_status = shell.execute_powershell(cmd, verbose=verbose)
    try:
        shell.execute_powershell('Restart-computer -force', verbose=verbose)
    except socket.error:
        pass

    print("  Waiting for reboot of domain controller leader with ip={} (Expect socket closed by peer messages).".format(control_ipv4_addr))
    time.sleep(10)
    status_received = False
    attempts = 0
    while not status_received and attempts < 60:
        try:
            attempts += 1
            shell = ShellHandler(control_ipv4_addr,user,password)
            stdout2,stderr2,exit_status2 = shell.execute_powershell("get-addomain", verbose=verbose)
            if 'Attempting to perform the' in str(stdout2)+ str(stderr2):
                # server is starting up, try again.
                status_received=False
                time.sleep(10)
            else:
                status_received=True
        except paramiko.ssh_exception.SSHException:
            time.sleep(10)
            pass
        except paramiko.ssh_exception.NoValidConnectionsError:
            time.sleep(10)
            pass
        except ConnectionResetError:
            time.sleep(10)
            pass

    if not 'ReplicaDirectoryServers' in str(stdout2):
        print("Stdout2: " + str(stdout2))
        print("Stderr2: " + str(stderr2))
        errstr = 'Cannot get domain information from ' + name
        raise RuntimeError(errstr)

    print("  Reboot Complete.  Waiting for domain controller service to start.");
    # wait for domain controller to be up/ready.


    remove_control_network_from_dns_cmd = (
            "set-dnsclient -interfacealias 'control-adapter' -registerthisconnectionsaddress 0 ; "
            " $srv=$(get-dnsserversetting -all) ;"
            " $srv.ListeningIPAddress=@( $srv.ListeningIPAddress[1]) ;"
            " set-dnsserversetting -inputobject $srv; "
            " ipconfig /flushdns  ; "
            " ipconfig /registerdns  ; "
            " dcdiag /fix  "
            )
    shell = ShellHandler(control_ipv4_addr,user,password)
    stdout3,stderr3,exit_status3 = shell.execute_powershell(remove_control_network_from_dns_cmd,verbose=verbose)


    return {
            "deploy_forest_results": {"name": name, "control_addr":control_ipv4_addr, "game_addr": game_ipv4_addr, "password": password, "domain": domain }, 
                "install_forest": {"stdout": stdout, "stderr": stderr, "exit_status": exit_status},
                "verify_forest": {"stdout": stdout2, "stderr": stderr2, "exit_status": exit_status2},
                "cleanup_control_from_dns": {"stdout": stdout3, "stderr": stderr3, "exit_status": exit_status3},
                "domain_safe_mode_password": domain_safe_mode_password
            }


def add_domain_controller(cloud_config,leader_details,name,control_ipv4_addr, game_ipv4_addr,password,domain):
    user='Administrator'
    domain_name = domain + '.' + cloud_config['enterprise_url'] 
    leader_admin_password=leader_details['admin_pass']
    game_leader_ip=leader_details['game_addr'][0]
    control_leader_ip=leader_details['control_addr'][0]
    print('  domain-controller leader (control): ' + control_leader_ip)
    print('  domain-controller leader: (game)' + game_leader_ip)
    print('  domain-controller password: ' + leader_admin_password)

    pycmd=(
        "wget https://www.python.org/ftp/python/3.12.1/python-3.12.1-embed-amd64.zip -Outfile python.zip; "
        "Expand-Archive -force .\python.zip; "
        "mv python c:\\ ; "
        "icacls \"c:\\python\" /grant:r \"users:(RX)\" /C ; "
        )

    adcmd =(
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
        ).format( game_leader_ip, game_leader_ip, leader_admin_password, domain_name, domain_safe_mode_password,domain_name)

    if verbose:
        print("  Register as domain comtroller command:" + adcmd)

    try:
        shell = ShellHandler(control_ipv4_addr,user,password)
        stdout2,stderr2,exit_status2 = shell.execute_powershell(pycmd,verbose=verbose)
    except paramiko.ssh_exception.AuthenticationException:
        return {}

    stdout = [stdout2]
    stderr = [stderr2]
    exit_status = [exit_status2]
    attempts = 0 
    while attempts < 10:
        shell = ShellHandler(control_ipv4_addr,user,password)
        attempts += 1 
#        if name == 'dc3':
#            print('adcmd='+ str(adcmd))
#            sys.exit(1)
        stdout2,stderr2,exit_status2 = shell.execute_powershell(adcmd,verbose=verbose)

        stdout.append(stdout2)
        stderr.append(stderr2)
        exit_status.append(exit_status2)
        
        # stop if successful
        if not 'A domain controller could not be contacted' in str(stderr2) and  not 'A domain controller could not be contacted' in str(stdout2):
            break;
        print("Domain controler registration failed, rebooting and retrying (Expect socket error messages)")
        #print(str(stdout2 + stderr2))
        shell.execute_powershell('Restart-computer -force', verbose=verbose)
        time.sleep(60)

    if attempts > 9:
        raise RuntimeError("Could not join domain on machine " + name)

    try:
        shell = ShellHandler(control_ipv4_addr,user,password)
        shell.execute_powershell('Restart-computer -force', verbose=verbose)
    # we expect a forced reboot  to end in a socket error because the socket will
    # forceably disconnect as the machine reboots.
    except socket.error:
        pass

    print("  Waiting for reboot of windows node with ip={} (Expect socket error messages).".format(control_ipv4_addr))
    time.sleep(10)
    status_received = False
    attempts = 0
    while not status_received and attempts < 60:
        try:
            attempts += 1
            shell = ShellHandler(control_ipv4_addr,user,leader_admin_password)
            stdout2,stderr2,exit_status2 = shell.execute_powershell("get-addomain", verbose=verbose)
            if not 'ReplicaDirectoryServers' in str(stdout2):
                print("Connected, waiting for AD to start up.") 
                time.sleep(10)
                continue
            status_received=True
            stdout.append(stdout2)
            stderr.append(stderr2)
            exit_status.append(exit_status2)
        except paramiko.ssh_exception.SSHException:
            time.sleep(10)
            pass
        except paramiko.ssh_exception.NoValidConnectionsError:
            time.sleep(10)
            pass

    if not "stdout2" in locals() or not 'ReplicaDirectoryServers' in str(stdout2):
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

    print("  Reboot Complete");

    return {
            "add_domain_results": {"name": name, "control_addr": control_ipv4_addr, "game_addr": game_ipv4_addr, "password": password, "domain": domain }, 
                "install_domain_controller": {"stdout": stdout, "stderr": stderr, "exit_status": exit_status},
                "verify_domain_controller": {"stdout": stdout2, "stderr": stderr2, "exit_status": exit_status2}
            }


def join_domain(obj):
    cloud_config=obj['cloud_config']
    node=obj['node']
    name=node['name']
    domain_name=obj['domain']
    enterprise_name = cloud_config['enterprise_url'] 
    fqdn_domain_name = domain_name + '.' + enterprise_name; 
    leader=obj['domain_leader']
    leader_admin_password=leader['admin_pass']
    game_leader_addrs=leader['game_addr']
    control_ipv4_addr=obj['control_addr']
    game_ipv4_addr=obj['game_addr']
    password=obj['password']
    roles=node['roles']
    iswindows = len(list(filter(lambda role: 'windows' == role, roles))) == 1
    islinux = len(list(filter(lambda role: 'linux' == role, roles))) == 1

    # convert array into string for powershell.
    domain_ips = str(game_leader_addrs).replace("[","").replace(']','').replace("'",'"')


    if verbose:
        print("  Domain controller leader:" + leader['name'])
        print("  Domain controller IPs (game):" + str(game_leader_addrs))

    if iswindows:
        print("Windows join-domain for node " + name)
        return join_domain_windows(name, leader_admin_password, control_ipv4_addr, game_ipv4_addr, domain_ips, fqdn_domain_name, domain_name, password)
    elif islinux:
        print("Linux join-domain for node " + name)
        return join_domain_linux(name, leader_admin_password, control_ipv4_addr, game_ipv4_addr, domain_ips, fqdn_domain_name, domain_name, password, enterprise_name)
    else:
        errstr = "  No endpoint/domain enrollment for node " + name
        raise RuntimeError(errstr)


def join_domain_windows(name, leader_admin_password, control_ipv4_addr, game_ipv4_addr, domain_ips, fqdn_domain_name, domain_name, password):

    print("Windows join-domain for node " + name)

    user='Administrator'
    cmd=(
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

    shell = ShellHandler(control_ipv4_addr,user,password)
    stdout,stderr,exit_status = shell.execute_powershell(cmd,verbose=verbose)

    try:
        shell = ShellHandler(control_ipv4_addr,user,password)
        shell.execute_powershell('Restart-computer -force', verbose=verbose)
    except socket.error:
        pass

    print("  Waiting for reboot of windows domain member with ip={} (Expect socket closed by peer messages).".format(control_ipv4_addr))
    time.sleep(10)
    status_received = False
    attempts=0
    stdout2=""
    stderr2=""
    while not status_received and attempts < 60:
        try:
            attempts += 1
            shell = ShellHandler(control_ipv4_addr,domain_name+'\\'+user,leader_admin_password)
            stdout2,stderr2,exit_status2 = shell.execute_powershell('echo "the domain is $env:userdomain" ', verbose=verbose)
            status_received=True
            print("  Reboot Completed by verifying computer is in the domain");
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

def join_domain_linux(name, leader_admin_password, control_ipv4_addr, game_ipv4_addr, domain_ips, fqdn_domain_name, domain_name, password, enterprise_name):
    netplan_config_path='/etc/netplan/50-cloud-init.yaml'
    chrony_config_path='/etc/chrony/chrony.conf'
    domain_ips_formated = str(domain_ips).replace('[','').replace(']','').replace('"','')
    krdb_config_path='/etc/krb5.conf'


    set_allow_password=(
        "set -x ; ip a ; ping -c 3 google.com; ping -c 3 nova.clouds.archive.ubuntu.com ;  "
        "sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/'  /etc/ssh/sshd_config; "
        "sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/'  /etc/ssh/sshd_config; "
        "sudo sed -i 's/#PasswordAuthentication /PasswordAuthentication /'  /etc/ssh/sshd_config; "
        "sudo sed -i 's/KbdInteractiveAuthentication no/KbdInteractiveAuthentication yes/'  /etc/ssh/sshd_config; "
        "sudo rm /etc/ssh/sshd_config.d/60-cloudimg-settings.conf "
    )

    set_dns_command=(
        "sudo sed -i '/dhcp4: true/a \            nameservers:\\n                addresses: \[ {} \]' {} ;  "
        "cat {}; sudo netplan apply ; echo Hostname=$(hostname); sudo resolvectl status  "
        ).format(domain_ips_formated, netplan_config_path, netplan_config_path)

    install_packages_cmd="sudo apt update && sudo env DEBIAN_FRONTEND=noninteractive apt install -y dnsutils iputils-ping traceroute telnet tcpdump python-is-python3 chrony krb5-user realmd sssd sssd-tools adcli samba-common-bin"

    set_chrony_command=(
        "sudo sed -i '/pool ntp.ubuntu.com        iburst maxsources 4/i pool {}        iburst maxsources 5' {} ; ".format(fqdn_domain_name, chrony_config_path) +
        "sudo systemctl enable chrony ; " +
        "sudo systemctl restart chrony; " +
        "while ! sudo chronyc tracking|grep 'Leap status     : Normal'; do echo waiting for chrony to sync time; sleep 1; done "
        )


    krb5_cmd= (
            "sudo sed -i 's/default_realm = .*/default_realm = {}/' {} ; "
            "sudo sed -i '/\\[libdefaults\\]/a \  rdns=false ' {} ;  "
            "while echo {} | sudo kinit administrator@{} 2>&1 | grep 'Cannot find KDC' ; do echo waiting for kinit to succeed; sudo netplan apply; sleep 1; done ; "
            "sudo klist "
            ).format(enterprise_name.upper(), krdb_config_path, krdb_config_path, leader_admin_password, fqdn_domain_name.upper())

    realm_cmd= (
        "sudo realm discover {};"
        "echo {}| sudo realm join -U administrator {}  -v;"
        ).format(fqdn_domain_name, leader_admin_password, fqdn_domain_name.upper())

    cmds= '(' + set_allow_password + ';' + set_dns_command + ';' + install_packages_cmd + ';' + set_chrony_command + ';' + krb5_cmd + ';' + realm_cmd + ') 2>&1'


    shell = ShellHandler(control_ipv4_addr,'ubuntu',None) 
    stdout,stderr,exit_status = shell.execute_cmd(cmds, verbose=verbose)

    shell.execute_cmd("sudo reboot now" , verbose=verbose)

    print("  Waiting for reboot of linux domain member with ip={}(Expect socket closed by peer messages).".format(control_ipv4_addr))
    time.sleep(5)
    status_received = False
    attempts = 0
    stdout2 = None
    stderr2 = None
    exit_status2 = None
    while not status_received and attempts < 300:
        attempts += 1
        try:
            admin_user='administrator@' + fqdn_domain_name
            print("  Trying to verify reboot ... creds={}:{}:{}".format(control_ipv4_addr,admin_user,leader_admin_password))
            shell = ShellHandler(control_ipv4_addr, admin_user, leader_admin_password)
            stdout2,stderr2,exit_status2 = shell.execute_cmd('realm list', verbose=verbose)
            status_received=True
        except paramiko.ssh_exception.SSHException:
            print("  Waiting for reboot of linux domain member with ip={}(Expect socket closed by peer messages).".format(control_ipv4_addr))

            time.sleep(5)
            pass
        except paramiko.ssh_exception.NoValidConnectionsError:
            print("  Waiting for reboot of linux domain member with ip={}(Expect socket closed by peer messages).".format(control_ipv4_addr))
            time.sleep(5)
            pass

    try: stdout2
    except:
        errstr = 'Connect after reboot.'
        raise RuntimeError(errstr)


    if stdout2 == None or not 'realm-name: {}'.format(fqdn_domain_name.upper()) in str(stdout2):
        print("join_domain_stdout:" + str(stdout))
        print("join_domain_stderr:" + str(stderr))
        print("verify_domain_stdout:" + str(stdout2))
        print("verify_domain_stderr:" + str(stderr2))
        errstr = 'Cannot detect domain information from ' + name
        if stdout2 == None:
            errstr += ". Could not connect"
        else:
            errstr += ". Missing domain information."
        raise RuntimeError(errstr)
    print("  Reboot Completed by verifying computer is in the domain");

    return {
            "join_domain": {"join-cmd": cmds, "stdout": stdout, "stderr": stderr, "exit_status": exit_status},
            "verify_join_domain": {"stdout": stdout2, "stderr": stderr2, "exit_status": exit_status2}
            }

def deploy_users(users,built):
    deploy_users={}
    domain_leaders=built['setup']['setup_domains']['domain_leaders']

    domain_commands={}
    for user in users:
        username = user['user_profile']['username']
        domain=user['domain']
        print("Preparing to install user " + username + " in domain " + domain)
        install_one_user=(
                '$secure=ConvertTo-SecureString -asplaintext -string "{}" -force; '
                'New-ADUser -samaccountname "{}" -name "{}" -accountpassword $secure  -enabled $true'
                ).format(user['user_profile']['password'], user['user_profile']['username'], user['user_profile']['name'])
        if domain in domain_commands:
            domain_commands[domain] += '; ' + install_one_user
        else:
            domain_commands[domain] = install_one_user

    deploy_users['cmds']=domain_commands;
    deploy_users['add_users']={}

    for domain in domain_commands:
        cmd=domain_commands[domain]
        controller_name = domain_leaders[domain]['name']
        print(domain_leaders[domain] )
        controller_addr = domain_leaders[domain]['control_addr'][0]     # uses control address
        domain_password = domain_leaders[domain]['admin_pass']
        print("Installing users for domain " + domain + " on server " + controller_addr)
        print("  controller name,addr:" + controller_name + "(" + controller_addr + ")")
        qualified_username='administrator@'+domain
        shell = ShellHandler(controller_addr,qualified_username,domain_password)
        stdout,stderr,exit_status = shell.execute_powershell(cmd, verbose=verbose)
        deploy_users['add_users'][domain]={ "cmd": cmd, "stdout": stdout, "stderr": stderr, "exit_status": exit_status}

    return deploy_users;

