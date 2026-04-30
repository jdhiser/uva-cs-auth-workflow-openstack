import os
import time
import role_fs
import paramiko
from shell_handler import ShellHandler


domain_safe_mode_password = 'hello!321'
verbose = False

gpupdate_str = """$MaxRetries = 15       # how many times to retry
$DelaySeconds = 60    # wait time between retries

for ($i = 1; $i -le $MaxRetries; $i++) {
    Write-Host "[$i/$MaxRetries] Running gpupdate /force..."
    gpupdate /force

    # check exit code – 0 usually means success
    if ($LASTEXITCODE -eq 0) {
        Write-Host "gpupdate succeeded."
        break
    }

    Write-Warning "gpupdate failed (exit code $LASTEXITCODE)."
    if ($i -lt $MaxRetries) {
        Write-Host "Waiting $DelaySeconds seconds before retry..."
        Start-Sleep -Seconds $DelaySeconds
    }
}

if ($LASTEXITCODE -ne 0) {
    Write-Error "gpupdate failed after $MaxRetries attempts."
}

"""

#
# Function: fqdn_to_dn
# --------------------
# Convert a fully-qualified domain name (FQDN) into an LDAP-style
# distinguished name suffix suitable for AD CS (e.g., "DC=castle,DC=project1,DC=os").
#
# Parameters:
#   fqdn_domain_name (str): Domain FQDN such as "castle.project1.os"
#
# Returns:
#   str: Distinguished name string such as "DC=castle,DC=project1,DC=os"
#


def fqdn_to_dn(fqdn_domain_name: str) -> str:
    # Split the FQDN into labels (castle, project1, os)
    parts = fqdn_domain_name.strip().split('.')

    # Remove any empty components (defensive)
    parts = [p for p in parts if p]

    # Join them as DC components
    dn = ','.join(f"DC={p}" for p in parts)

    return dn


def deploy_forest(cloud_config, name, control_ipv4_addr, game_ipv4_addr, password, domain):

    user = 'Administrator'
    domain_name = domain + '.' + cloud_config['enterprise_url']
    print("  Setting safe-mode password for domain to " + password)

    adcmd = (f"""
        net user administrator {password}
        net user administrator /passwordreq:yes
        reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\NtpServer /v Enabled /t REG_DWORD /d 1 /f
        reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters /v Type /t REG_SZ /d NTP /f
        reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Config /v AnnounceFlags /t REG_DWORD /d 5 /f
        tzutil /s 'Eastern Standard Time'
        w32tm /config /manualpeerlist:'pool.ntp.org,0x1' /syncfromflags:manual /reliable:yes /update
        net stop w32time
        net start w32time
        w32tm /resync /force
        w32tm /config /manualpeerlist:\"time.google.com 0.pool.ntp.org 1.pool.ntp.org\" /syncfromflags:manual /reliable:yes /update
        net stop w32time
        net start w32time
        w32tm /resync
        w32tm /query /status
        Install-windowsfeature AD-domain-services
        Import-Module ADDSDeployment
        $secure=ConvertTo-SecureString -asplaintext -string {domain_safe_mode_password} -force
        Install-ADDSForest -domainname {domain_name} -SafeModeAdministratorPassword $secure -verbose -NoRebootOnCompletion:$true -Force:$true
        wget https://www.python.org/ftp/python/3.12.1/python-3.12.1-embed-amd64.zip -Outfile python.zip
        Expand-Archive -force .\\python.zip
        mv python c:\\
        icacls "c:\\python" /grant:r "users:(RX)" /C
        $oldpath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name PATH).path
        $newpath = "$oldpath;C:\\python"
        Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name PATH -Value $newpath
        """)

    if verbose:
        print("  Register forest command:" + adcmd)

    shell = ShellHandler(control_ipv4_addr, user, password)
    stdout, stderr, exit_status = shell.execute_powershell_multiline(adcmd, filename="deploy-forest.ps1", verbose=verbose)
    try:
        shell.execute_powershell('Restart-computer -force', verbose=verbose)
    except Exception:
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
                print(f"  output={output}")
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

    remove_control_network_from_dns_cmd = (f"""
        set-dnsclient -interfacealias 'control-adapter' -registerthisconnectionsaddress 0
        $srv=$(get-dnsserversetting -all)
        $srv.ListeningIPAddress=@( {game_ipv4_addr} )
        set-dnsserversetting -inputobject $srv
        ipconfig /flushdns
        ipconfig /registerdns
        dcdiag /fix  """
    )

    shell = ShellHandler(control_ipv4_addr, user, password)
    stdout3, stderr3, exit_status3 = shell.execute_powershell_multiline(remove_control_network_from_dns_cmd, filename="fix-dns.ps1", verbose=verbose)

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

    adcmd = """
        wget https://www.python.org/ftp/python/3.12.1/python-3.12.1-embed-amd64.zip -Outfile python.zip
        Expand-Archive -force .\\python.zip
        mv python c:\\
        icacls "c:\\python" /grant:r "users:(RX)" /C
        reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\NtpServer /v Enabled /t REG_DWORD /d 1 /f
        reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters /v Type /t REG_SZ /d NTP /f
        reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Config /v AnnounceFlags /t REG_DWORD /d 5 /f
        tzutil /s 'Eastern Standard Time'
        w32tm /config /manualpeerlist:'pool.ntp.org,0x1' /syncfromflags:manual /reliable:yes /update
        net stop w32time
        net start w32time
        w32tm /resync /force
        w32tm /config /manualpeerlist:"time.google.com 0.pool.ntp.org 1.pool.ntp.org" /syncfromflags:manual /reliable:yes /update
        net stop w32time
        net start w32time
        w32tm /resync
        w32tm /query /status
        Install-windowsfeature AD-domain-services
        Import-Module ADDSDeployment
        Set-DnsClientServerAddress -serveraddress ('{}') -interfacealias 'game-adapter'
        Set-DnsClientServerAddress -serveraddress ('{}') -interfacealias 'control-adapter'
        $passwd = convertto-securestring -AsPlainText -Force -String '{}'
        $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist '{}\\administrator',$passwd
        $secure=ConvertTo-SecureString -asplaintext -string '{}' -force
        sleep 60
        Install-ADDSDomainController -DomainName {} -SafeModeAdministratorPassword $secure -verbose -NoRebootOnCompletion:$true  -confirm:$false -credential $cred
        $oldpath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name PATH).path
        $newpath = "$oldpath;C:\\python"
        Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name PATH -Value $newpath
    """.format(game_leader_ip, game_leader_ip, leader_admin_password, domain_name, domain_safe_mode_password, domain_name)

    stdout = []
    stderr = []
    exit_status = []

    max_install_attempts = 3
    install_succeeded = False
    for install_attempt in range(1, max_install_attempts + 1):
        try:
            print(f"  Trying to install AD and join domain on {name} (attempt {install_attempt}/{max_install_attempts})")
            shell = ShellHandler(control_ipv4_addr, user, password, retries=2)
            stdout2, stderr2, exit_status2 = shell.execute_powershell_multiline(adcmd, filename="ad-install.ps1", verbose=verbose)
            stdout.append(stdout2)
            stderr.append(stderr2)
            exit_status.append(exit_status2)
            install_succeeded = True
            break
        except Exception as e:
            print(f"  Install AD attempt {install_attempt} failed: {type(e).__name__}: {e}")
            if install_attempt < max_install_attempts:
                print("  Sleeping 30s before retrying install...")
                time.sleep(30)

    if not install_succeeded:
        errstr = f"Failed to install AD on {name} after {max_install_attempts} attempts"
        raise RuntimeError(errstr)

    print(f"  Trying to finalize domain join of {name}")
    try:
        shell = ShellHandler(control_ipv4_addr, user, password, retries=1)
        shell.execute_powershell('Restart-computer -force', verbose=verbose)
    except Exception as e:
        # Socket errors during reboot are expected — the SSH session dies as the host goes down.
        print(f"  Reboot triggered (received expected exception {type(e).__name__}: {e})")

    print(f"  Waiting for domain join confirmation from {name}")
    time.sleep(10)
    status_received = False
    attempts = 0
    verify_timeout_sec = 20 * 60
    verify_deadline = time.time() + verify_timeout_sec
    while not status_received and time.time() < verify_deadline:
        try:
            attempts += 1
            remaining = int(verify_deadline - time.time())
            print(f"  Verifying AD startup on {name} (attempt {attempts}, {remaining}s remaining)")
            shell = ShellHandler(control_ipv4_addr, user, leader_admin_password, retries=1)
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
            print(f"  SSH exception {type(e).__name__} handled, retrying: {e}")
            time.sleep(10)

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

    print(f"  Reboot of {name} complete, domain join verified!")

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
        print("  Linux join-domain for node " + name)
        return join_domain_linux(obj, name, leader_admin_password, control_ipv4_addr, game_ipv4_addr, domain_ips, fqdn_domain_name, domain_name, password, enterprise_name)
    else:
        errstr = "  No endpoint/domain enrollment for node " + name
        raise RuntimeError(errstr)


def join_domain_windows(name, leader_admin_password, control_ipv4_addr, game_ipv4_addr, domain_ips, fqdn_domain_name, domain_name, password):

    print("  Windows join-domain for node " + name)

    user = 'Administrator'
    cmd = f"""
$passwd = convertto-securestring -AsPlainText -Force -String {leader_admin_password}
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist 'administrator@{domain_name}',$passwd
Set-DnsClientServerAddress -serveraddress ({domain_ips}) -interfacealias 'game-adapter'

# Retry Add-Computer up to 3 times
$maxRetries = 5
$retryDelay = 60
for ($i = 1; $i -le $maxRetries; $i++) {{
    try {{
        Write-Host "Attempt $i to join domain {fqdn_domain_name}..."
        Add-Computer -Credential $cred -DomainName {fqdn_domain_name} -ErrorAction Stop
        Write-Host "Successfully joined the domain."
        break
    }} catch {{
        Write-Warning "Attempt $i failed: $($_.Exception.Message)"
        if ($i -lt $maxRetries) {{
            Write-Host "Waiting $retryDelay seconds before retry..."
            Start-Sleep -Seconds $retryDelay
        }} else {{
            Write-Error "All attempts to join domain failed."
            exit 1
        }}
    }}
}}

if (Test-Path 'C:\\Python') {{
    Remove-Item -Path 'C:\\Python' -Recurse -Force
}}

wget https://www.python.org/ftp/python/3.12.1/python-3.12.1-embed-amd64.zip -Outfile python.zip
Expand-Archive -force .\\python.zip
mv python c:\\
icacls 'c:\\python' /grant:r "users:(RX)" /C
$oldpath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name PATH).path
$newpath = "$oldpath;C:\\python"
Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name PATH -Value $newpath
"""

    print(f"  {name} is joining an existing domain: {domain_name}")

    shell = ShellHandler(control_ipv4_addr, user, password)
    stdout, stderr, exit_status = shell.execute_powershell_multiline(cmd, filename="join-domain", verbose=verbose)

    try:
        shell = ShellHandler(control_ipv4_addr, user, password)
        shell.execute_powershell('Restart-computer -force', verbose=verbose)
    except Exception:
        pass

    print(f"  Waiting for reboot of windows domain member {name} with ip={control_ipv4_addr}.")
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
                'gpupdate /force; echo "the domain is $env:userdomain" ', verbose=verbose)
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


def install_ca_certs_from_ad(obj, leader_admin_password: str):
    """
    install_ca_certs_from_ad

    Retrieves the Root and Subordinate CA certificates from the domain controller using LDAP,
    saves them to the local trust store, and updates the system CA certificates.

    Parameters:
    - obj: dict - Node and domain configuration object from join_domain_linux
    - leader_admin_password: str - the password for the domain controller in charge of the domain

    Returns:
    - dict: stdout, stderr, exit_status from the installation step
    """

    cloud_config = obj['cloud_config']
    node = obj['node']
    name = node['name']
    domain_name = obj['domain']
    enterprise_name = cloud_config['enterprise_url']
    fqdn_domain_name = domain_name + '.' + enterprise_name
    base_dn = ','.join([f'DC={x}' for x in fqdn_domain_name.split('.')])
    ldap_base = f"CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,{base_dn}"
    leader = obj['domain_leader']
    control_ipv4_addr = obj['control_addr']
    game_leader_addr = leader['game_addr'][0]

    print(f"  Attempting to trust Root and Subordinate CAs for domain {fqdn_domain_name} on node {name}...")

    cmd = f"""
sudo bash << 'EOT' 2>&1 | sudo tee -a /var/log/install_ca_certs.log
set -x
whoami

export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
sudo apt-get install -y ldap-utils openssl

# Create output directory for certs
mkdir -p /usr/local/share/ca-certificates/castle
cd /usr/local/share/ca-certificates/castle

# Retrieve certs using ldapsearch
ldap_output=$(ldapsearch -x -w {leader_admin_password}  -D 'administrator@{domain_name}.{enterprise_name}' -H ldap://{game_leader_addr} \
  -b "{ldap_base}" \
  -s sub \
  "(objectClass=*)" \
  cACertificate)

if ! echo "$ldap_output" | grep -q '^cACertificate::'; then
    echo "No CA certificates found in LDAP. Skipping installation."
    echo "NO_CA_FOUND_MARKER"
    exit 0
fi

# Properly extract multi-line base64-encoded certificates
echo "$ldap_output" | awk '
    /^cACertificate:: / {{
        collecting = 1;
        print substr($0, index($0, "::") + 3);
        next;
    }}
    collecting && /^[ \t]/ {{
        gsub(/^[ \t]+/, "");
        print;
        next;
    }}
    collecting {{
        collecting = 0;
    }}
' | base64 -d > combined_cas.der

if [[ ! -s combined_cas.der ]]; then
    echo "Error: No certificates retrieved from LDAP." >&2
    exit 1
fi

# Split certs (if needed) and convert to PEM
csplit -f part_ -b "%02d.der" combined_cas.der '/-----BEGIN/' '{{*}}' || true

cert_count=0
for f in part_*.der; do
    if openssl x509 -inform DER -in "$f" -out "${{f%.der}}.crt"; then
        rm "$f"
        ((cert_count++))
    fi
done

if (( cert_count == 0 )); then
    echo "Error: No valid certificates converted from DER." >&2
    exit 1
fi

# Copy .crt files to CA store
cp *.crt /usr/local/share/ca-certificates/

# Update CA certificates and log result
update-ca-certificates | tee /tmp/update-ca-certs.out
EOT
"""

    shell = ShellHandler(control_ipv4_addr, 'ubuntu', None, retries=2)
    stdout, stderr, exit_status = shell.execute_cmd(cmd, verbose=False)

    # Check if no CA was found and installation skipped
    if any("NO_CA_FOUND_MARKER" in line for line in stdout):
        print("  No CA published in domain. Skipping certificate installation.")
    else:
        install_success = any(
            "Adding debian:" in line or "Adding certificate" in line or "Updating certificates" in line
            for line in stdout
        )

        if not install_success:
            print("install_ca_certs_from_ad failed to detect success")
            print("STDOUT:\n" + ''.join(stdout))
            print("STDERR:\n" + ''.join(stderr))
            print("EXIT STATUS:\n" + str(exit_status))
            raise RuntimeError("Failed to verify that CA certificates were installed from domain controller")

        print(f"  Successfully trusted CA certificates for domain {fqdn_domain_name} on node {name}.")

    return {
        "install_ca_certs": {
            "stdout": stdout,
            "stderr": stderr,
            "exit_status": exit_status
        }
    }


def join_domain_linux(obj,
                      name,
                      leader_admin_password,
                      control_ipv4_addr,
                      game_ipv4_addr,
                      domain_ips,
                      fqdn_domain_name,
                      domain_name,
                      password,
                      enterprise_name
                      ):
    netplan_config_path = '/etc/netplan/50-cloud-init.yaml'
    chrony_config_path = '/etc/chrony/chrony.conf'
    domain_ips_formated = str(domain_ips).replace('[', '').replace(']', '').replace('"', '')
    krdb_config_path = '/etc/krb5.conf'

    ca_trust = install_ca_certs_from_ad(obj, leader_admin_password)

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
sudo sed -i -E 's/^( *)dhcp4: true$/&\\n\\1nameservers:\\n\\1  addresses: [ {domain_ips_formated} ]/' {netplan_config_path}

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
sudo sed -i '/\\[libdefaults\\]/a \\  rdns=false ' {krdb_config_path}

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
            shell = ShellHandler(control_ipv4_addr, admin_user, leader_admin_password, timeout=30)
            stdout2, stderr2, exit_status2 = shell.execute_cmd('realm list', verbose=verbose)
            if not 'realm-name: {}'.format(fqdn_domain_name.upper()) in str(stdout2):
                print(f"  Realm list did not return fqdn ({fqdn_domain_name}), retrying.")
                time.sleep(5)
            else:
                status_received = True
        except Exception:
            print(f"  Waiting domain join to complete for ip={control_ipv4_addr}.")

            time.sleep(5)
            pass

    try:
        stdout2
    except Exception:
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
        "verify_join_domain": {"stdout": stdout2, "stderr": stderr2, "exit_status": exit_status2},
        "ca_trust_output": ca_trust
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
        shell = ShellHandler(controller_addr, qualified_username, domain_password, retries=1)
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

    name = node['name']
    domain_name = node['domain']
    enterprise_name = cloud_config['enterprise_url']
    fqdn_domain_name = domain_name + '.' + enterprise_name
    dn_suffix = fqdn_to_dn(fqdn_domain_name)
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
    adcs_cmd = gpupdate_str + rf"""

        Install-WindowsFeature AD-Domain-Services
        Get-ADDomain
        Install-WindowsFeature ADCS-Cert-Authority
        Import-Module ADCSDeployment
        for ($i = 1; $i -le $MaxRetries; $i++) {{
            Write-Host "[$i/$MaxRetries] Running Install-AdcsCertificationAuthority"
            try {{
                Install-AdcsCertificationAuthority -CAType EnterpriseRootCA `
                    -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' `
                    -KeyLength 2048 `
                    -HashAlgorithmName SHA256 `
                    -ValidityPeriod Years -ValidityPeriodUnits 5 `
                    -CACommonName "{domain_name}-RootCA" `
                    -CADistinguishedNameSuffix "{dn_suffix}" `
                    -Force
                Write-Host "Install-AdcsCertificationAuthority succeeded."
                break
            }} catch {{
                Write-Warning "Install-AdcsCertificationAuthority failed."
                if ($i -lt $MaxRetries) {{
                    Write-Host "Waiting $DelaySeconds seconds before retry..."
                    Start-Sleep -Seconds $DelaySeconds
                }}
                else {{
                    Write-Error "Install-AdcsCertificationAuthority failed after $MaxRetries attempts."
                }}
            }}
        }}

        # debug output
        Get-ChildItem C:\Windows\System32\CertSrv\CertEnroll | Where-Object Name -like "*RootCA*"

        # make sure certs are published.
        certutil -dspublish -f "C:\Windows\System32\CertSrv\CertEnroll\{name}.{domain_name}.{enterprise_name}_{domain_name}-RootCA.crt" RootCA
        certutil -dspublish -f "C:\Windows\System32\CertSrv\CertEnroll\{name}.{domain_name}.{enterprise_name}_{domain_name}-RootCA.crt" NTAuthCA
        certutil -dspublish -f "C:\Windows\System32\CertSrv\CertEnroll\{domain_name}-RootCA.crl"
        certutil -dspublish -f "C:\Windows\System32\CertSrv\CertEnroll\{domain_name}-RootCA+.crl"

        """

    # Create a shell session to the target machine
    shell = ShellHandler(control_ipv4_addr, domain_name + '\\' + 'administrator', leader_admin_password, retries=1)

    # Execute the multi-line PowerShell command
    try:
        adcs_stdout, adcs_stderr, adcs_exit_status = shell.execute_powershell_multiline(
            adcs_cmd, verbose=verbose, filename='install-rootca.ps1')
    except Exception as e:
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

    if '  Verified RootCA was setup properly' not in str(verify_stdout):
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

    name = node['name']
    domain_name = node['domain']
    enterprise_name = cloud_config['enterprise_url']
    fqdn_domain_name = domain_name + '.' + enterprise_name
    dn_suffix = fqdn_to_dn(fqdn_domain_name)
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
    cmd = gpupdate_str + f"""

    Write-Host "=== Subordinate CA install starting for {name} ({domain_name}) ==="

    # Basic domain / time sanity checks
    Install-WindowsFeature AD-Domain-Services
    Get-ADDomain
    whoami /groups
    Write-Host "LOGONSERVER env var at start: $env:LOGONSERVER"
    klist
    w32tm /query /status

    # Ensure ADCS role is present
    Install-WindowsFeature ADCS-Cert-Authority
    Import-Module ADCSDeployment

    # Confirm we can find a DC
    nltest /dsgetdc:{domain_name}

    function Get-SubCAState {{
        param(
            [Parameter(Mandatory=$true)][string] $CACommonName
        )

        $feature     = Get-WindowsFeature ADCS-Cert-Authority
        $hasFeature  = $feature -and $feature.Installed

        $configKey   = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\$CACommonName"
        $hasConfig   = Test-Path $configKey

        $caInfoOk    = $false
        try {{
            $out = certutil -CAInfo | Out-String
            if ($out -match 'CertUtil: -CAInfo command completed successfully') {{
                $caInfoOk = $true
            }}
        }} catch {{
            # ignore, just report false
        }}

        [PSCustomObject]@{{
            FeatureInstalled = $hasFeature
            ConfigExists     = $hasConfig
            CAInfoOk         = $caInfoOk
        }}
    }}

    $maxRetries = 20
    $retryDelay = 30
    $success    = $false
    $caName     = "{domain_name}-SubCA"

    # If the SubCA already appears installed and healthy, treat this as success
    $state = Get-SubCAState -CACommonName $caName
    if ($state.CAInfoOk -and $state.ConfigExists) {{
        Write-Host "Subordinate CA '$caName' already appears fully configured. Skipping Install-AdcsCertificationAuthority."
        $success = $true
    }}

    if (-not $success) {{
        for ($i = 1; $i -le $maxRetries; $i++) {{
            Write-Host ("[{0}] === Attempt $i of $maxRetries ===" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
            Write-Host "LOGONSERVER env var (attempt $i): $env:LOGONSERVER"

            try {{
                $rootdse = [ADSI]"LDAP://RootDSE"
                Write-Host "Connected Config NC: $($rootdse.configurationNamingContext)"
                Write-Host "Connected to DC    : $($rootdse.dnsHostName)"
            }} catch {{
                Write-Warning "Could not read RootDSE: $($_.Exception.Message)"
            }}

            try {{
                Install-AdcsCertificationAuthority `
                    -CAType EnterpriseSubordinateCA `
                    -CACommonName $caName `
                    -CADistinguishedNameSuffix "{dn_suffix}" `
                    -Force

                Write-Host "AD CS SubordinateCA request created (attempt $i)."
                $success = $true
                break
            }} catch {{
                $msg = $_.Exception.Message
                Write-Warning "Attempt $i failed: $msg"
                Write-Warning ("Full exception: {0}" -f ($_.Exception | Format-List * | Out-String))

                # If the CA is already installed, treat this as success (idempotent behavior).
                if ($msg -match 'The Certification Authority is already installed') {{
                    Write-Host "CA reports as already installed. Treating as success for idempotency."
                    $success = $true
                    break
                }}

                # Collect additional context to help debugging real failures
                Write-Host "Current Kerberos tickets:"
                klist

                Write-Host "Current group memberships:"
                whoami /groups

                Write-Host "Time sync status:"
                w32tm /query /status

                Write-Host "Secure channel / DC info:"
                nltest /sc_query:{domain_name}

                # Re-check CA state after the failure – if it became healthy, stop retrying.
                $stateAfter = Get-SubCAState -CACommonName $caName
                if ($stateAfter.CAInfoOk -and $stateAfter.ConfigExists) {{
                    Write-Host "After failure, CA now appears healthy. Treating as success."
                    $success = $true
                    break
                }}

                if ($i -lt $maxRetries) {{
                    Write-Host "Sleeping $retryDelay seconds before retry..."
                    Start-Sleep -Seconds $retryDelay
                }} else {{
                    Write-Error "AD CS SubordinateCA installation failed after $maxRetries attempts."
                    Write-Host "Last 50 lines of certocm.log for context:"
                    Get-Content -Tail 50 C:\\Windows\\certocm.log
                    throw
                }}
            }}
        }}
    }}

    if (-not $success) {{
        Write-Error "Subordinate CA install did not complete successfully."
        exit 1
    }} else {{
        Write-Host "Subordinate CA install completed or was already present."
    }}
"""

    try:
        adcs_exit_status = 1
        count = 0
        while count < 5 and adcs_exit_status != 0:
            shell = ShellHandler(control_ipv4_addr, domain_name + '\\' + 'administrator', leader_admin_password)
            adcs_stdout, adcs_stderr, adcs_exit_status = shell.execute_powershell_multiline(
                cmd, filename="install-subca.ps1", verbose=verbose)
            count += 1
    except Exception as e:
        raise RuntimeError(f"Authentication failed: {e}")

    # Verify Subordinate CA role installed
    verify_stdout = None
    for attempt in range(3):
        verify_cmd = "Get-WindowsFeature ADCS-Cert-Authority"
        shell = ShellHandler(control_ipv4_addr, domain_name + '\\' + 'administrator', leader_admin_password)
        try:
            verify_stdout, verify_stderr, verify_exit_status = shell.execute_powershell(verify_cmd, verbose=verbose)
            break
        except Exception:
            time.sleep(10)

    if 'Installed' not in str(verify_stdout):
        print(f"adcs_stdout = {adcs_stdout}")
        print(f"adcs_stderr = {adcs_stderr}")
        print(f"verify_stdout = {verify_stdout}")
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


def _wait_for_root_pki_ready(root_shell, template_name="SubCA", timeout_sec=300, poll_sec=15):
    """
    Wait until the Enterprise Root CA can see its AD CS PKI objects
    and the specified template name, or raise RuntimeError on timeout.
    """
    import time

    deadline = time.time() + timeout_sec
    attempt = 0

    while time.time() < deadline:
        attempt += 1
        print(f"  [rootca-pki-check] Attempt {attempt}: verifying CA and template '{template_name}'...")

        # 1) Check CAInfo
        ca_cmd = "certutil -CAInfo"
        ca_out, ca_err, ca_status = root_shell.execute_powershell(
            ca_cmd, verbose=verbose
        )

        if ca_status != 0:
            print(f"    certutil -CAInfo not ready yet (exit={ca_status})")
            time.sleep(poll_sec)
            continue

        # 2) Check templates list
        tmpl_cmd = "certutil -catemplates"
        tmpl_out, tmpl_err, tmpl_status = root_shell.execute_powershell(
            tmpl_cmd, verbose=verbose
        )

        if tmpl_status != 0 or template_name.lower() not in str(tmpl_out).lower():
            print(f"    Template '{template_name}' not visible yet (exit={tmpl_status})")
            print(f"    [debug] catemplates_status={tmpl_status}")
            print(f"    [debug] catemplates_out=\n{tmpl_out}")
            print(f"    [debug] catemplates_err=\n{tmpl_err}")
            time.sleep(poll_sec)
            continue

        print("  [rootca-pki-check] Root CA PKI looks ready, with:")
        print(f"    [debug] catemplates_status={tmpl_status}")
        print(f"    [debug] catemplates_out=\n{tmpl_out}")
        print(f"    [debug] catemplates_err=\n{tmpl_err}")
        return

    raise RuntimeError(
        f"Root CA PKI did not become ready within {timeout_sec} seconds "
        f"(template='{template_name}')."
    )


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

    sub_node = sub_info['node']
    sub_name = sub_node['name']
    sub_ip = sub_info['control_ip']
    domain = sub_info['domain']
    enterprise_url = sub_info['enterprise_url']

    sub_req_file = f"C:\\{sub_name}.{domain}.{enterprise_url}_{domain}-SubCA.req"

    root_ip = root_info['control_addr']
    root_password = root_info['admin_pass']

    tmp_dir = "tmp"
    os.makedirs(tmp_dir, exist_ok=True)

    local_req = os.path.join(tmp_dir, f"{sub_name}.req")
    local_cer = os.path.join(tmp_dir, f"{sub_name}.cer")

    remote_req = f"C:\\tmp\\{sub_name}.req"
    remote_cer = f"C:\\tmp\\{sub_name}.cer"

    admin_upn = f"{domain}\\Administrator"

    sub_shell = ShellHandler(sub_ip, admin_upn, root_password, retries=50)
    root_shell = ShellHandler(root_ip, admin_upn, root_password, retries=50)

    _wait_for_root_pki_ready(root_shell, template_name="SubCA", timeout_sec=900, poll_sec=15)

    # Ensure C:\tmp exists on both systems
    sub_shell.execute_cmd("mkdir C:\\tmp", verbose=verbose)
    root_shell.execute_cmd("mkdir C:\\tmp", verbose=verbose)

    # Step 1: Fetch subordinate .req
    sub_shell.get_file(sub_req_file, local_req)

    # Step 2: Send .req to root CA
    root_shell.put_file(local_req, remote_req)

    # Step 3: Submit request on root CA and save .cer
    sign_cmd = f"""
$ErrorActionPreference = 'Stop'
certreq -submit -q -f -attrib "CertificateTemplate:SubCA" "{remote_req}" "{remote_cer}"
Restart-Service certsvc
"""

    max_sign_attempts = 5

    for attempt in range(1, max_sign_attempts + 1):
        print(f"  [subca-sign] Attempt {attempt}/{max_sign_attempts} to sign SubCA request on root CA...")
        stdout, stderr, exit_status = root_shell.execute_powershell_multiline(
            sign_cmd,
            verbose=verbose,
            filename=f"sign_request_attempt{attempt}.ps1"
        )

        # Detect success: exit code 0 and no "Certificate not issued" / "Denied"
        txt = (str(stdout) + "\n" + str(stderr)).lower()
        if exit_status == 0 and "certificate not issued" not in txt and "denied by policy module" not in txt:
            print("  [subca-sign] certreq appears to have succeeded.")
            break

        if attempt < max_sign_attempts:
            print(f"  [subca-sign] certreq did not succeed (exit={exit_status}), retrying in 30s...")
            time.sleep(30)
        else:
            # Final failure
            raise RuntimeError(
                "Failed to sign SubCA request on root CA.\n"
                f"exit_status={exit_status}\n"
                f"stdout={stdout}\n"
                f"stderr={stderr}\n"
                "See sign_request_attempt*.ps1 on the root CA for full details."
            )

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

# Wait until the SubCA cert chains to a trusted root (ignore revocation during bootstrap)
function Wait-SubCAChainReady
{
    param(
        [Parameter(Mandatory=$true)][string] $CertPath,
        [int] $TimeoutSec = 300,
        [int] $PollSec = 3
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $sub = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath)

    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    # Ignore revocation while bootstrapping (we just care about PartialChain vs trusted root)
    $chain.ChainPolicy.RevocationMode  = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $chain.ChainPolicy.RevocationFlag  = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
    $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreWrongUsage

    do
    {
        # Attempt chain build
        $ok = $chain.Build($sub)

        if ($ok)
        {
            # Chain now builds cleanly to a trusted root
            return $true
        }

        # ------------------------------------------------------------------
        # NEW: Hint Windows to refresh Enterprise Roots & CA chain data
        # ------------------------------------------------------------------
        try
        {
            # Refresh auto-enrolled certificates + enterprise trust lists
            certutil -pulse | Out-Null
        }
        catch { }

        try
        {
            # Refresh group-policy-delivered CA trust (without reboot)
            gpupdate /target:computer /force | Out-Null
        }
        catch { }

        # ------------------------------------------------------------------
        # NEW: Backoff to avoid hammering DC/CA
        # ------------------------------------------------------------------
        Start-Sleep -Seconds $PollSec
    }
    while ((Get-Date) -lt $deadline)

    Write-Error "Timed out waiting for the SubCA cert to chain to a trusted root (PartialChain persisted)."
    return $false
}

# Usage:
if (-not (Wait-SubCAChainReady -CertPath 'C:\\tmp\\subca.cer' -TimeoutSec 300))
{
    exit 1
}



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
        certutil -f -v -addstore CA C:\\tmp\\subca.cer
        # sometimes hangs?
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


# wait for services to be ready
$maxWaitSeconds = 300
$intervalSeconds = 5
$elapsed = 0
$success = $false

while ($elapsed -lt $maxWaitSeconds)
{
    try
    {
        $output = certutil -CAInfo | Out-String
        if ($output -match 'CertUtil: -CAInfo command completed successfully')
        {
            Write-Host "CertUtil verified: CAInfo command succeeded."
            $success = $true
            break
        }
    }
    catch
    {
        # Ignoring exception, will retry
    }

    Start-Sleep -Seconds $intervalSeconds
    $elapsed += $intervalSeconds
}

if (-not $success)
{
    Write-Warning "Timed out waiting for certutil -CAInfo to succeed."
}

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
            "verify_cert": {
                "stdout": verify_out,
                "stderr": verify_err,
                "exit_status": verify_exit_status
            }
        }
    }
