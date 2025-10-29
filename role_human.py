from shell_handler import ShellHandler
import os

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
    """
    Install minimal dependencies to run the MITRE Caldera 'human' plugin on Windows
    using the embedded Python at C:\python (installed by join_domain_windows).

    Steps:
      1) Ensure C:\python exists and enable 'import site' and '.' in pythonXY._pth
      2) Upload the human plugin zip to the target host with ShellHandler.put_file
      3) Download and run get-pip.py to install pip into C:\python\Scripts
      4) Upgrade pip/setuptools/wheel
      5) Expand the uploaded zip and install dependencies from its requirements.txt

    Expects `human_plugin_version` to be a local path to the plugin zip on the
    controller/runner that is invoking this function.

    Returns a dict with stdout/stderr/exit_status.
    """
    # Local path to the plugin zip (provided by caller/environment)
    plugin_zip_local = human_plugin_version  # e.g., "/home/ubuntu/Downloads/workflows.zip"

    # Remote path where we'll upload the zip on the Windows host
    remote_zip_path = r"C:\\tmp\\human_plugin.zip"

    # Compose a resilient PowerShell script. It can be re-run safely.
    ps = f'''
$ErrorActionPreference = "Stop"

# --- Config ---
$PythonDir = "C:\\python"
$PythonExe = Join-Path $PythonDir "python.exe"
$GetPip    = "C:\\tmp\\get-pip.py"
$PluginZip = "{remote_zip_path}"
$HumanRoot = "C:\\human"
$ScriptsDir = Join-Path $PythonDir "Scripts"

# Ensure C:\\tmp exists
if (-not (Test-Path -LiteralPath "C:\\tmp"))
{{
    New-Item -ItemType Directory -Path "C:\\tmp" | Out-Null
}}

function Assert-File([string]$Path)
{{
    if (-not (Test-Path -LiteralPath $Path))
    {{
        throw "Required path not found: $Path"
    }}
}}


# --- Ensure C:\\python\\Scripts on PATH for *this session* (pip invocation) ---
if (-not ($env:PATH -split ";" | Where-Object {{ $_ -eq $ScriptsDir }}))
{{
    $env:PATH = "$ScriptsDir;" + $env:PATH
}}

# --- Bootstrap pip with get-pip.py ---
if (-not (Test-Path -LiteralPath (Join-Path $ScriptsDir "pip.exe")))
{{
    Write-Host "[*] Fetching get-pip.py"
    Invoke-WebRequest -UseBasicParsing -Uri "https://bootstrap.pypa.io/get-pip.py" -OutFile $GetPip

    Write-Host "[*] Running get-pip.py with embedded Python"
    & $PythonExe $GetPip --no-warn-script-location
}}
else
{{
    Write-Host "[*] pip already present"
}}

# --- Upgrade toolchain ---
Write-Host "[*] Upgrading pip/setuptools/wheel"
& (Join-Path $ScriptsDir "pip.exe") install --upgrade pip setuptools wheel

# --- Expand plugin and install its requirements ---
if (-not (Test-Path -LiteralPath $PluginZip))
{{
    throw "Plugin zip not found at $PluginZip. Upload likely failed."
}}

Write-Host "[*] Ensuring embedded Python exists at $PythonDir"
Assert-File $PythonExe

# --- Enable 'import site' and ensure '.' is on sys.path for embedded distro ---
# Embedded distros commonly ship pythonXY._pth (underscore). Support both patterns.
$pth = Get-ChildItem -LiteralPath $PythonDir -Filter "python*._pth" -File -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $pth)
{{
    # Fallback in case someone dropped a plain .pth
    $pth = Get-ChildItem -LiteralPath $PythonDir -Filter "python*.pth" -File -ErrorAction SilentlyContinue | Select-Object -First 1
}}

Add-Content 'C:\\python\\Lib\\site-packages\\_human_project.pth' 'C:\\human' -Encoding ASCII
Add-Content 'C:\\python\\Lib\\site-packages\\_human_project.pth' 'C:\\human' -Encoding ASCII

if ($null -eq $pth)
{{
    throw "Could not locate python*._pth or python*.pth under $PythonDir. The embedded distro layout looks unexpected."
}}

Write-Host "[*] Using path config file: $($pth.FullName)"

$orig = Get-Content -LiteralPath $pth.FullName -Raw
$new  = $orig

# Ensure a bare 'import site' line exists (uncomment or append)
$new = ($new -replace "(?m)^\s*#\s*import\s+site\s*$","import site")
if ($new -notmatch "(?m)^import site$")
{{
    $new = $new.TrimEnd() + "`r`nimport site`r`n"
}}

# Ensure a '.' line exists so the script directory is on sys.path
if ($new -notmatch "(?m)^\.$")
{{
    # Add '.' on its own line (append to be safe)
    $new = $new.TrimEnd() + "`r`n.`r`n"
}}

if ($new -ne $orig)
{{
    Write-Host "[*] Updating $($pth.Name) to include 'import site' and '.'"
    Set-Content -LiteralPath $pth.FullName -Value $new -Encoding ASCII
}}
else
{{
    Write-Host "[*] Path config already includes 'import site' and '.'"
}}

python -m pip install --upgrade pip setuptools wheel

Write-Host "[*] Unpacking plugin: $PluginZip -> $HumanRoot"
New-Item -ItemType Directory -Force -Path $HumanRoot | Out-Null
# Clean destination (but keep root folder) to allow re-runs
Get-ChildItem -LiteralPath $HumanRoot -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive -Path $PluginZip -DestinationPath $HumanRoot -Force

# Try to locate requirements.txt (top-level or nested). Use the first one found.
$req = Get-ChildItem -LiteralPath $HumanRoot -Recurse -Filter requirements.txt -File -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -ne $req)
{{
    Write-Host "[*] Installing dependencies from: $($req.FullName)"
    & (Join-Path $ScriptsDir "pip.exe") install -r $req.FullName
}}
else
{{
    Write-Host "[*] No requirements.txt found in plugin, skipping dependency install."
}}


Write-Host "[*] Installing Chrome."
$url = 'https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi'
$msi = "$env:TEMP\\chrome_installer.msi"
Write-Host "Downloading Chrome from $url"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
(New-Object Net.WebClient).DownloadFile($url, $msi)
Write-Host 'Installing via MSI...'
Start-Process msiexec -ArgumentList "/i `"$msi`" /qn /norestart ALLUSERS=1" -Wait

Write-Host "[OK] Windows human install done."
'''

    shell = ShellHandler(control_ipv4_addr, user, password, verbose=verbose, retries=3, timeout=60)

    # Upload the plugin zip to the Windows host before running the PowerShell steps
    if not os.path.exists(plugin_zip_local):
        return {
            "node_details": node,
            "stdout": "",
            "stderr": f"Local plugin zip not found: {plugin_zip_local}",
            "exit_status": 1,
        }

    # Ensure remote directory exists and upload the file
    shell.put_file(plugin_zip_local, remote_zip_path)

    stdout, stderr, exit_status = shell.execute_powershell_multiline(ps, 'install-human.ps1', verbose=verbose, retries=10)

    return {
        "node_details": node,
        "stdout": stdout,
        "stderr": stderr,
        "exit_status": exit_status,
    }


def install_human_linux(node, user, control_ipv4_addr, password, cloud_config):
    print(f"Installing human plugin support as user {user} on node {node['name']} ", flush=True)
    shell = ShellHandler(control_ipv4_addr, user, password=None, verbose=verbose, retries=1)
    shell.put_file(human_plugin_version, '/tmp/pyhuman.zip')

    enterprise_url = cloud_config['enterprise_url']
    domain = node['domain']

    packages = 'python3 python3-pip virtualenv xvfb unzip build-essential git autotools-dev autoconf libncursesw5-dev libtool autoconf automake bison flex libevent-dev ncurses-dev golang-go ninja-build gettext libtool libtool-bin autoconf automake cmake g++ pkg-config unzip curl doxygen gnutls-dev libgnutls28-dev pkg-config build-essential groff-base libpipeline-dev libgdbm-dev groff libtool m4 xz-utils lzip'
    cmd = f"""
        set -x
        sudo rm -rf /opt/pyhuman
        sudo mkdir -p /opt/pyhuman
        cd /opt/pyhuman
        sudo env DEBIAN_FRONTEND=noninteractive apt update
        sudo env DEBIAN_FRONTEND=noninteractive apt install -y {packages}
        sudo unzip /tmp/pyhuman.zip
        sudo sed -i "s/castle.castle.os/{domain}.{enterprise_url}/" /opt/pyhuman/app/workflows/*.py
        sudo sed -i "s/castle.project1.os/{domain}.{enterprise_url}/" /opt/pyhuman/app/workflows/*.py
        sudo sed -i "s/castle.os/{enterprise_url}/" /opt/pyhuman/app/workflows/*.py
        sudo sed -i "s/project1.os/{enterprise_url}/" /opt/pyhuman/app/workflows/*.py
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
    print(f"Setting up human plugin for {node['name']}")

    if user == "Administrator":
        return install_human_windows(node, user, control_ipv4_addr, password, cloud_config)
    elif user == "ubuntu":
        return install_human_linux(node, user, control_ipv4_addr, password, cloud_config)
    else:
        msg = (f"No information for how to install human on node with username='{user}'")
        print(msg)
        return msg
