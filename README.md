# macOS Setup

## Elevator Pitch
**Why this exists:** Most people trust Apple's defaults, but those prioritize convenience over security: processes can persist on startup, DNS queries leak browsing history, system file changes go unaudited, and background services (like iCloud sync) run even when disabled in settings. This setup blocks unauthorized programs and allows manual tracing when processes modify critical directories.

**What it achieves:** The system blocks unauthorized executables, encrypts and validates all DNS traffic, maintains cryptographic checksums of system files, and complies with government security baselines (CNSSI-1253 in particular).

| Component | What It Does | Key Features |
|-----------|-------------|--------------|
| **Application allowlisting (Santa)** | Block unauthorized executables | • Signing ID-based blocking<br>• Protect sensitive files (SSH keys, configs) |
| **NIST compliance (mSCP)** | Apply government-level security standards | • CNSSI-1253 baseline (~96-100% compliance)<br>• Enforce telemetry and firewall rules |
| **File integrity monitoring (AIDE)** | Detect unauthorized file changes | • Monitor LaunchDaemons/LaunchAgents<br>• Detect PAM modifications |
| **DNS hardening** | Encrypt and validate DNS queries | • DNSCrypt-proxy for encrypted queries<br>• Unbound for DNSSEC validation + caching |
| **Application isolation** | Limit app privileges | • Restrict write access to system directories<br>• Prevent persistence in `/Library` paths |
| **Shell environment** | Secure development tools | • Hardened SSH (modern algorithms, multiplexing)<br>• GPG for commit signing |

Time investment: ~90 minutes from a fresh install with decent Internet connectivity.

*This is not the most convenient, most resource-optimized, or most secure configuration. It is simply what works best for me.*

## 0. Basics

- `launchd` should not be modified like `systemctl` as the former is not designed for user tweaks
  - This rule also applies to "UI skins," custom plugins, etc. since they might break with future updates
  - I.e., one should not change any obscure settings (e.g., `defaults write com.apple.something`) unless they know exactly what they are doing
- Do not use the admin account besides initializing the machine
- Do not install any apps as Admin unless necessary, as some should run just fine outside the root directory (e.g. `/Users/warren/Applications`)
  - Said apps will prompt for password if they need privilege escalations regardless, and it is up to one to decide whether to escalate its privilege (install in `/Applications`) or find an alternative.
  - Do not move pre-/auto-installed macOS apps around in Finder, because future updates might break those modifications
- Only make system-wide configurations (e.g., network interface) or run services such as ClamAV and Santa in Admin; for things like gpg keys, set up in individual users
- Terminal
  - Ensure that [Secure keyboard](https://fig.io/docs/support/secure-keyboard-input) (in Terminal and iTerm) is enabled
  - Use MacPorts [instead of](https://saagarjha.com/blog/2019/04/26/thoughts-on-macos-package-managers/) Brew
  - Implement some hardware hardening:

```zsh
# Cold boot attacks (deprecated)
# sudo pmset -a destroyfvkeyonstandby 1 hibernatemode 25 standbydelaylow 0 standbydelayhigh 0 highstandbythreshold 0 powernap 0 tcpkeepalive 0 proximitywake 0
# to revert: sudo pmset -a destroyfvkeyonstandby 0 hibernatemode 3 standbydelaylow 10800 standbydelayhigh 86400

# Reduce unified log retention
sudo log config --mode "level:off" --subsystem com.apple.diagnosticd

# Prevents SUID programs from dumping core
sudo sysctl -w kern.sugid_coredump=0

# Secure virtual memory
sudo defaults write /Library/Preferences/com.apple.virtualMemory UseEncryptedSwap -bool YES
defaults read /Library/Preferences/com.apple.virtualMemory UseEncryptedSwap
# 1
```

- Extra Memos
  - Do not install [unmaintained](https://the-sequence.com/twitch-privileged-helper) applications
  - Avoid [Parallels VM](https://jhftss.github.io/Parallels-0-day/), [Electron-based](https://redfoxsecurity.medium.com/hacking-electron-apps-security-risks-and-how-to-protect-your-application-9846518aa0c0) applications (see a full list [here](https://www.electronjs.org/apps)), and apps needing [Rosetta](https://cyberinsider.com/apples-rosetta-2-exploited-for-bypassing-macos-security-protections/) translation

**Note** This guide reflects the "secure, not private" concept in that, although these settings make the OS more secure than the shipped or reinstalled version, this does **not** guarantee privacy from first-party or three-letter-agencies surveillance.

<sup>https://taoofmac.com/space/howto/switch#best-practices</sup><br/>
<sup>https://news.ycombinator.com/item?id=31864974</sup><br/>
<sup>https://github.com/beerisgood/macOS_Hardening?tab=readme-ov-file</sup>

## 1. CLI Tools

> Until section 7, this tutorial should be done in admin's GUI because some sections require running a privileged script, but admin cannot read/write warren's files if downloaded there, even if switched to warren in admin's terminal. I.e., the only way that works is to download and run `sudo` in admin's GUI. `su - warren` does not work with all commands in that user.

- Install xcode CLI tools/MacPorts in only one account (admin) to prevent duplicate instances and PATH confusion (technically port can only be installed in admin because it needs sudo access, but still).
- After `xcode-select --install`, install [MacPorts](https://www.macports.org/install.php). Quit and re-open Terminal.

## 2. Santa Setup

> For the following sections, all dependencies can be installed via MacPorts. Avoid using third-party pkg/dmg installers to keep dependency tree clean.

> Remember to create the non-privileged user first to ensure sections 2-4 also apply to it without having to double-check later.

1.  First create the Warren user (hello!). Log in, go through the setup, and make sure the Warren account works. Also go to Settings > "Menu Bar" > "Fast User Switching" and toggle it on. Switch back to admin's GUI.
2.  Add MacPorts to warren's shells:

```zsh
su - warren
echo 'export PATH=/opt/local/bin:/opt/local/sbin:$PATH' >> ~/.zshrc
echo 'export PATH=/opt/local/bin:/opt/local/sbin:$PATH' >> ~/.bash_profile
exit
```

3.  Install the updated release from Northpole on [GitHub](https://github.com/northpolesec/santa/releases).
4.  Grant permissions:
    - "Login Items & Extensions" > "App Background Activity" add Santa.app
    - "Login Items & Extensions" > "Extensions" > "By App" > toggle "Santa"
    - "Login Items & Extensions" > "Extensions" > "By Category" > "Endpoint Security Extensions" toggle Santa daemon
    - "Privacy" > "Full Disk Access" enable Santa Endpoint Security Extension (close and re-open Settings app after Santa install)
5.  Quit and re-open the terminal and check if Santa is running:

```zsh
sudo santactl doctor
```

6.  Add a custom [FAA policy](https://github.com/crimsonpython24/macsetup/blob/master/policies/faa_policy.plist):

```zsh
sudo mkdir -p /var/db/santa
sudo vi /var/db/santa/faa_policy.plist
# Paste content

sudo chmod 644 /var/db/santa/faa_policy.plist
sudo chown root:wheel /var/db/santa/faa_policy.plist
```

7.  Download the [Configuration Profile](https://github.com/crimsonpython24/macsetup/blob/master/policies/santa.mobileconfig). Install this profile first before the mSCP config (section 4) because NIST configurations block adding new profiles.

```zsh
cd ~/Desktop && mkdir Profiles && cd Profiles
vi santa.mobileconfig
# Paste content

sudo open santa.mobileconfig
```

8.  Debug:

```zsh
# Force reload
sudo launchctl kickstart -k system/com.northpolesec.santa.daemon
sudo santactl status | grep "Policy Version\|Last Policy Update"
```

9.  Blocking application example (a selected list of banned apps are [in the repo](https://github.com/crimsonpython24/macsetup/blob/master/policies/prefs/rules.json)):

```zsh
santactl fileinfo /System/Applications/Dictionary.app
# Path                   : /System/Applications/Dictionary.app/Contents/MacOS/Dictionary
# SHA-256                : 85f755c92afe93a52034d498912be0ab475020d615bcbe2ac024babbeed4439f
# SHA-1                  : 0cb8cb1f8d31650f4d770d633aacce9b2fcc5901
# Bundle Name            : Dictionary
# Bundle Version         : 294
# Bundle Version Str     : 2.3.0
# Signing ID             : platform:com.apple.Dictionary

# Use signing ID (will not change even with app update)
sudo santactl rule \
  --block \
  --signingid \
  --identifier platform:com.apple.Dictionary

santactl fileinfo /System/Applications/Dictionary.app
# Rule                   : Blocked (SigningID)
```

```zsh
# Deprecated appproach: sha-256
sudo santactl rule --block/--remove --sha256 85f755c92afe93a52034d498912be0ab475020d615bcbe2ac024babbeed4439f
# Added/Removed rule for SHA-256: 85f755c92afe93a52034d498912be0ab475020d615bcbe2ac024babbeed4439f
```

10. Certain files should be blocked by the FAA policy (because they should be immutable after being initialized), e.g.,

```zsh
# Will be created in section 7
cat ~/.ssh/github_ed25519
```

11. When importing/exporting rules, use:

```zsh
sudo santactl rule --export santa1.json
```

12. To temporarily unblock an FAA rule (e.g., rotating SSH keys with a non-allowlisted editor), edit `/var/db/santa/faa_policy.plist` and either delete the rule's `<key>RuleName</key><dict>...</dict>` block, or flip its `AuditOnly` option to `<true />` so accesses are logged but not blocked. Santa reloads the policy every 60s (`FileAccessPolicyUpdateIntervalSec` in `santa.mobileconfig`) — no daemon restart needed. To force an immediate reload:

```zsh
sudo launchctl kickstart -k system/com.northpolesec.santa.daemon
```

To watch FAA decisions in the unified log while testing (helps confirm the rule is now audit-only or absent):

```zsh
log stream --predicate 'subsystem == "com.northpolesec.santa"' --info | grep -i "file_access\|FAA"
```

Restore the original block when done. Never edit the policy directly while a sensitive operation is mid-flight — wait the 60s for reload, verify, then proceed.

## 3. mSCP Setup

> [!IMPORTANT]
> The NIST security compliance project does **not** modify any system behavior on its own. It generates a script that validates if the system reflects the selected policy, and creates a configuration profile that implements some changes.

> Unless otherwise specified, all commands here should be ran at the project base (`macos_security-*/`).

1.  Download the [repository](https://github.com/usnistgov/macos_security) and the [provided YAML config](https://github.com/crimsonpython24/macsetup/blob/master/policies/cnssi-1253_cust.yaml) in this repo, or a config from [NIST baselines](https://github.com/usnistgov/macos_security/tree/main/baselines).

```zsh
cd macos_security-tahoe/build
mkdir baselines && cd baselines && vi cnssi-1253_cust.yaml
# Paste content
```

2.  Ensure that the `macos_security-*` branch downloaded matches the OS version, e.g., `macos_security-tahoe`.
3.  Install dependencies, recommended within a virtual environment; after this step, warren will also gain paths to python3.14 and its corresponding pip package.

```zsh
sudo port install python314
sudo port select --set python python314 && sudo port select --set python3 python314
# For admin's shell
echo 'export PATH=/opt/local/bin:/opt/local/sbin:$PATH' >> ~/.zshrc
echo 'export PATH=/opt/local/bin:/opt/local/sbin:$PATH' >> ~/.bash_profile
source ~/.zshrc
source ~/.bash_profile

python --version
# Python 3.14.2
python3 --version
# Python 3.14.2

sudo port install py314-pip
sudo port select --set pip pip314 && sudo port select --set pip3 pip314
rehash (zsh) / hash -r (bash)
pip --version
# pip 25.3
pip3 --version
# pip 25.3
```

```zsh
cd ~/Desktop/Profiles/macos_security-tahoe
python3 -m venv venv && source venv/bin/activate
python3 -m pip install --upgrade pip && pip3 install pyyaml xlwt
```

4.  Small tangent: also check if MacPort libs also work in warren.

```zsh
su - warren
python3 --version
# Python 3.14.2
python --version
# Python 3.14.2
pip3 --version
# pip 25.3 from /opt/local/Library
pip --version
# pip 25.3 from /opt/local/Library
exit
```

5.  Remove `warren` from the FileVault authorized users group to ensure that only admin can unlock FV (so during double-auth, the first login must be admin to unlock FileVault before logging in as warren):

```zsh
sudo fdesetup list
sudo fdesetup remove -user warren
sudo fdesetup list
# Should only have admin
```

6.  Load custom ODVs (organization-defined values)

```zsh
cd ~/Desktop/Profiles/macos_security-tahoe

cat > custom/rules/system_settings_screensaver_ask_for_password_delay_enforce.yaml << 'EOF'
odv:
  custom: 0
EOF
```

7.  Generate the configuration file (there should be a `*.mobileconfig` and a `*_compliance.sh` file). Note: do not use root for `generate_guidance.py` as it may affect non-root users. The python script will ask for permissions itself (repeat running the script even if it kills itself; it will eventually get all permissions it needs).

```zsh
python3 scripts/generate_guidance.py \
        -P \
        -s \
        -p \
    build/baselines/cnssi-1253_cust.yaml
```

8.  If there is a previous configuration profile installed, remove it in Settings.app first. Run the compliance script.

```zsh
sudo zsh build/cnssi-1253_cust/cnssi-1253_cust_compliance.sh
```

9. First select option 2 in the script, then option 1 to see the report. Skip option 3 in this step. The compliance percentage should be around 18%. Exit the script.
10. Install the configuration profile in the Settings app:

```zsh
sudo open build/cnssi-1253_cust/mobileconfigs/unsigned/cnssi-1253_cust.mobileconfig
```

11. After installing the profile, one way to verify that ODVs are working is to go to "Lock Screen" in Settings and check if "Require password after screen saver begins..." is set to "immediately", as this guide overwrites NIST guideline's default value for that field.
12. Run the compliance script again (step 7) with options 2, then 1 in that order, i.e., always run a new compliance scan when settings changed. The script should now yield ~80% compliance.

```zsh
sudo zsh build/cnssi-1253_cust/cnssi-1253_cust_compliance.sh
```

13. Run option 3 and go through all scripts (select `y` for all settings) to apply settings not covered by the configuration profile. There are a handful of them.
14. Exit the script first to ensure that sudo access persists (it is shortened in the new CNSSI profile).
15. Run options 2 and 1 yet again. The compliance percentage should be about 96%. At this point, running option 3 will not do anything, because it does everything it can already, and the script will automatically return to the main menu.
16. Run option 2, copy the outputs, and find all rules that are still failing. Usually it is these two:

```zsh
os_firewall_default_deny_require
system_settings_filevault_enforce
```

17. Go inside Settings and manually toggle these two options:
    - Enable "Filevault" under "Privacy and Security" > "Security". Wait until the encryption finishes.
    - "Block all incoming connections" in "Network" > "Firewall" > "Options". Further ensure that `pf` firewall and FileVault are enabled (ALF is enabled by default):

```zsh
sudo bash includes/enablePF-mscp.sh

sudo pfctl -a '*' -sr | grep "block drop in all"
# Should output smt like "block drop in all" i.e. default deny all incoming
sudo pfctl -s info
# Should give output

# FileVault
sudo fdesetup status
```

18. Note from previous step: one might encounter these two warnings.
    - "No ALTQ support in kernel" / "ALTQ related functions disabled": ALTQ is a legacy traffic shaping feature that has been disabled in modern macOS, which does not affect pf firewall at all.
    - "pfctl: DIOCGETRULES: Invalid argument": this occurs when pfctl queries anchors that do not support certain operations, but custom rules in this guide are still loaded (can still see `block drop in all`).
19. The script should yield 100% compliance by running option 2, then option 1.

```zsh
sudo zsh ~/Desktop/Profiles/macos_security-tahoe/build/cnssi-1253_cust/cnssi-1253_cust_compliance.sh
```

20. Restart the device at this point.
21. After restart, run the compliance script to verify that everything works. If `system_settings_bluetooth_sharing_disable` fails, it can simply be remediated by running option 3; or since it is already disabled in the Settings app, one can safely ignore it.

**Note** If unwanted banners show up, remove the corresponding files with `sudo rm -rf /Library/Security/PolicyBanner.*`

**Note** Run `pip list` after this section. There should only be `pip` and `setuptools` in global python environment.

## 4. AIDE Setup

> The database itself is the soft target — if an attacker can rewrite `aide.db`, the next scan compares the filesystem against their forgery and reports clean. We address this two ways: (1) GPG-sign the database after every init/update so tampering is detectable, (2) `chflags uchg` the database + signature so casual writes (`rm`, `mv`, `tee`) fail without an explicit unlock first.

> **Run every command in this section as `admin` (in admin's GUI Terminal, same as the rest of section 1–4).** The signing key lives in `~admin/.gnupg/`, so `gpg2` invocations only resolve to that key when admin is the shell user. Running these commands as warren would fall back to warren's keyring, which doesn't have the AIDE key — sign and verify both fail.
>
> CNSSI's `os_root_disable` only disables interactive root login (`su -`, login screen, `ssh root@…`). `sudo` keeps working — it authenticates against admin's password and executes individual commands as root. Every `sudo`-prefixed command below works the same with root disabled.

1.  Install AIDE via MacPorts: `sudo port install aide`.
2.  Generate a dedicated AIDE-signing GPG key in admin's keyring (one-time). This is separate from warren's git-signing key in section 7(B):

```zsh
gpg2 --full-generate-key
# Choose: (1) RSA and RSA, 4096 bits, key does not expire
# Real name: Admin AIDE Signing
# Email: aide@<hostname>   (placeholder is fine; not used for mail)
# Set a strong passphrase

gpg2 --list-secret-keys --keyid-format=long
# sec   rsa4096/<KEYID> ...
#       <FINGERPRINT>
#       Admin AIDE Signing <aide@...>
```

3.  Edit the [configuration file](https://github.com/crimsonpython24/macsetup/blob/master/policies/aide.conf):

```zsh
sudo vi /opt/local/etc/aide/aide.conf
# Paste content
```

> **Optional flag-tracking test.** If you want AIDE to log `chflags` changes as "flags changed" instead of just "ctime changed", append `+flags` to the `Full` group definition and re-init. If the build supports it, `--init` succeeds; if not, you'll see a config error and should revert. ctime already catches chflags activity either way, so this is cosmetic.

4.  Initialize database:

```zsh
sudo aide --init -L info
#    INFO: read new entries from disk (limit: '(none)', root prefix: '')
#    INFO: write new entries to database: file:/opt/local/var/lib/aide/aide.db.new
#    ...
# AIDE successfully initialized database.
# New AIDE database written to /opt/local/var/lib/aide/aide.db.new
# Number of entries:	~9000
# End timestamp: ... (run time 0m 0-5s)
# INFO: exit AIDE with exit code '0'    <--- 0 = no error
```

5.  Move, sign, and lock the database:

```zsh
sudo mv /opt/local/var/lib/aide/aide.db.new /opt/local/var/lib/aide/aide.db

# Detach-sign with admin's AIDE key. sudo cat reads the root-owned db,
# gpg2 runs as admin so it uses admin's keyring.
sudo cat /opt/local/var/lib/aide/aide.db | \
    gpg2 --detach-sign --armor | \
    sudo tee /opt/local/var/lib/aide/aide.db.sig > /dev/null
sudo chown root:admin /opt/local/var/lib/aide/aide.db.sig
sudo chmod 644 /opt/local/var/lib/aide/aide.db.sig

# Lock both files (uchg = user immutable; only root can clear it)
sudo chflags uchg /opt/local/var/lib/aide/aide.db
sudo chflags uchg /opt/local/var/lib/aide/aide.db.sig

ls -lO /opt/local/var/lib/aide/aide.db /opt/local/var/lib/aide/aide.db.sig
# -rw-------  1 root  admin  uchg ... aide.db
# -rw-r--r--  1 root  admin  uchg ... aide.db.sig
```

6.  Test installation — verify the signature first, then check:

```zsh
# Verify GPG signature. "Good signature" = db hasn't been tampered.
sudo cat /opt/local/var/lib/aide/aide.db | \
    gpg2 --verify /opt/local/var/lib/aide/aide.db.sig -
# gpg: Good signature from "Admin AIDE Signing <...>" [ultimate]

sudo aide --check
# AIDE found NO differences between database and filesystem. Looks okay!!
```

> **If the verify fails** (BAD signature, missing signature, or no public key): treat as a tamper event. Don't trust the next `--check` output; investigate before re-init.

7.  Test modifying watched directories:

```zsh
sudo touch /Library/LaunchAgents/com.test.aide.plist

sudo aide --check
# AIDE found differences between database and filesystem!!
# Summary:
#   Added entries:		1
# f++++++++++++: /Library/LaunchAgents/com.test.aide.plist
```

8.  Routine update workflow — unlock, update, re-sign, re-lock:

```zsh
# Unlock
sudo chflags nouchg /opt/local/var/lib/aide/aide.db
sudo chflags nouchg /opt/local/var/lib/aide/aide.db.sig

# Update database
sudo aide --update
sudo mv /opt/local/var/lib/aide/aide.db.new /opt/local/var/lib/aide/aide.db

# Re-sign
sudo cat /opt/local/var/lib/aide/aide.db | \
    gpg2 --detach-sign --armor | \
    sudo tee /opt/local/var/lib/aide/aide.db.sig > /dev/null
sudo chown root:admin /opt/local/var/lib/aide/aide.db.sig
sudo chmod 644 /opt/local/var/lib/aide/aide.db.sig

# Re-lock
sudo chflags uchg /opt/local/var/lib/aide/aide.db
sudo chflags uchg /opt/local/var/lib/aide/aide.db.sig

# Sanity check
sudo cat /opt/local/var/lib/aide/aide.db | \
    gpg2 --verify /opt/local/var/lib/aide/aide.db.sig -
sudo aide --check
# AIDE found NO differences between database and filesystem. Looks okay!!
```

9.  Ensure that database exists and is locked:

```zsh
ls -lO /opt/local/var/lib/aide/aide.db /opt/local/var/lib/aide/aide.db.sig
# -rw-------  1 root  admin  uchg ... aide.db
# -rw-r--r--  1 root  admin  uchg ... aide.db.sig
```

10. Cleanup after testing for the next manual/on-demand scan (uses the step-8 update workflow):

```bash
sudo rm /Library/LaunchAgents/com.test.aide.plist

sudo chflags nouchg /opt/local/var/lib/aide/aide.db /opt/local/var/lib/aide/aide.db.sig
sudo aide --update
sudo mv /opt/local/var/lib/aide/aide.db.new /opt/local/var/lib/aide/aide.db
sudo cat /opt/local/var/lib/aide/aide.db | \
    gpg2 --detach-sign --armor | \
    sudo tee /opt/local/var/lib/aide/aide.db.sig > /dev/null
sudo chown root:admin /opt/local/var/lib/aide/aide.db.sig
sudo chmod 644 /opt/local/var/lib/aide/aide.db.sig
sudo chflags uchg /opt/local/var/lib/aide/aide.db /opt/local/var/lib/aide/aide.db.sig

sudo aide --check
# AIDE found NO differences between database and filesystem. Looks okay!!
```

### A) Quick Reference

| Task                 | Command                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Verify signature     | `sudo cat /opt/local/var/lib/aide/aide.db \| gpg2 --verify /opt/local/var/lib/aide/aide.db.sig -`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Manual check         | `sudo aide --check` (run after verify)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Update after changes | `sudo chflags nouchg /opt/local/var/lib/aide/aide.db /opt/local/var/lib/aide/aide.db.sig && sudo aide --update && sudo mv /opt/local/var/lib/aide/aide.db.new /opt/local/var/lib/aide/aide.db && sudo cat /opt/local/var/lib/aide/aide.db \| gpg2 --detach-sign --armor \| sudo tee /opt/local/var/lib/aide/aide.db.sig > /dev/null && sudo chown root:admin /opt/local/var/lib/aide/aide.db.sig && sudo chmod 644 /opt/local/var/lib/aide/aide.db.sig && sudo chflags uchg /opt/local/var/lib/aide/aide.db /opt/local/var/lib/aide/aide.db.sig`                                                       |
| Re-initialize        | Same flow as update, but with `aide --init` instead of `aide --update`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| View log             | `sudo cat /opt/local/var/log/aide/aide.log`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Verbose check        | `sudo aide --check -L info`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |

### B) Monitored Directories

| Category      | Paths                                              | Reason                 |
| ------------- | -------------------------------------------------- | ---------------------- |
| Startup       | `/Library/LaunchDaemons`, `/Library/LaunchAgents`  | Root-level persistence |
| GPG           | `/opt/local/bin/gpg2`, `/opt/local/bin/gpg2-agent` | GPG integrity          |
| Shell configs | `~/.zshrc`, `~/.bash_profile`, etc.                | Backdoor detection     |
| SSH           | `/Users/*/.ssh/*`                                  | SSH hijacking          |
| PAM           | `/etc/pam.d`                                       | Auth bypass            |
| User apps     | `/Users/*/Library/Application Support/*`           | Securing app data      |

## 5. DNS Setup

### A) Hosts File

- Append [StevenBlack/hosts](https://github.com/StevenBlack/hosts) into `hosts`.

```zsh
curl https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | sudo tee -a /etc/hosts
```

### B) DNSCrypt

> Some VPN applications override DNS settings on connect; may need to reconfigure VPN and make it use the local DNS server (change DNS to 127.0.0.1).
> No need to configure DNSSEC in this step; it will be handled with Unbound.

1.  Install DNSCrypt with `sudo port install dnscrypt-proxy`. Do not load the port just yet, this will be done later.
    - Because there will be no Internet connection until the end of this section, also install Unbound with `sudo port install unbound`, and do not load it yet.
    - Also copy the [DNSCrypt config](https://github.com/crimsonpython24/macsetup/blob/master/dns/dnscrypt-proxy.toml) and [Unbound config](https://github.com/crimsonpython24/macsetup/blob/master/dns/unbound.conf) beforehand.
    - Then, update DNS server settings to point to 127.0.0.1 ("Network" > Wi-Fi or Eth > Current network "Details" > DNS tab).
2.  Find DNSCrypt's installation location with `port contents dnscrypt-proxy` to get configuration files' path.

```zsh
sudo vi /opt/local/share/dnscrypt-proxy/dnscrypt-proxy.toml
# Paste content
```

3.  Edit the property list to give DNSCrypt startup access:

```zsh
sudo vi /opt/local/etc/LaunchDaemons/org.macports.dnscrypt-proxy/org.macports.dnscrypt-proxy.plist
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>org.macports.dnscrypt-proxy</string>
    <key>ProgramArguments</key>
    <array>
      <string>/opt/local/bin/daemondo</string>
      <string>--label=dnscrypt-proxy</string>
      <string>--start-cmd</string>
      <string>/opt/local/sbin/dnscrypt-proxy</string>
      <string>-config</string>
      <string>/opt/local/share/dnscrypt-proxy/dnscrypt-proxy.toml</string>
      <string>;</string>
      <string>--restart-netchange</string>
      <string>--pid=exec</string>
    </array>
    <key>Disabled</key>
    <false />
    <key>KeepAlive</key>
    <true />
    <key>RunAtLoad</key>
    <true />
  </dict>
</plist>
```

4.  Load the proxy:

```zsh
sudo launchctl enable system/org.macports.dnscrypt-proxy
sudo port unload dnscrypt-proxy
sudo port load dnscrypt-proxy
```

5.  Check if current configuration is valid (will not run otherwise):

```zsh
sudo /opt/local/sbin/dnscrypt-proxy -config /opt/local/share/dnscrypt-proxy/dnscrypt-proxy.toml -check
# Remember to reload dnscrypt-proxy after toml change

# If debug: run in foreground with verbose logging
sudo /opt/local/sbin/dnscrypt-proxy -config /opt/local/share/dnscrypt-proxy/dnscrypt-proxy.toml -loglevel 0
```

```zsh
sudo lsof +c 15 -Pni UDP:54
# dnscrypt-proxy 57409 root    7u  IPv4 0xf2ce17b711151ccc      0t0  UDP 127.0.0.1:54
# dnscrypt-proxy 57409 root    9u  IPv6 0x8031285518513383      0t0  UDP [::1]:54
```

6.  After changing the network DNS resolver to use local, ensure that Wi-Fi interfaces use `127.0.0.1` instead of `192.168.x.x`:

```zsh
# Sometimes system will not respect GUI settings
sudo networksetup -setdnsservers "Wi-Fi" 127.0.0.1

networksetup -getdnsservers "Wi-Fi"
# 127.0.0.1

scutil --dns | head -10
# nameserver[0] : 127.0.0.1
```

7.  Again, since this guide routes `dnscrypt-proxy` to port 54, there will not be Internet connection until after section 2(C)

**Note** `dnscrypt-proxy` could take ~30 seconds to load on re-wake and startup, so there might not be connection immediately after session login.

### C) Unbound

> The original guide uses `dnsmasq`; however, Dnsmasq will not load `ad` (authenticated data) flag in DNS queries if an entry is cached. Hence this section is replaced with unbound to achieve both caching and auth.

1.  Unbound should already be installed in 5(B). If not, set DNS back to 192.168.0.1, install Unbound, and then change back to 127.0.0.1.
2.  Copy the configurations stored from 5(B) ([here](https://github.com/crimsonpython24/macsetup/blob/master/dns/unbound.conf) once again) into Unbound:

```zsh
sudo vi /opt/local/etc/unbound/unbound.conf
# Paste content
```

3.  Initialize root trust anchor for DNSSEC.

```zsh
sudo unbound-anchor -a /opt/local/etc/unbound/root.key
```

4.  Check configurations:

```zsh
sudo unbound-checkconf /opt/local/etc/unbound/unbound.conf
sudo port load unbound
sudo lsof +c 15 -Pni UDP:53
# Should show unbound on 127.0.0.1:53 and [::1]:53
```

5.  Test Unbound dnssec:

```zsh
sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder

# First query - should have 'ad' flag
dig @127.0.0.1 dnssec.works

# Second query (cached) - should STILL have 'ad' flag
dig @127.0.0.1 dnssec.works
# ;; flags: qr rd ra ad;

# Third query - 'ad' flag should persist
dig @127.0.0.1 dnssec.works

# Test without DNS argument - should still go through 127.0.0.1#53 with `ad` flag
dig dnssec.works

# Test DNSSEC validation - should fail
dig @127.0.0.1 fail01.dnssec.works
# ;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL
```

```zsh
unbound-host -vDr test.dnscheck.tools
# test.dnscheck.tools has address xx.xx.xx.xx (secure)
# test.dnscheck.tools has IPv6 address xx:xx:xx:xx:xx:xx (secure)
# test.dnscheck.tools mail is handled by 0 . (secure)

unbound-host -vDr badsig.test.dnscheck.tools
# ... (BOGUS (security failure))
```

**Note** Some websites will not have `ad` flag no matter how hard one tries. E.g.,

```zsh
dig DNSKEY archlinux.org
# ;; Got answer:
# ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 38272
# ;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1
#
# ;; QUESTION SECTION:
# ;archlinux.org.			IN	DNSKEY
#
# (!! No answer section !!)
#
# ;; AUTHORITY SECTION:
# archlinux.org.		3600	IN	SOA	hydrogen.ns.hetzner.com. dns.hetzner.com. 2026010201 86400 10800 3600000 3600
```

```zsh
dig DNSKEY dnsviz.net
dig DNSKEY dnssec-debugger.verisignlabs.com
# ;; Got answer:
# ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: xxxxx
# ;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1
...
```

**Note** Debugging commands:

```zsh
log show --predicate 'process == "dnscrypt-proxy"' --last 5m
curl -I https://google.com

# Test if resolver is blocking domains itself
dig @127.0.0.1 dnsleaktest.com
dig @9.9.9.9 dnsleaktest.com
```

One might have to quit and restart Safari (while testing) with `killall Safari`.

<sup>https://wiki.archlinux.org/title/Dnscrypt-proxy#Startup</sup></br>
<sup>https://00f.net/2019/11/03/stop-using-low-dns-ttls/</sup></br>
<sup>https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html</sup>
<sup>https://wiki.archlinux.org/title/Unbound</sup>

## 6. Application Install

> [!NOTE]
> Although this section applies to `warren`, it is more convenient to run the script inside `admin` because `warren` is not in the sudoers group (and hence cannot run `sudo` commands), and `admin` cannot read/write warren's files because `admin` is not `root`. This is the same note as in section 1.

> When actually installing apps after following this guide, install BlockBlock, KnockKnock, and Little Snitch in this order. It prevents having to re-filter app binaries or miss binaries' persistence after the three tools are installed.

1.  Ensure that warren is not an admin (so apps should write to `/Users/warren/Library/`):

```zsh
sudo dseditgroup -o edit -d warren -t user admin
# Should be blank
```

2.  Force certain `/Library` folders to be inaccessible to apps in `~/Library`.

```zsh
vi ~/Desktop/Profiles/directory_lock.sh
```

```zsh
CRITICAL_DIRS=(
    "/Library/LaunchAgents"
    "/Library/LaunchDaemons"
    "/Library/StartupItems"
    "/Library/Security/SecurityAgentPlugins"
    "/Library/DirectoryServices/PlugIns"
)

for dir in "${CRITICAL_DIRS[@]}"; do
    sudo chmod +a "user:warren deny add_subdirectory,add_file,writeattr,writeextattr,delete,delete_child" "$dir"
done
```

```zsh
sudo chmod +x ~/Desktop/Profiles/directory_lock.sh
~/Desktop/Profiles/./directory_lock.sh
```

3.  Note for step 2: one can add `/Library/PrivilegedHelperTools` into the directory list, but this will not be created until an application writes to that directory. I.e., this directory will be empty if one runs this script in a fresh system. Also test step 2:

```zsh
ls -led /Library/LaunchAgents
ls -led /Library/LaunchDaemons
ls -led /Library/StartupItems

# drwxr-xr-x+ 3 root  wheel  96 Jan 11 14:30 /Library/LaunchAgents
#  0: user:warren deny add_file,delete,add_subdirectory,delete_child,writeattr,writeextattr
```

4.  Rollback command:

```zsh
# use -a instead of +a
sudo chmod -a "user:warren deny add_subdirectory,add_file,writeattr,writeextattr,delete,delete_child" /Library/LaunchAgents
# ls -led /Library/LaunchAgents
# drwxr-xr-x  3 root  wheel  96 Jan 18 20:08 /Library/LaunchAgents
```

5.  When installing application for warren, make sure to create the directory `/Users/warren/Applications` (i.e., `~/Applications`) and drag-and-drop apps there. The "Applications" folder on Finder's sidebar points to `/Applications` (i.e., root). As such, user apps will store files to `~/Library`.

### GnuPG

If any applications are curl'd through Git, make sure to configure it as in [section 7(B)](https://github.com/crimsonpython24/macsetup?tab=readme-ov-file#b-gpg-configuration).

### Firefox

- When using Firefox, use the uploaded [user-overrides.js](https://github.com/crimsonpython24/macsetup/blob/master/browser/user-overrides.js) in this repo.
- If macOS does not allow opening the LibreWolf browser, fix the error notification with `xattr -d com.apple.quarantine /Applications/LibreWolf.app`

### VSCodium

To directly access VSCode's extensions marketplace:

```zsh
vi ~/Applications/VSCodium.app/Contents/Resources/app/product.json
```

```zsh
# Replace
  "extensionsGallery": {
    "serviceUrl": "https://marketplace.visualstudio.com/_apis/public/gallery",
    "cacheUrl": "https://vscode.blob.core.windows.net/gallery/index",
    "itemUrl": "https://marketplace.visualstudio.com/items"
  },
```

## 7. Fish Shell

> For this section, running in warren's GUI is easier (keep zsh as default for admin since that account should not be used besides global settings). Obviously `su - admin` when escalation is needed.

1.  First change the hostname:

```zsh
sudo scutil --set ComputerName "device"
sudo scutil --set LocalHostName "device"
sudo scutil --set HostName "device"
hostname # device
```

2.  Restart the terminal to ensure the hostname change takes effect.
3.  Install fish through the admin account:

```zsh
sudo port install fish
```

4.  Switch shells for warren only:

```zsh
sudo sh -c 'echo /opt/local/bin/fish >> /etc/shells'
sudo chpass -s /opt/local/bin/fish warren
```

5.  Add paths to fish:

```fish
# su - warren
# fish (zsh is still default until quitting Terminal again)
fish_add_path /opt/local/bin
fish_add_path /opt/local/sbin
```

6.  Download [Source Code Pro Nerd Font](https://www.nerdfonts.com/font-downloads) and macOS terminal config [in this repo](https://github.com/crimsonpython24/macsetup/blob/master/shell/fish/default.terminal)
    - There is nothing special about this terminal config, they are simply personal prefs).
    - Load the custom font and config in "Terminal" > "cmd + `,`" > "Import profile". This configuration chooses not to use iTerm2 because personally most features are not used, and not Alacritty because some of `tide@v6`'s features do not work there.
7.  Install [Fisher](https://github.com/jorgebucaran/fisher) with the following extensions:
    - [jethrokuan/z](https://github.com/jethrokuan/z)
    - [PatrickF1/fzf.fish](https://github.com/PatrickF1/fzf.fish) -- depends on `sudo port install fzf fd bat`
    - [jorgebucaran/nvm.fish](https://github.com/jorgebucaran/nvm.fish)
    - [jorgebucaran/autopair.fish](https://github.com/jorgebucaran/autopair.fish)
    - [nickeb96/puffer-fish](https://github.com/nickeb96/puffer-fish)

```fish
fisher install jethrokuan/z    # Example
```

8.  Download Node: `nvm install lts`.
9.  Add custom functions:

```fish
vi ~/.config/fish/functions/mkcd.fish

function mkcd
    mkdir -p $argv[1] && cd $argv[1]
end
```

```fish
vi ~/.config/fish/functions/up.fish

function up
  if test -z $argv[1]
    set n 1
  else
    set n $argv[1]
  end
  for i in (seq $n)
    cd ..
  end
end
```

```fish
vi ~/.config/fish/functions/uext.fish

function uext
    find . -type f | perl -ne 'print $1 if m/\.([^.\/]+)$/' | sort -u
end
```

10. Install tide with `fisher install IlanCosman/tide@v6` and add in [custom configurations](https://github.com/crimsonpython24/macsetup/blob/master/shell/fish/config.fish).
    - In the initial config, select "Classic" (step 1), "Dark" (step 3), and "24-hour format" (step 4). All other options can go with default.
    - Also edit the [custom item context](https://github.com/crimsonpython24/macsetup/blob/master/shell/fish/_tide_item_context.fish) to complete this setup. Restart Terminal for both changes to take effect.

```fish
vi ~/.config/fish/config.fish
vi ~/.config/fish/functions/_tide_item_context.fish
```

11. Install [Amix's vim configuration](https://github.com/amix/vimrc):

```fish
git clone --depth=1 https://github.com/amix/vimrc.git ~/.vim_runtime
sh ~/.vim_runtime/install_awesome_vimrc.sh
```

### A) SSH Configuration

1.  Install new configuration from [ssh-config](https://github.com/crimsonpython24/macsetup/blob/master/shell/ssh_config):

```fish
mkdir ~/.ssh
vi ~/.ssh/config
# Paste contents
chmod 600 ~/.ssh/config
```

2.  Create the sockets directory for multiplexing:

```fish
mkdir -p ~/.ssh/sockets
chmod 700 ~/.ssh/sockets
```

3.  Generate an authentication key. Pick **one** of these — option B is the
    higher-assurance path, since the private key is non-extractable from the
    YubiKey/FIDO2 device and every signature requires a physical touch (and
    a PIN, with `verify-required`):

```fish
# Option A — software Ed25519 key (KDF rounds bumped from default 16 to 100).
ssh-keygen -t ed25519 -a 100 -f ~/.ssh/github_ed25519 \
  -C "github-$(hostname)-$(date +%Y)"

# Option B — FIDO2 hardware-backed key (requires a YubiKey 5 or similar).
# resident         = key handle stored on the token, so a fresh laptop only
#                    needs `ssh-keygen -K` to recover the stub.
# verify-required  = PIN required for every signature (not just touch).
# application=ssh:github = isolates this credential per-service inside the
#                    authenticator so it can't be reused for another site.
ssh-keygen -t ed25519-sk -a 100 \
  -O resident -O verify-required -O application=ssh:github \
  -f ~/.ssh/github_ed25519_sk \
  -C "github-sk-$(hostname)-$(date +%Y)"
```

4.  Set permissions:

```fish
chmod 700 ~/.ssh
chmod 600 ~/.ssh/config
chmod 600 ~/.ssh/*_ed25519 ~/.ssh/*_ed25519_sk 2>/dev/null
chmod 644 ~/.ssh/*_ed25519.pub ~/.ssh/*_ed25519_sk.pub 2>/dev/null
```

5.  Add keys to the macOS keychain. Hardware-backed (`*_sk`) keys do not
    cache a passphrase — each use prompts the token directly — so only the
    software key path actually needs `--apple-use-keychain`:

```fish
ssh-add --apple-use-keychain ~/.ssh/github_ed25519
ssh-add -l
```

6.  Add the SSH key to GitHub:

```fish
cat ~/.ssh/github_ed25519.pub | pbcopy
# or, for the FIDO2 path:
# cat ~/.ssh/github_ed25519_sk.pub | pbcopy
# Add to https://github.com/settings/keys as an authentication key, remove trailing new line.
```

   If you used the FIDO2 (`-sk`) key, you must also add the
   `IdentityFile ~/.ssh/github_ed25519_sk` line to the `Host github.com`
   block in `~/.ssh/config` (or replace the existing IdentityFile pointer).

7.  Test SSH connection:

```fish
ssh -T git@github.com
cat ~/.ssh/known_hosts
# |1|qN7XE853AcGGBmJDT/APv+AiZGU=|qq21+AC5OMD...    <-- should be hashed
```

   Confirm the negotiated KEX is post-quantum (one of `mlkem768x25519-sha256`
   or `sntrup761x25519-sha512@openssh.com`). GitHub announced support for
   `sntrup761x25519-sha512@openssh.com` on 2025-09-17, so any OpenSSH ≥ 9.0
   client should now negotiate it automatically:

```fish
ssh -v git@github.com exit 2>&1 | grep 'kex: algorithm:'
```

8.  Run the [test script](https://github.com/crimsonpython24/macsetup/blob/master/shell/ssh_test.sh) to verify that SSH settings are applied.

```fish
vi ssh_test.sh
# Paste content

chmod +x ssh_test.sh
./ssh_test.sh
rm ssh_test.sh
```

**Note** If a legacy SSH server is not working, add a per-host override
**below** the `Host *` block (Match/Host blocks are evaluated top-to-bottom
and the **first** match for any given keyword wins, so the override has to
come first in the file). Prefer the `+` syntax to extend the hardened
defaults rather than replace them:

```fish
Host legacy-server
  HostName old.server.com
  # Re-enable legacy KEX/cipher/MAC for THIS host only.
  KexAlgorithms +diffie-hellman-group14-sha256
  Ciphers +aes256-cbc
  MACs +hmac-sha2-256
  HostKeyAlgorithms +ssh-rsa
  PubkeyAcceptedAlgorithms +ssh-rsa
```

**Note** `VerifyHostKeyDNS yes` in the hardened `~/.ssh/config` requires
OpenSSH ≥ 9.9p2 (the patched build for CVE-2025-26465, where the prior
client logic accepted server impersonation under DNS misuse). MacPorts and
Homebrew are well past that release. Apple's bundled `ssh` typically lags
upstream — confirm `ssh -V` is ≥ 9.9p2 before relying on this directive,
and flip it to `no` if you see a version mismatch.

### B) GPG Configuration

The hardened setup ships three configuration files: `gpg.conf` (gpg behavior),
`gpg-agent.conf` (passphrase cache + pinentry), and `dirmngr.conf` (keyserver
network policy). All three live in `~/.gnupg`.

1.  Make sure GnuPG and a graphical pinentry are installed: `sudo port install gnupg2 pinentry-mac`.
2.  Create the configuration directory and drop in all three files. The agent
    and dirmngr daemons read their configs only at startup, so reload them
    after writing:

```fish
exit    # or su - warren
mkdir -p ~/.gnupg
chmod 700 ~/.gnupg

vi ~/.gnupg/gpg.conf
# Paste content from shell/gpg.conf

vi ~/.gnupg/gpg-agent.conf
# Paste content from shell/gpg-agent.conf
# If you installed pinentry-mac via Homebrew rather than MacPorts, change
# pinentry-program to /opt/homebrew/bin/pinentry-mac.

vi ~/.gnupg/dirmngr.conf
# Paste content from shell/dirmngr.conf

chmod 600 ~/.gnupg/gpg.conf ~/.gnupg/gpg-agent.conf ~/.gnupg/dirmngr.conf

gpg-connect-agent reloadagent /bye
gpg-connect-agent --dirmngr reloaddirmngr /bye
```

3.  Validate syntax — both commands should print nothing:

```fish
gpg2 --gpgconf-test
gpg2 --gpgconf-list-components
```

4.  Generate a key. The hardened `gpg.conf` sets
    `default-new-key-algo "ed25519/cert,sign+cv25519/encr"`, so
    `--quick-generate-key` produces a modern Ed25519 cert+sign primary with a
    Curve25519 encryption subkey. Choose **one** of:

```fish
# Option A — modern (ed25519/cv25519, recommended for new keys)
gpg2 --quick-generate-key "Yu-Jen Warren Wang <you@example.com>" default default 2y

# Option B — RSA-4096 (use only if you need to sign for a system that
# does not yet accept Ed25519 — most don't have that limitation in 2026)
gpg2 --full-generate-key   # pick "RSA and RSA", 4096 bits
```

5.  List the new key, capture the long key ID, and export the public half.
    `0xD67D...` in `gpg.conf` (`default-key`, `trusted-key`) is the previous
    holder's key — replace it with whatever your new key reports:

```fish
gpg2 --list-secret-keys --keyid-format=long
# sec   ed25519/ABC123DEF4567890 2026-05-03 [SC] [expires: 2028-05-03]
gpg2 --armor --export ABC123DEF4567890

# Open ~/.gnupg/gpg.conf and update default-key / trusted-key. Upstream
# recommends the full 40-char fingerprint with a trailing "!" to disable
# subkey substitution heuristics, e.g.:
#   default-key  ABCDEF0123456789ABCDEF0123456789ABCDEF01!
gpg2 --list-keys --fingerprint --keyid-format=long
```

6.  Generate and store an offline revocation certificate. If your key is ever
    compromised, this is what you publish to invalidate it:

```fish
gpg2 --output ~/Documents/revoke-ABC123DEF4567890.asc --gen-revoke ABC123DEF4567890
chmod 400 ~/Documents/revoke-ABC123DEF4567890.asc
# Move the file to offline storage (USB stick in a safe, encrypted vault, etc).
```

7.  Add the public key to [GitHub](https://github.com/settings/keys) as a
    Signing Key. GitHub accepts Ed25519, ECDSA, RSA, and DSA OpenPGP keys for
    commit signing, but RSA must be ≥ 2048 bits and DSA is being phased out.
8.  Find the privacy-preserving email under
    **Settings → Access → Emails → "Keep my email address private"** and copy
    that `<id>+<user>@users.noreply.github.com` address.
9.  Configure Git to sign with the new key:

```fish
git config --global user.signingkey ABC123DEF4567890
git config --global commit.gpgsign true
git config --global tag.gpgsign true
git config --global gpg.program gpg2
git config --global user.name "Yu-Jen Warren Wang"
git config --global user.email "<id>+<user>@users.noreply.github.com"
```

10. Verify by signing a throwaway commit and asking gpg to verify it:

```fish
echo test > /tmp/sigtest && cd /tmp && git init -q && git add sigtest \
    && git -c commit.gpgsign=true commit -m "sig test" -q \
    && git log --show-signature -1 \
    && cd - >/dev/null && rm -rf /tmp/.git /tmp/sigtest
# Expect: "Good signature from <you>" and the long key ID matching above.
```

**Note** The hardened `gpg-agent.conf` enforces 12-character minimum
passphrases with at least 2 non-alphabetic characters, caches OpenPGP
passphrases for 10 min (1 h max) and SSH passphrases for 30 min (2 h max),
and refuses external credential caches, loopback pinentry, and runtime
trust elevation. To require a pinentry prompt on every signature (paranoid
mode), uncomment `ignore-cache-for-signing` in `gpg-agent.conf`.

**Note** `gpg.conf` enables `include-key-block` and `auto-key-import` so
signatures we emit carry a stripped-down copy of our public key, and
inbound signatures we verify auto-import the signer's key (cleaned to
self-sigs only by `import-options import-clean import-minimal`). The net
effect: signed git commits and signed mail can be verified offline by a
reviewer who hasn't pre-fetched our key, without growing either side's
keyring. Signature size grows by ~1–2 KB per signed object, which matters
for nothing in the git workflow. To opt out (e.g. for size-sensitive
detached signatures on releases), pass `--no-include-key-block` on the
specific gpg invocation.

## Footnotes

Reboot and everything should work, even by directly logging into `warren` and not `admin`.
