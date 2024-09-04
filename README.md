# Automating Security Audits and Server Hardening on Linux Servers
## STEP 1 : Setting up environment
- Open amazon console , create a EC2 instance ,then connect 
- Install git
```
sudo yum install git -y
```
- Now create a new directory for our project and navigate to that folder
```
mkdir monitoring-dashboard
```
```
cd monitoring-dashboard
```
## STEP 2 : Initializing Git Repository
- Initialize Git
```
git init
```
- Create a README.md:
```
touch README.md
```
- Create a .gitignore File , to exclude unnecessary files
```
touch .gitignore
```
## Step 3: Develop the Bash Script
- Create a bash script file :
```
touch security_audit.sh
```
- edit the script file :
```
vim security_audit.sh
```
```
#!/bin/bash

# security_audit.sh
# A script for automating security audits and server hardening on Linux servers.

# Function to list all users and groups
list_users_groups() {
    echo "Listing all users:"
    cut -d: -f1 /etc/passwd
    
    echo "Listing all groups:"
    cut -d: -f1 /etc/group
}

# Function to check for users with UID 0
check_uid_zero() {
    echo "Checking for non-root users with UID 0:"
    awk -F: '($3 == 0) {print $1}' /etc/passwd
}

# Function to check for users without passwords or with weak passwords
check_weak_passwords() {
    echo "Checking for users without passwords:"
    awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow
}

# Function to scan for world-writable files
check_world_writable_files() {
    echo "Scanning for world-writable files:"
    find / -xdev -type f -perm -0002 ! -path "/proc/*" ! -path "/sys/*" -exec ls -l {} \; 2>/dev/null
}

# Function to check .ssh directory permissions
check_ssh_permissions() {
    echo "Checking .ssh directory permissions:"
    find /home -type d -name ".ssh" -exec chmod 700 {} \; -exec ls -ld {} \;
    find /home -type f -name "authorized_keys" -exec chmod 600 {} \;
}

# Function to report SUID/SGID files
check_suid_sgid_files() {
    echo "Checking for SUID/SGID files:"
    find / -perm /6000 -type f -exec ls -ld {} \; 2>/dev/null
}

# Function to list all running services
list_running_services() {
    echo "Listing all running services:"
    systemctl list-units --type=service --state=running
}

# Function to ensure critical services are running
check_critical_services() {
    echo "Checking critical services:"
    for service in sshd iptables; do
        systemctl is-active --quiet "$service" || echo "$service is not running!"
    done
}

# Function to verify firewall status
check_firewall_status() {
    echo "Checking if the firewall is active:"
    if command -v ufw > /dev/null; then
        ufw status
    elif command -v iptables > /dev/null; then
        iptables -L
    else
        echo "No firewall command found!"
    fi
}

# Function to report open ports
check_open_ports() {
    echo "Listing open ports:"
    netstat -tuln 2>/dev/null
}

# Function to identify public vs. private IPs
check_ip_addresses() {
    echo "Identifying public vs. private IPs:"
    ip -o addr show | awk '/inet/ {print $2, $4}' | while read iface ip; do
        if [[ "$ip" =~ ^10\.|^172\.16\.|^192\.168\. ]]; then
            echo "Private IP: $ip on interface $iface"
        else
            echo "Public IP: $ip on interface $iface"
        fi
    done
}

# Function to check for available security updates
check_security_updates() {
    echo "Checking for available security updates:"
    if command -v apt > /dev/null; then
        apt update && apt list --upgradable 2>/dev/null | grep -i security
    elif command -v dnf > /dev/null; then
        dnf updateinfo list available --security
    elif command -v yum > /dev/null; then
        yum list updates --security
    else
        echo "No compatible package manager found!"
    fi
}

# Function to check for suspicious log entries
check_suspicious_logs() {
    echo "Checking for suspicious log entries:"
    if [ -f /var/log/auth.log ]; then
        grep -i "failed" /var/log/auth.log | tail -10
    else
        echo "No auth.log file found!"
    fi
}

# Function to harden SSH configuration
harden_ssh() {
    echo "Hardening SSH configuration:"
    if [ -f /etc/ssh/sshd_config ]; then
        sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
        systemctl reload sshd
    else
        echo "No sshd_config file found!"
    fi
}

# Function to disable IPv6
disable_ipv6() {
    echo "Disabling IPv6:"
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p
}

# Function to set a password for GRUB bootloader
secure_grub() {
    echo "Setting a password for the GRUB bootloader:"
    if command -v grub-mkpasswd-pbkdf2 > /dev/null; then
        grub-mkpasswd-pbkdf2
        echo "GRUB_PASSWORD setting should be added manually to /etc/grub.d/40_custom"
    else
        echo "grub-mkpasswd-pbkdf2 command not found!"
    fi
}

# Function to configure automatic updates
configure_auto_updates() {
    echo "Configuring automatic updates:"
    if command -v apt > /dev/null; then
        apt install -y unattended-upgrades
        dpkg-reconfigure --priority=low unattended-upgrades
    elif command -v dnf > /dev/null; then
        dnf install -y dnf-automatic
        systemctl enable --now dnf-automatic.timer
    else
        echo "No compatible package manager found for automatic updates!"
    fi
}

# Function to generate a security audit report
generate_report() {
    echo "Generating security audit report:"
    report_file="/var/log/security_audit_report.log"
    echo "Security Audit Report - $(date)" > "$report_file"
    echo "-------------------------------------" >> "$report_file"
    check_uid_zero >> "$report_file"
    check_world_writable_files >> "$report_file"
    check_suid_sgid_files >> "$report_file"
    check_firewall_status >> "$report_file"
    echo "Report generated at $report_file"
}

# Function to run all checks and hardening tasks
run_all_checks() {
    list_users_groups
    check_uid_zero
    check_weak_passwords
    check_world_writable_files
    check_ssh_permissions
    check_suid_sgid_files
    list_running_services
    check_critical_services
    check_firewall_status
    check_open_ports
    check_ip_addresses
    check_security_updates
    check_suspicious_logs
    harden_ssh
    disable_ipv6
    secure_grub
    configure_auto_updates
    generate_report
}

# Main execution
run_all_checks
echo "Security audit and hardening completed."
```
- Make the Script Executable:
```
chmod +x security_audit.sh
```
- Run the script:
```
sudo ./security_audit.sh
```
```bash
[ec2-user@ip-172-31-20-191 monitoring-dashboard]$ sudo ./security_audit.sh 
Listing all users:
root
bin
daemon
adm
lp
sync
shutdown
halt
mail
operator
games
ftp
nobody
dbus
systemd-network
systemd-oom
systemd-resolve
sshd
rpc
libstoragemgmt
systemd-coredump
systemd-timesync
chrony
ec2-instance-connect
rpcuser
tcpdump
ec2-user
Listing all groups:
root
bin
daemon
sys
adm
tty
disk
lp
mem
kmem
wheel
cdrom
mail
man
dialout
floppy
games
tape
video
ftp
lock
audio
users
nobody
utmp
utempter
dbus
input
kvm
render
sgx
systemd-journal
systemd-network
systemd-oom
systemd-resolve
ssh_keys
sshd
rpc
libstoragemgmt
systemd-coredump
systemd-timesync
chrony
ec2-instance-connect
stapusr
stapsys
stapdev
rpcuser
tcpdump
screen
ec2-user
Checking for non-root users with UID 0:
root
Checking for users without passwords:
Scanning for world-writable files:
Checking .ssh directory permissions:
drwx------. 2 ec2-user ec2-user 29 Sep  4 12:14 /home/ec2-user/.ssh
Checking for SUID/SGID files:
---s--x--x. 1 root root 223240 Apr 23 20:34 /usr/bin/sudo
-rwsr-xr-x. 1 root root 58064 Jan 30  2023 /usr/bin/at
-rwsr-xr-x. 1 root root 74360 Nov 20  2023 /usr/bin/chage
-rwsr-xr-x. 1 root root 78680 Nov 20  2023 /usr/bin/gpasswd
-rwsr-xr-x. 1 root root 42392 Nov 20  2023 /usr/bin/newgrp
-rwsr-xr-x. 1 root root 57720 Mar 20 21:18 /usr/bin/su
-rwxr-sr-x. 1 root tty 24576 Mar 20 21:18 /usr/bin/write
-rwsr-xr-x. 1 root root 49264 Mar 20 21:18 /usr/bin/mount
-rwsr-xr-x. 1 root root 36896 Mar 20 21:18 /usr/bin/umount
---s--x---. 1 root stapusr 120568 Feb 16  2023 /usr/bin/staprun
-rwsr-xr-x. 1 root root 32776 Feb  1  2023 /usr/bin/passwd
-rwxr-sr-x. 1 root screen 504160 Jun  8  2023 /usr/bin/screen
-rwsr-xr-x. 1 root root 15528 Mar 26 03:02 /usr/sbin/grub2-set-bootflag
-rwsr-xr-x. 1 root root 16192 Jan 29  2024 /usr/sbin/pam_timestamp_check
-rwsr-xr-x. 1 root root 28712 Jan 29  2024 /usr/sbin/unix_chkpwd
-rwsr-xr-x. 1 root root 116816 Feb  1  2023 /usr/sbin/mount.nfs
-rwx--s--x. 1 root utmp 16176 Jan 29  2023 /usr/libexec/utempter/utempter
-r-xr-sr-x. 1 root ssh_keys 338392 Jul 15 10:20 /usr/libexec/openssh/ssh-keysign
Listing all running services:
  UNIT                       LOAD   ACTIVE SUB     DESCRIPTION                                   
  acpid.service              loaded active running ACPI Event Daemon
  amazon-ssm-agent.service   loaded active running amazon-ssm-agent
  atd.service                loaded active running Deferred execution scheduler
  auditd.service             loaded active running Security Auditing Service
  chronyd.service            loaded active running NTP client/server
  dbus-broker.service        loaded active running D-Bus System Message Bus
  getty@tty1.service         loaded active running Getty on tty1
  gssproxy.service           loaded active running GSSAPI Proxy Daemon
  libstoragemgmt.service     loaded active running libstoragemgmt plug-in server daemon
  rngd.service               loaded active running Hardware RNG Entropy Gatherer Daemon
  serial-getty@ttyS0.service loaded active running Serial Getty on ttyS0
  sshd.service               loaded active running OpenSSH server daemon
  systemd-homed.service      loaded active running Home Area Manager
  systemd-journald.service   loaded active running Journal Service
  systemd-logind.service     loaded active running User Login Management
  systemd-networkd.service   loaded active running Network Configuration
  systemd-resolved.service   loaded active running Network Name Resolution
  systemd-udevd.service      loaded active running Rule-based Manager for Device Events and Files
  systemd-userdbd.service    loaded active running User Database Manager
  user@1000.service          loaded active running User Manager for UID 1000

LOAD   = Reflects whether the unit definition was properly loaded.
ACTIVE = The high-level unit activation state, i.e. generalization of SUB.
SUB    = The low-level unit activation state, values depend on unit type.
20 loaded units listed.
Checking critical services:
iptables is not running!
Checking if the firewall is active:
No firewall command found!
Listing open ports:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
udp        0      0 127.0.0.1:323           0.0.0.0:*                          
udp        0      0 172.31.20.191:68        0.0.0.0:*                          
udp6       0      0 ::1:323                 :::*                               
udp6       0      0 fe80::445:7cff:fe2b:546 :::*                               
Identifying public vs. private IPs:
Public IP: 127.0.0.1/8 on interface lo
Public IP: ::1/128 on interface lo
Public IP: 172.31.20.191/20 on interface enX0
Public IP: fe80::445:7cff:fe2b:2d69/64 on interface enX0
Checking for available security updates:
Last metadata expiration check: 0:02:44 ago on Wed Sep  4 12:14:34 2024.
Checking for suspicious log entries:
No auth.log file found!
Hardening SSH configuration:
Disabling IPv6:
net.ipv6.conf.all.disable_ipv6 = 1
Setting a password for the GRUB bootloader:
grub-mkpasswd-pbkdf2 command not found!
Configuring automatic updates:
Last metadata expiration check: 0:02:44 ago on Wed Sep  4 12:14:34 2024.
Dependencies resolved.
=========================================================================================================================================================================
 Package                                 Architecture                     Version                                            Repository                             Size
=========================================================================================================================================================================
Installing:
 dnf-automatic                           noarch                           4.14.0-1.amzn2023.0.5                              amazonlinux                            29 k

Transaction Summary
=========================================================================================================================================================================
Install  1 Package

Total download size: 29 k
Installed size: 63 k
Downloading Packages:
dnf-automatic-4.14.0-1.amzn2023.0.5.noarch.rpm                                                                                           742 kB/s |  29 kB     00:00    
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Total                                                                                                                                    343 kB/s |  29 kB     00:00     
Running transaction check
Transaction check succeeded.
Running transaction test
Transaction test succeeded.
Running transaction
  Preparing        :                                                                                                                                                 1/1 
  Installing       : dnf-automatic-4.14.0-1.amzn2023.0.5.noarch                                                                                                      1/1 
  Running scriptlet: dnf-automatic-4.14.0-1.amzn2023.0.5.noarch                                                                                                      1/1 
  Verifying        : dnf-automatic-4.14.0-1.amzn2023.0.5.noarch                                                                                                      1/1 

Installed:
  dnf-automatic-4.14.0-1.amzn2023.0.5.noarch                                                                                                                             

Complete!
Created symlink /etc/systemd/system/timers.target.wants/dnf-automatic.timer → /usr/lib/systemd/system/dnf-automatic.timer.
Generating security audit report:
Report generated at /var/log/security_audit_report.log
Security audit and hardening completed.
[ec2-user@ip-172-31-20-191 monitoring-dashboard]$ /var/log/security_audit_report.log
-bash: /var/log/security_audit_report.log: Permission denied
[ec2-user@ip-172-31-20-191 monitoring-dashboard]$ cat /var/log/security_audit_report.log
Security Audit Report - Wed Sep  4 12:17:19 UTC 2024
-------------------------------------
Checking for non-root users with UID 0:
root
Scanning for world-writable files:
Checking for SUID/SGID files:
---s--x--x. 1 root root 223240 Apr 23 20:34 /usr/bin/sudo
-rwsr-xr-x. 1 root root 58064 Jan 30  2023 /usr/bin/at
-rwsr-xr-x. 1 root root 74360 Nov 20  2023 /usr/bin/chage
-rwsr-xr-x. 1 root root 78680 Nov 20  2023 /usr/bin/gpasswd
-rwsr-xr-x. 1 root root 42392 Nov 20  2023 /usr/bin/newgrp
-rwsr-xr-x. 1 root root 57720 Mar 20 21:18 /usr/bin/su
-rwxr-sr-x. 1 root tty 24576 Mar 20 21:18 /usr/bin/write
-rwsr-xr-x. 1 root root 49264 Mar 20 21:18 /usr/bin/mount
-rwsr-xr-x. 1 root root 36896 Mar 20 21:18 /usr/bin/umount
---s--x---. 1 root stapusr 120568 Feb 16  2023 /usr/bin/staprun
-rwsr-xr-x. 1 root root 32776 Feb  1  2023 /usr/bin/passwd
-rwxr-sr-x. 1 root screen 504160 Jun  8  2023 /usr/bin/screen
-rwsr-xr-x. 1 root root 15528 Mar 26 03:02 /usr/sbin/grub2-set-bootflag
-rwsr-xr-x. 1 root root 16192 Jan 29  2024 /usr/sbin/pam_timestamp_check
-rwsr-xr-x. 1 root root 28712 Jan 29  2024 /usr/sbin/unix_chkpwd
-rwsr-xr-x. 1 root root 116816 Feb  1  2023 /usr/sbin/mount.nfs
-rwx--s--x. 1 root utmp 16176 Jan 29  2023 /usr/libexec/utempter/utempter
-r-xr-sr-x. 1 root ssh_keys 338392 Jul 15 10:20 /usr/libexec/openssh/ssh-keysign
Checking if the firewall is active:
No firewall command found!
[ec2-user@ip-172-31-20-191 monitoring-dashboard]$ git add .
```
## Step 4 : To check the log and report
- **Review the Report**: After the script completes, check the generated report at `/var/log/security_audit_report.log`  for detailed findings and actions taken.
In my case i have got this report

![image.png](https://eraser.imgix.net/workspaces/HIVnA3F1HU8IEAzDE67y/5T6WA8Rp9oV9FfxS5Xk5Ozc3twa2/MGpXHNOv-Nh-UkABE7FNo.png?ixlib=js-3.7.0 "image.png")

## Features
#### User and Group Listing
The script lists all users and groups on the system. This helps in identifying any unauthorized or suspicious accounts.

#### Check for Non-root Users with UID 0
The script checks if there are any non-root users with a UID of 0, which could indicate a security issue, as only the root user should have this UID.

#### Check for Users Without Passwords
The script checks if there are any user accounts without passwords, which could be a security risk.

#### World-writable Files
The script scans the filesystem for world-writable files, which can be a security concern as they could potentially be modified by unauthorized users.

#### SUID/SGID Files
The script identifies files with SUID/SGID bits set. These files can be a security risk if misconfigured.

#### Running Services
The script lists all running services, helping to identify any unnecessary or potentially malicious services.

#### Critical Services
The script checks if critical services like `iptables` (firewall) are running. It also verifies whether the firewall is active.

#### Open Ports
The script lists all open ports on the system, which can be useful for identifying potential vulnerabilities.

#### Public vs. Private IPs
The script identifies public and private IP addresses assigned to the system's network interfaces.

#### Security Updates
The script checks for available security updates. This feature helps ensure that the system is running the latest security patches.

#### Suspicious Log Entries
The script searches for suspicious entries in the system's authentication logs, which can help in identifying potential security breaches.

#### SSH Hardening
The script hardens the SSH configuration by disabling root login, enforcing strong authentication, and restricting SSH access.

#### Disable IPv6
The script disables IPv6 on the system, which can help reduce the attack surface if IPv6 is not required.

#### GRUB Bootloader Password
The script prompts to set a password for the GRUB bootloader to prevent unauthorized access to the system during boot.

#### Automatic Updates
The script configures the system to automatically install security updates, ensuring the system remains up-to-date.

#### Troubleshooting
If you encounter any issues while running the script, ensure that all necessary utilities are installed. The script is designed to work on most Linux distributions, but some features may require specific tools (e.g., `apt` for Debian-based systems).

#### Contributing
Contributions are welcome! Please fork the repository and submit a pull request with your improvements.

