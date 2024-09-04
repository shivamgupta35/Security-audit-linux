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
