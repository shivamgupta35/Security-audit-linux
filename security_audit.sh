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
    find / -xdev -type f -perm -0002 -exec ls -l {} \;
}

# Function to check .ssh directory permissions
check_ssh_permissions() {
    echo "Checking .ssh directory permissions:"
    find /home -type d -name ".ssh" -exec chmod 700 {} \;
}

# Function to report SUID/SGID files
check_suid_sgid_files() {
    echo "Checking for SUID/SGID files:"
    find / -perm /6000 -type f -exec ls -ld {} \;
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
        systemctl is-active --quiet $service || echo "$service is not running!"
    done
}

# Function to verify firewall status
check_firewall_status() {
    echo "Checking if the firewall is active:"
    ufw status || iptables -L
}

# Function to report open ports
check_open_ports() {
    echo "Listing open ports:"
    netstat -tuln
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
    apt update && apt list --upgradable | grep -i security
}

# Function to check for suspicious log entries
check_suspicious_logs() {
    echo "Checking for suspicious log entries:"
    grep -i "failed" /var/log/auth.log | tail -10
}

# Function to harden SSH configuration
harden_ssh() {
    echo "Hardening SSH configuration:"
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl reload sshd
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
    grub-mkpasswd-pbkdf2
    echo "GRUB_PASSWORD setting should be added manually to /etc/grub.d/40_custom"
}

# Function to configure automatic updates
configure_auto_updates() {
    echo "Configuring automatic updates:"
    apt install unattended-upgrades
    dpkg-reconfigure --priority=low unattended-upgrades
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
