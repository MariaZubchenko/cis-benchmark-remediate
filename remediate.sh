#!/usr/bin/env bash

### for test ###
# yum update -y
# service httpd start
# chkconfig httpd on

# 1.1.2 Ensure /tmp is configured

#systemctl unmask tmp.mountsystemctl enable tmp.mount 


# 1.1.17 Ensure noexec option set on /dev/shm partition

# 1.1.1.1 Ensure mounting of cramfs filesystems is disabled (worked)

echo "install cramfs /bin/true" >> /etc/modprobe.d/cramfs.conf
sudo rmmod cramfs

# 1.1.1.2 Ensure mounting of hfs filesystems is disabled (worked)

echo "install hfs /bin/true" >> /etc/modprobe.d/hfs.conf
sudo rmmod hfs

# 1.1.1.3 Ensure mounting of hfsplus filesystems is disabled (worked)

echo "install hfsplus /bin/true" >> /etc/modprobe.d/hfsplus.conf
sudo rmmod hfsplus

# 1.1.1.4 Ensure mounting of squashfs filesystems is disabled (worked)

echo "install squashfs /bin/true" >> /etc/modprobe.d/squashfs.conf
sudo rmmod squashfs

# 1.1.1.5 Ensure mounting of udf filesystems is disabled (worked)

echo "install udf /bin/true" >> /etc/modprobe.d/udf.conf
sudo rmmod udf

# 1.3.1 Ensure AIDE is installed (worked)

sudo yum install aide -y

# 1.3.2 Ensure filesystem integrity is regularly checked

# 1.4.1 Ensure permissions on bootloader config are configured (worked)

sudo chownroot: root /boot/grub2/grub.cfg
sudo chmod og-rwx /boot/grub2/grub.cfg

# 1.5.1 Ensure core dumps are restricted

echo "hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
sysctl -w fs.suid_dumpable = 0

# 1.5.2 Ensure address space layout randomization (ASLR) is enabled

# 1.7.1.1 Ensure message of the day is configured properly

# 1.7.1.2 Ensure local login warning banner is configured properly

# 1.7.1.3 Ensure remote login warning banner is configured properly

# 3.1.1 Ensure IP forwarding is disabled (worked)

echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding = 0" >> /etc/sysctl.conf
sudo sysctl -w net.ipv4.ip_forward = 0
sudo sysctl -w net.ipv6.conf.all.forwarding = 0
sudo sysctl -w net.ipv4.route.flush = 1
sudo sysctl -w net.ipv6.route.flush = 1

# 3.1.2 Ensure packet redirect sending is disabled (fixed)

echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
sudo sysctl -w net.ipv4.conf.all.send_redirects = 0
sudo sysctl -w net.ipv4.conf.default.send_redirects = 0
sudo sysctl -w net.ipv4.route.flush = 1

# 3.2.1 Ensure source routed packets are not accepted (worked)

echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
sudo sysctl -w net.ipv4.conf.all.accept_source_route = 0
sudo sysctl -w net.ipv4.conf.default.accept_source_route = 0
sudo sysctl -w net.ipv6.conf.all.accept_source_route = 0
sudo sysctl -w net.ipv6.conf.default.accept_source_route = 0
sudo sysctl -w net.ipv4.route.flush = 1
sudo sysctl -w net.ipv6.route.flush = 1

# 3.2.2 Ensure ICMP redirects are not accepted (fixed)

echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
sudo sysctl -w net.ipv4.conf.all.accept_redirects = 0
sudo sysctl -w net.ipv4.conf.default.accept_redirects = 0
sudo sysctl -w net.ipv6.conf.all.accept_redirects = 0
sudo sysctl -w net.ipv6.conf.default.accept_redirects = 0
sudo sysctl -w net.ipv4.route.flush = 1
sudo sysctl -w net.ipv6.route.flush = 1

# 3.2.3 Ensure secure ICMP redirects are not accepted (fixed)

echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
sudo sysctl -w net.ipv4.conf.all.secure_redirects = 0
sudo sysctl -w net.ipv4.conf.default.secure_redirects = 0
sudo sysctl -w net.ipv4.route.flush = 1

# 3.2.4 Ensure suspicious packets are logged (fixed)

echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
sudo sysctl -w net.ipv4.conf.all.log_martians = 1
sudo sysctl -w net.ipv4.conf.default.log_martians = 1
sudo sysctl -w net.ipv4.route.flush = 1

# 3.2.5 Ensure broadcast ICMP requests are ignored (worked)

echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts = 1
sudo sysctl -w net.ipv4.route.flush = 1

# 3.2.6 Ensure bogus ICMP responses are ignored (worked)
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
sudo sysctl -w net.ipv4.icmp_ignore_bogus_error_responses = 1
sudo sysctl -w net.ipv4.route.flush = 1

# 3.2.7 Ensure Reverse Path Filtering is enabled (worked)

echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
sudo sysctl -w net.ipv4.conf.all.rp_filter = 1
sudo sysctl -w net.ipv4.conf.default.rp_filter = 1
sudo sysctl -w net.ipv4.route.flush = 1

# 3.2.8 Ensure TCP SYN Cookies is enabled (worked)

echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
sudo sysctl -w net.ipv4.tcp_syncookies = 1
sudo sysctl -w net.ipv4.route.flush = 1

# 3.2.9 Ensure IPv6 router advertisements are not accepted (fixed)

echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf
sudo sysctl -w net.ipv6.conf.all.accept_ra = 0
sudo sysctl -w net.ipv6.conf.default.accept_ra = 0
sudo sysctl -w net.ipv6.route.flush = 1

# 3.3.3 Ensure /etc/hosts.deny is configured (worked)

echo "ALL: ALL" >> /etc/hosts.deny

# 3.4.1 Ensure DCCP is disabled (worked)

echo "install dccp /bin/true" >>  /etc/modprobe.d/dccp.conf

# 3.4.2 Ensure SCTP is disabled (worked)

echo "install sctp /bin/true" >>  /etc/modprobe.d/sctp.conf

# 3.4.3 Ensure RDS is disabled (worked)

echo "install rds /bin/true" >> /etc/modprobe.d/rds.conf

# 3.4.4 Ensure TIPC is disabled (worked)

echo "install tipc /bin/true" >> /etc/modprobe.d/tipc.conf

# 3.5.1.1 Ensure default deny firewall policy

# 3.5.1.2 Ensure loopback traffic is configured

# 3.5.1.4 Ensure firewall rules exist for all open ports

# 3.5.2.1 Ensure IPv6 default deny firewall policy

# 3.5.2.2 Ensure IPv6 loopback traffic is configured

# 4.2.4 Ensure permissions on all logfiles are configured

# 4.2.1.3 Ensure rsyslog default file permissions configured (worked)

echo "\$FileCreateMode 0640" >> /etc/rsyslog.conf

# 4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host

# 5.6 Ensure access to the su command is restricted (worked)

echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su

# 5.1.2 Ensure permissions on /etc/crontab are configured (worked)

sudo chown root:root /etc/crontab
sudo chmod og-rwx /etc/crontab

# 5.1.3 Ensure permissions on /etc/cron.hourly are configured (worked)

chown root:root /etc/cron.hourly 
chmod og-rwx /etc/cron.hourly

# 5.1.4 Ensure permissions on /etc/cron.daily are configured (worked)

chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily

# 5.1.5 Ensure permissions on /etc/cron.weekly are configured (worked)

chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly

# 5.1.6 Ensure permissions on /etc/cron.monthly are configured (worked)

chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly

# 5.1.7 Ensure permissions on /etc/cron.d are configured (worked)

chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d

# 5.1.8 Ensure at/cron is restricted to authorized users (worked)

rm /etc/cron.deny
rm /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow

# 5.2.4 Ensure SSH Protocol is set to 2

# 5.2.5 Ensure SSH LogLevel is appropriate

# 5.2.7 Ensure SSH MaxAuthTries is set to 4 or less

# 5.2.8 Ensure SSH IgnoreRhosts is enabled

# 5.2.9 Ensure SSH HostbasedAuthentication is disabled

# 5.2.10 Ensure SSH root login is disabled

# 5.2.11 Ensure SSH PermitEmptyPasswords is disabled

# 5.2.12 Ensure SSH PermitUserEnvironment is disabled

# 5.2.13 Ensure only strong ciphers are used

# 5.2.14 Ensure only strong MAC algorithms are used

# 5.2.15 Ensure that strong Key Exchange algorithms are used

# 5.2.16 Ensure SSH Idle Timeout Interval is configured

# 5.2.17 Ensure SSH LoginGraceTime is set to one minute or less

# 5.2.18 Ensure SSH access is limited

# 5.2.19 Ensure SSH warning banner is configured

# 5.3.1 Ensure password creation requirements are configured

# 5.3.2 Ensure lockout for failed password attempts is configured

echo "auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900" >> /etc/pam.d/system-auth
echo "auth [success=1 default=bad] pam_unix.so" >> /etc/pam.d/system-auth
echo "auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900" >> /etc/pam.d/system-auth
echo "auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900" >> /etc/pam.d/system-auth

# 5.3.3 Ensure password reuse is limited

# 5.4.4 Ensure default user umask is 027 or more restrictive

echo "umask 027" >> /etc/bashrc
echo "umask 027" >> /etc/profile

# 5.4.1.1 Ensure password expiration is 365 days or less

# 5.4.1.2 Ensure minimum days between password changes is 7 or more

# 5.4.1.4 Ensure inactive password lock is 30 days or less

# 1.1.6 Ensure separate partition exists for /var

# 1.1.7 Ensure separate partition exists for /var/tmp

# 1.1.11 Ensure separate partition exists for /var/log

# 1.1.12 Ensure separate partition exists for /var/log/audit

# 1.1.13 Ensure separate partition exists for /home

# 1.1.17 Ensure noexec option set on /dev/shm partition

# 1.6.1.2 Ensure the SELinux state is enforcing
 
# 1.6.1.3 Ensure SELinux policy is configured

# 1.6.1.6 Ensure no unconfined daemons exist

# 3.6 Disable IPv6

# 4.1.4 Ensure events that modify date and time information are collected

# 4.1.5 Ensure events that modify user/group information are collected

# 4.1.6 Ensure events that modify the system's network environment are collected

# 4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected

# 4.1.8 Ensure login and logout events are collected

# 4.1.9 Ensure session initiation information is collected

# 4.1.10 Ensure discretionary access control permission modification events are collected

# 4.1.11 Ensure unsuccessful unauthorized file access attempts are collected

# 4.1.13 Ensure successful file system mounts are collected

# 4.1.14 Ensure file deletion events by users are collected

# 4.1.15 Ensure changes to system administration scope (sudoers) is collected

# 4.1.16 Ensure system administrator actions (sudolog) are collected

# 4.1.17 Ensure kernel module loading and unloading is collected

# 4.1.18 Ensure the audit configuration is immutable

# 4.1.1.2 Ensure system is disabled when audit logs are full

# 4.1.1.3 Ensure audit logs are not automatically deleted

# 5.4.5 Ensure default user shell timeout is 900 seconds or less



