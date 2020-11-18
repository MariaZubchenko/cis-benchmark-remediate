#!/usr/bin/env bash

# 1.1.2 Ensure /tmp is configured

###Recommendation###
# Configure /etc/fstab as appropriate. example:tmpfs /tmp tmpfs defaults,rw,nosuid,nodev
# ,noexec,relatime 0 0 or Run the following commands to enable systemd /tmp mounting:
# systemctl unmask tmp.mountsystemctl enable tmp.mount 
# Edit /etc/systemd/system/
# local-fs.target.wants/tmp.mount to configure the /tmp mount: [Mount]What=tmpfsWhe
# re=/tmpType=tmpfsOptions=mode=1777,strictatime,noexec,nodev,nosuid Impact:
# Since the /tmp directory is intended to be world-writable, there is a risk of resource
# exhaustion if it is not bound to a separate partition.Running out of /tmp space is a problem regardless of what kind of filesystem lies under it, but in a default installation
# a disk-based /tmp will essentially have the whole disk available, as it only creates a
# single / partition. On the other hand, a RAM-based /tmp as with tmpfs will almost
# certainly be much smaller, which can lead to applications filling up the filesystem much
# more easily./tmp utalizing tmpfs can be resized using the size={size} parameter on the
# Options line on the tmp.mount file
######

#systemctl unmask tmp.mountsystemctl enable tmp.mount 


# 1.1.17 Ensure noexec option set on /dev/shm partition

###Recommendation###
# Edit the /etc/fstab file and add noexec to the fourth field (mounting options) for
# the /dev/shm partition. See the fstab(5) manual page for more information. Run the
# following command to remount /dev/shm : # mount -o remount,noexec /dev/shm
######

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

###Recommendation###
# Run the following command: # crontab -u root -e Add the following line to the crontab:
# 0 5 * * * /usr/sbin/aide --check
######

# 1.4.1 Ensure permissions on bootloader config are configured (worked)

sudo chownroot: root /boot/grub2/grub.cfg
sudo chmod og-rwx /boot/grub2/grub.cfg

# 1.5.1 Ensure core dumps are restricted (fixed)

###Recommendation###
# Add the following line to /etc/security/limits.conf or a /etc/security/limits.d/* file:
# * hard core 0 Set the following parameter in /etc/sysctl.conf or a /etc/sysctl.d/* file:
# fs.suid_dumpable = 0 Run the following command to set the active kernel parameter: #
# sysctl -w fs.suid_dumpable=0
######

echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
sysctl -w fs.suid_dumpable = 0

# 1.5.2 Ensure address space layout randomization (ASLR) is enabled (fixed)

###Recommendation###
# Set the following parameter in /etc/sysctl.conf or a /etc/sysctl.d/* file:
# kernel.randomize_va_space = 2 Run the following command to set the active kernel
# parameter: # sysctl -w kernel.randomize_va_space=2
######

echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
sysctl -w kernel.randomize_va_space = 2

# 1.7.1.1 Ensure message of the day is configured properly

###Recommendation###
# Edit the /etc/motd file with the appropriate contents according to your site policy,
# remove any instances of \m , \r , \s ,\v. , or references to the OS platform
######

# 1.7.1.2 Ensure local login warning banner is configured properly (fixed)

###Recommendation###
# Edit the /etc/issue file with the appropriate contents according to your site policy,
# remove any instances of \m , \r , \s , \v or references to the OS platform: # echo
# "Authorized uses only. All activity may be monitored and reported." > /etc/issue
######

echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue

# 1.7.1.3 Ensure remote login warning banner is configured properly (fixed)

###Recommendation###
# Edit the /etc/issue.net file with the appropriate contents according to your site policy,
# remove any instances of \m , \r , \s , or \v , or references to the OS platform: # echo
# "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net
######

echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net

# 3.1.1 Ensure IP forwarding is disabled (worked)

echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding = 0" >> /etc/sysctl.conf
sudo sysctl -w net.ipv4.ip_forward = 0
sudo sysctl -w net.ipv6.conf.all.forwarding = 0
sudo sysctl -w net.ipv4.route.flush = 1
sudo sysctl -w net.ipv6.route.flush = 1

# 3.1.2 Ensure packet redirect sending is disabled (fixed)

###Recommendation###
# Set the following parameters in /etc/sysctl.conf or a /etc/sysctl.d/* file: net.ipv4
# .conf.all.send_redirects = 0net.ipv4.conf.default.send_redirects = 0 Run the
# following commands to set the active kernel parameters: # sysctl -w net.ipv4.con
# f.all.send_redirects=0# sysctl -w net.ipv4.conf.default.send_redirects=0# sysctl -w
# net.ipv4.route.flush=1
######

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

###Recommendation###
# Set the following parameters in /etc/sysctl.conf or a /etc/sysctl.d/* file: net.ipv4.con
# f.all.accept_redirects = 0net.ipv4.conf.default.accept_redirects = 0net.ipv6.conf.a
# ll.accept_redirects = 0net.ipv6.conf.default.accept_redirects = 0 Run the following
# commands to set the active kernel parameters: # sysctl -w net.ipv4.conf.all.accept_red
# irects=0# sysctl -w net.ipv4.conf.default.accept_redirects=0# sysctl -w net.ipv6.con
# f.all.accept_redirects=0# sysctl -w net.ipv6.conf.default.accept_redirects=0# sysctl -w
# net.ipv4.route.flush=1# sysctl -w net.ipv6.route.flush=1
######

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

###Recommendation###
# Set the following parameters in /etc/sysctl.conf or a /etc/sysctl.d/* file: net.ipv4
# .conf.all.secure_redirects = 0net.ipv4.conf.default.secure_redirects = 0 Run the
# following commands to set the active kernel parameters: # sysctl -w net.ipv4.conf.all.secure_redirects=0# sysctl -w net.ipv4.conf.default.secure_redirects=0# sysctl -w
# net.ipv4.route.flush=1
######

echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
sudo sysctl -w net.ipv4.conf.all.secure_redirects = 0
sudo sysctl -w net.ipv4.conf.default.secure_redirects = 0
sudo sysctl -w net.ipv4.route.flush = 1

# 3.2.4 Ensure suspicious packets are logged (fixed)

###Recommendation###
# Set the following parameters in /etc/sysctl.conf or a /etc/sysctl.d/* file:
# net.ipv4.conf.all.log_martians = 1net.ipv4.conf.default.log_martians = 1 Run the
# following commands to set the active kernel parameters: # sysctl -w net.ipv4.con
# f.all.log_martians=1# sysctl -w net.ipv4.conf.default.log_martians=1# sysctl -w
# net.ipv4.route.flush=1
######

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

###Recommendation###
# Set the following parameters in /etc/sysctl.conf or a /etc/sysctl.d/* file:
# net.ipv6.conf.all.accept_ra = 0net.ipv6.conf.default.accept_ra = 0 Run
# the following commands to set the active kernel parameters: # sysctl -w
# net.ipv6.conf.all.accept_ra=0# sysctl -w net.ipv6.conf.default.accept_ra=0# sysctl -w
# net.ipv6.route.flush=1
######

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

# 3.5.1.1 Ensure default deny firewall policy (fixed)

###Recommendation###
# Run the following commands to implement a default DROP policy: # iptables -P
# INPUT DROP# iptables -P OUTPUT DROP# iptables -P FORWARD DROP
######

iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# 3.5.1.2 Ensure loopback traffic is configured (fixed)

###Recommendation###
# Run the following commands to implement the loopback rules: # iptables -A INPUT
# -i lo -j ACCEPT# iptables -A OUTPUT -o lo -j ACCEPT# iptables -A INPUT -s
# 127.0.0.0/8 -j DROP
######

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -s 127.0.0.0/8 -j DROP

# 3.5.1.4 Ensure firewall rules exist for all open ports

###Recommendation###
# For each port identified in the audit which does not have a firewall rule establish a
# proper rule for accepting inbound connections: 
# iptables -A INPUT -p <protocol> -- dport <port> -m state --state NEW -j ACCEPT
######

# 3.5.2.1 Ensure IPv6 default deny firewall policy (fixed)

###Recommendation###
# Run the following commands to implement a default DROP policy: # ip6tables -P
# INPUT DROP# ip6tables -P OUTPUT DROP# ip6tables -P FORWARD DROP
######

ip6tables -P INPUT DROP
ip6tables -P OUTPUT DROP
ip6tables -P FORWARD DROP

# 3.5.2.2 Ensure IPv6 loopback traffic is configured (worked)

###Recommendation###
# Run the following commands to implement the loopback rules: # ip6tables -A INPUT -
# i lo -j ACCEPT# ip6tables -A OUTPUT -o lo -j ACCEPT# ip6tables -A INPUT -s ::1 -j
# DROP
######

ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT
ip6tables -A INPUT -s ::1 -j DROP

# 4.2.4 Ensure permissions on all logfiles are configured (fixed)

###Recommendation###
# Run the following command to set permissions on all existing log files: # find -L /var/
# log -type f -exec chmod g-wx,o-rwx {} +
######

find -L /var/ log -type f -exec 
hmod g-wx,o-rwx {} +

# 4.2.1.3 Ensure rsyslog default file permissions configured (worked)

echo "\$FileCreateMode 0640" >> /etc/rsyslog.conf

# 4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host

###Recommendation###
# Edit the /etc/rsyslog.conf and /etc/rsyslog.d/*.conf files and add the following
# line (where loghost.example.com is the name of your central log host). *.*
# @@loghost.example.com Run the following command to reload the rsyslogd
# configuration: # pkill -HUP rsyslogd
######

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

###Recommendation###
# Edit the /etc/ssh/sshd_config file to set the parameter as follows: Protocol 2
######

# 5.2.5 Ensure SSH LogLevel is appropriate

###Recommendation###
# Edit the /etc/ssh/sshd_config file to set the parameter as follows: LogLevel VERBOSE
# or LogLevel INFO
######

# 5.2.7 Ensure SSH MaxAuthTries is set to 4 or less

###Recommendation###
# Edit the /etc/ssh/sshd_config file to set the parameter as follows: MaxAuthTries 4
######

# 5.2.8 Ensure SSH IgnoreRhosts is enabled

###Recommendation###
# Edit the /etc/ssh/sshd_config file to set the parameter as follows: MaxAuthTries 4
######

# 5.2.9 Ensure SSH HostbasedAuthentication is disabled

###Recommendation###
# Edit the /etc/ssh/sshd_config file to set the parameter as follows:
# HostbasedAuthentication no
######

# 5.2.10 Ensure SSH root login is disabled

###Recommendation###
# Edit the /etc/ssh/sshd_config file to set the parameter as follows:
# HostbasedAuthentication no
######

# 5.2.11 Ensure SSH PermitEmptyPasswords is disabled

###Recommendation###
# Edit the /etc/ssh/sshd_config file to set the parameter as follows:
# PermitEmptyPasswords no
######

# 5.2.12 Ensure SSH PermitUserEnvironment is disabled

###Recommendation###
# Edit the /etc/ssh/sshd_config file to set the parameter as follows:
# PermitUserEnvironment no
######

# 5.2.13 Ensure only strong ciphers are used

###Recommendation###
# Edit the /etc/ssh/sshd_config file add/modify the Ciphers line to contain a comma
# separated list of the site approved ciphers Example: Ciphers chacha20-poly1305@op
# enssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ct
# r,aes128-ctr
######

# 5.2.14 Ensure only strong MAC algorithms are used

###Recommendation###
# Edit the /etc/ssh/sshd_config file and add/modify the MACs line to contain a comma
# separated list of the site approved MACs Example: MACs hmac-sha2-512-etm@openss
# h.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
######

# 5.2.15 Ensure that strong Key Exchange algorithms are used

###Recommendation###
# Edit the /etc/ssh/sshd_config file add/modify the KexAlgorithms line to contain
# a comma separated list of the site approved key exchange algorithms Example:
# KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-gr
# oup14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sh
# a2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchangesha256
######

# 5.2.16 Ensure SSH Idle Timeout Interval is configured

###Recommendation###
# Edit the /etc/ssh/sshd_config file to set the parameters according to site policy:
# ClientAliveInterval 300ClientAliveCountMax 0
######

# 5.2.17 Ensure SSH LoginGraceTime is set to one minute or less

###Recommendation###
# Edit the /etc/ssh/sshd_config file to set the parameter as follows: LoginGraceTime 60
######

# 5.2.18 Ensure SSH access is limited

###Recommendation###
# Edit the /etc/ssh/sshd_config file to set one or more of the parameter as follows:
# AllowUsers <userlist>AllowGroups <grouplist>DenyUsers <userlist>DenyGroups
# <grouplist>
######

# 5.2.19 Ensure SSH warning banner is configured

###Recommendation###
# Edit the /etc/ssh/sshd_config file to set the parameter as follows: Banner /etc/issue.net
######

# 5.3.1 Ensure password creation requirements are configured

###Recommendation###
# Edit the /etc/pam.d/password-auth and /etc/pam.d/system-auth files to include the
# appropriate options for pam_pwquality.so and to conform to site policy: password
# requisite pam_pwquality.so try_first_pass retry=3 Edit /etc/security/pwquality.conf to
# add or update the following settings to conform to site policy: minlen = 14dcredit =
# -1ucredit = -1ocredit = -1lcredit = -1
######

# 5.3.2 Ensure lockout for failed password attempts is configured

###Recommendation###
# Edit the /etc/pam.d/password-auth and /etc/pam.d/system-auth files and add
# the following pam_faillock.so lines surrounding a pam_unix.so line modify
# the pam_unix.so is [success=1 default=bad] as listed in both: auth required
# pam_faillock.so preauth audit silent deny=5 unlock_time=900auth [success=1
# default=bad] pam_unix.soauth [default=die] pam_faillock.so authfail audit
# deny=5 unlock_time=900auth sufficient pam_faillock.so authsucc audit deny=5
# unlock_time=900
######

echo "auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900" >> /etc/pam.d/system-auth
echo "auth [success=1 default=bad] pam_unix.so" >> /etc/pam.d/system-auth
echo "auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900" >> /etc/pam.d/system-auth
echo "auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900" >> /etc/pam.d/system-auth

# 5.3.3 Ensure password reuse is limited

###Recommendation###
# Edit the /etc/pam.d/password-auth and /etc/pam.d/system-auth files to include the
# remember option and conform to site policy as shown: password sufficient pam_unix.so
# remember=5 or password required pam_pwhistory.so remember=5
######

# 5.4.4 Ensure default user umask is 027 or more restrictive

###Recommendation###
# Edit the /etc/bashrc, /etc/profile and /etc/profile.d/*.sh files (and the appropriate files
# for any other shell supported on your system) and add or edit any umask parameters as
# follows: umask 027
######

echo "umask 027" >> /etc/bashrc
echo "umask 027" >> /etc/profile

# 5.4.1.1 Ensure password expiration is 365 days or less

###Recommendation###
# Set the PASS_MAX_DAYS parameter to conform to site policy in /etc/login.defs :
# PASS_MAX_DAYS 90 Modify user parameters for all users with a password set to
# match: # chage --maxdays 90 <user>
######

# 5.4.1.2 Ensure minimum days between password changes is 7 or more

###Recommendation###
# Set the PASS_MIN_DAYS parameter to 7 in /etc/login.defs : PASS_MIN_DAYS 7
# Modify user parameters for all users with a password set to match: # chage --mindays 7
# <user>
######

# 5.4.1.4 Ensure inactive password lock is 30 days or less

###Recommendation###
# Run the following command to set the default password inactivity period to 30 days: #
# useradd -D -f 30 Modify user parameters for all users with a password set to match: #
# chage --inactive 30 <user>
######

# 1.1.6 Ensure separate partition exists for /var

###Recommendation###
# For new installations, during installation create a custom partition setup and specify
# a separate partition for /var . For systems that were previously installed, create a new
# partition and configure /etc/fstab as appropriate. Impact: Resizing filesystems is a
# common activity in cloud-hosted servers. Separate filesystem partitions may prevent
# successful resizing, or may require the installation of additional tools solely for the
# purpose of resizing operations. The use of these additional tools may introduce their
# own security considerations.
######

# 1.1.7 Ensure separate partition exists for /var/tmp

###Recommendation###
# For new installations, during installation create a custom partition setup and specify
# a separate partition for /var/tmp For systems that were previously installed, create a
# new partition and configure /etc/fstab as appropriate. Impact: Resizing filesystems is
# a common activity in cloud-hosted servers. Separate filesystem partitions may prevent
# successful resizing, or may require the installation of additional tools solely for the
# purpose of resizing operations. The use of these additional tools may introduce their
# own security considerations.
######

# 1.1.11 Ensure separate partition exists for /var/log

###Recommendation###
# For new installations, during installation create a custom partition setup and specify
# a separate partition for /var/log . For systems that were previously installed, create a
# new partition and configure /etc/fstab as appropriate. Impact: Resizing filesystems is
# a common activity in cloud-hosted servers. Separate filesystem partitions may prevent
# successful resizing, or may require the installation of additional tools solely for the
# purpose of resizing operations. The use of these additional tools may introduce their
# own security considerations.
######

# 1.1.12 Ensure separate partition exists for /var/log/audit

###Recommendation###
# For new installations, during installation create a custom partition setup and specify a
# separate partition for /var/log/audit . For systems that were previously installed, create
# a new partition and configure /etc/fstab as appropriate. Impact: Resizing filesystems is
# a common activity in cloud-hosted servers. Separate filesystem partitions may prevent
# successful resizing, or may require the installation of additional tools solely for the
# purpose of resizing operations. The use of these additional tools may introduce their
# own security considerations.
######

# 1.1.13 Ensure separate partition exists for /home

###Recommendation###
# For new installations, during installation create a custom partition setup and specify
# a separate partition for /home . For systems that were previously installed, create a
# new partition and configure /etc/fstab as appropriate. Impact: Resizing filesystems is
# a common activity in cloud-hosted servers. Separate filesystem partitions may prevent
# successful resizing, or may require the installation of additional tools solely for the purpose of resizing operations. The use of these additional tools may introduce their
# own security considerations.
######

# 1.1.17 Ensure noexec option set on /dev/shm partition

###Recommendation###
# Edit the /etc/fstab file and add noexec to the fourth field (mounting options) for
# the /dev/shm partition. See the fstab(5) manual page for more information. Run the
# following command to remount /dev/shm : # mount -o remount,noexec /dev/shm
######

# 1.6.1.2 Ensure the SELinux state is enforcing
 
###Recommendation###
# Edit the /etc/selinux/config file to set the SELINUX parameter: SELINUX=enforcing
######

# 1.6.1.3 Ensure SELinux policy is configured

###Recommendation###
# Edit the /etc/selinux/config file to set the SELINUXTYPE parameter:
# SELINUXTYPE=targeted
######

# 1.6.1.6 Ensure no unconfined daemons exist

###Recommendation###
# Investigate any unconfined daemons found during the audit action. They may need to
# have an existing security context assigned to them or a policy built for them.
######

# 3.6 Disable IPv6

###Recommendation###
# Edit /etc/default/grub and remove add ipv6.disable=1 to the
# GRUB_CMDLINE_LINUX parameters: GRUB_CMDLINE_LINUX="ipv6.disable=1"
# Run the following command to update the grub2 configuration: # grub2-mkconfig -o /
# boot/grub2/grub.cfg
######

# 4.1.4 Ensure events that modify date and time information are collected

###Recommendation###
# For 32 bit systems add the following lines to the /etc/audit/rules.d/audit.rules file: -
# a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change-a
# always,exit -F arch=b32 -S clock_settime -k time-change-w /etc/localtime -p wa -k
# time-change For 64 bit systems add the following lines to the /etc/audit/audit.rules file:
# -a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change-a always,exit
# -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change-a always,exit -F
# arch=b64 -S clock_settime -k time-change-a always,exit -F arch=b32 -S clock_settime -
# k time-change-w /etc/localtime -p wa -k time-change
######

# 4.1.5 Ensure events that modify user/group information are collected

###Recommendation###
# Add the following lines to the /etc/audit/rules.d/audit.rules file: -w /etc/group -p wa
# -k identity-w /etc/passwd -p wa -k identity-w /etc/gshadow -p wa -k identity-w /etc/
# shadow -p wa -k identity-w /etc/security/opasswd -p wa -k identity
######

# 4.1.6 Ensure events that modify the system's network environment are collected

###Recommendation###
# For 32 bit systems add the following lines to the /etc/audit/rules.d/audit.rules file: -a
# always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale-w /etc/
# issue -p wa -k system-locale-w /etc/issue.net -p wa -k system-locale-w /etc/hosts -p
# wa -k system-locale-w /etc/sysconfig/network -p wa -k system-locale-w /etc/sysconf
# ig/network-scripts/ -p wa -k system-locale For 64 bit systems add the following lines
# to the /etc/audit/rules.d/audit.rules file: -a always,exit -F arch=b64 -S sethostname
# -S setdomainname -k system-locale -a always,exit -F arch=b32 -S sethostname -S
# setdomainname -k system-locale-w /etc/issue -p wa -k system-locale-w /etc/issue.net -p
# wa -k system-locale-w /etc/hosts -p wa -k system-locale-w /etc/sysconfig/network -p wa
# -k system-locale-w /etc/sysconfig/network-scripts/ -p wa -k system-locale
######

# 4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected

###Recommendation###
# Add the following lines to the /etc/audit/rules.d/audit.rules file: -w /etc/selinux/ -p wa -k
# MAC-policy-w /usr/share/selinux/ -p wa -k MAC-policy
######

# 4.1.8 Ensure login and logout events are collected

###Recommendation###
# Add the following lines to the /etc/audit/rules.d/audit.rules file: -w /var/log/lastlog -p wa
# -k logins-w /var/run/faillock/ -p wa -k logins
######

# 4.1.9 Ensure session initiation information is collected

###Recommendation###
# Add the following lines to the /etc/audit/rules.d/audit.rules file: -w /var/run/utmp -p wa -
# k session-w /var/log/wtmp -p wa -k logins-w /var/log/btmp -p wa -k logins
######

# 4.1.10 Ensure discretionary access control permission modification events are collected

###Recommendation###
# For 32 bit systems add the following lines to the /etc/audit/rules.d/audit.rules file:
# -a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F
# auid!=4294967295 -k perm_mod-a always,exit -F arch=b32 -S chown -S fchown -S
# fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod-a always,exit
# -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S
# fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod For 64 bit systems
# add the following lines to the /etc/audit/rules.d/audit.rules file: -a always,exit -F
# arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k
# perm_mod-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000
# -F auid!=4294967295 -k perm_mod-a always,exit -F arch=b64 -S chown -S fchown -S
# fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod-a always,exit
# -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!
# =4294967295 -k perm_mod-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S
# fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!
# =4294967295 -k perm_mod-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S
# fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!
# =4294967295 -k perm_mod
######

# 4.1.11 Ensure unsuccessful unauthorized file access attempts are collected

###Recommendation###
# For 32 bit systems add the following lines to the /etc/audit/rules.d/audit.rules file: -a
# always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-
# EACCES -F auid>=1000 -F auid!=4294967295 -k access-a always,exit -F arch=b32 -
# S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -
# F auid!=4294967295 -k access For 64 bit systems add the following lines to the /etc/
# audit/rules.d/audit.rules file: -a always,exit -F arch=b64 -S creat -S open -S openat -S
# truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k accessa always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-
# EACCES -F auid>=1000 -F auid!=4294967295 -k access-a always,exit -F arch=b64 -
# S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F
# auid!=4294967295 -k access-a always,exit -F arch=b32 -S creat -S open -S openat -S
# truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
######

# 4.1.13 Ensure successful file system mounts are collected

###Recommendation###
# For 32 bit systems add the following lines to the /etc/audit/rules.d/audit.rules file: -
# a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
# For 64 bit systems add the following lines to the /etc/audit/rules.d/audit.rules file: -a
# always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts-a
# always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
######

# 4.1.14 Ensure file deletion events by users are collected

###Recommendation###
# For 32 bit systems add the following lines to the /etc/audit/rules.d/audit.rules file: -a
# always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000
# -F auid!=4294967295 -k delete For 64 bit systems add the following lines to the /etc/
# audit/rules.d/audit.rules file: -a always,exit -F arch=b64 -S unlink -S unlinkat -S rename
# -S renameat -F auid>=1000 -F auid!=4294967295 -k delete-a always,exit -F arch=b32
# -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k
# delete
######

# 4.1.15 Ensure changes to system administration scope (sudoers) is collected

###Recommendation###
# Add the following line to the /etc/audit/rules.d/audit.rules file: -w /etc/sudoers -p wa -k
# scope-w /etc/sudoers.d/ -p wa -k scope
######

# 4.1.16 Ensure system administrator actions (sudolog) are collected

###Recommendation###
# Add the following lines to the /etc/audit/rules.d/audit.rules file: -w /var/log/sudo.log -p
# wa -k actions
######

# 4.1.17 Ensure kernel module loading and unloading is collected

###Recommendation###
# For 32 bit systems add the following lines to the /etc/audit/rules.d/audit.rules file: -w /
# sbin/insmod -p x -k modules-w /sbin/rmmod -p x -k modules-w /sbin/modprobe -p x
# -k modules-a always,exit -F arch=b32 -S init_module -S delete_module -k modules
# For 64 bit systems add the following lines to the /etc/audit/rules.d/audit.rules file: -w /
# sbin/insmod -p x -k modules-w /sbin/rmmod -p x -k modules-w /sbin/modprobe -p x -k
# modules-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
######

# 4.1.18 Ensure the audit configuration is immutable

###Recommendation###
# Add the following line to the end of the /etc/audit/rules.d/audit.rules file. -e 2
######

# 4.1.1.2 Ensure system is disabled when audit logs are full

###Recommendation###
# Set the following parameters in /etc/audit/auditd.conf: space_left_action =
# emailaction_mail_acct = rootadmin_space_left_action = halt
######

# 4.1.1.3 Ensure audit logs are not automatically deleted

###Recommendation###
# Set the following parameter in /etc/audit/auditd.conf: max_log_file_action = keep_logs
######

# 5.4.5 Ensure default user shell timeout is 900 seconds or less

###Recommendation###
# Edit the /etc/bashrc and /etc/profile files (and the appropriate files for any other
# shell supported on your system) and add or edit any umask parameters as follows:
# TMOUT=600
######



