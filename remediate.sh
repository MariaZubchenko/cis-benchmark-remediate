#!/usr/bin/env bash

# 1.1.2 Ensure /tmp is configured

###Description###
# Description The /tmp directory is a world-writable directory used for temporary storage
#  by all users and some applications. Rationale Making /tmp its own file system allows
# an administrator to set the noexec option on the mount, making /tmp useless for an attacker 
# to install executable code. It would also prevent an attacker from establishing a hardlink to a system 
# setuid program and wait for it to be updated. Once the program was updated, the hardlink 
# would be broken and the attacker would have his own copy of the program. If the program happened to 
# have a security vulnerability, the attacker could continue to exploit the known flaw. This can be 
# accomplished by either mounting tmpfs to /tmp, or creating a separate partition for /tmp.
###Recommendation###
# Configure /etc/fstab as appropriate. example:tmpfs /tmp tmpfs defaults,rw,nosuid,nodev
# ,noexec,relatime 0 0 or Run the following commands to enable systemd /tmp mounting:
# systemctl unmask tmp.mountsystemctl enable tmp.mount 
# Edit /etc/systemd/system/
# local-fs.target.wants/tmp.mount to configure the /tmp mount: [Mount]What=tmpfsWhe
# re=/tmpType=tmpfsOptions=mode=1777,strictatime,noexec,nodev,nosuid Impact:
# Since the /tmp directory is intended to be world-writable, there is a risk of resource
# exhaustion if it is not bound to a separate partition.Running out of /tmp space is a problem
# regardless of what kind of filesystem lies under it, but in a default installation
# a disk-based /tmp will essentially have the whole disk available, as it only creates a
# single / partition. On the other hand, a RAM-based /tmp as with tmpfs will almost
# certainly be much smaller, which can lead to applications filling up the filesystem much
# more easily./tmp utalizing tmpfs can be resized using the size={size} parameter on the
# Options line on the tmp.mount file
######

#systemctl unmask tmp.mountsystemctl enable tmp.mount 


# 1.1.17 Ensure noexec option set on /dev/shm partition


###Description###
# The noexec mount option specifies that the filesystem cannot contain executable binaries. 
# Rationale Setting this option on a file system prevents users from executing programs from 
# shared memory. This deters users from introducing potentially malicious software on the system.
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

# 1.3.2 Ensure filesystem integrity is regularly checked (fixed)

###Description###
# Periodic checking of the filesystem integrity is needed to detect changes to the filesystem.
# Rationale Periodic file checking allows the system administrator to determine on a regular basis 
# if critical files have been changed in an unauthorized fashion.
###Recommendation###
# Run the following command: # crontab -u root -e Add the following line to the crontab:
# 0 5 * * * /usr/sbin/aide --check
######

crontab -u root -e 
echo "0 5 * * * /usr/sbin/aide --check" >> /etc/crontab

# 1.4.1 Ensure permissions on bootloader config are configured (worked)

sudo chownroot: root /boot/grub2/grub.cfg
sudo chmod og-rwx /boot/grub2/grub.cfg

# 1.5.1 Ensure core dumps are restricted (worked)

echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
sysctl -w fs.suid_dumpable = 0

# 1.5.2 Ensure address space layout randomization (ASLR) is enabled (worked)

echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
sysctl -w kernel.randomize_va_space = 2

# 1.7.1.1 Ensure message of the day is configured properly

###Description### 
# The contents of the /etc/motd file are displayed to users after login and function as a message 
# of the day for authenticated users. Unix-based systems have typically displayed information about 
# the OS release and patch level upon logging in to the system. This information can be useful to 
# developers who are developing software for a particular OS platform. If mingetty(8) supports the 
# following options, they display operating system information: \m - machine architecture \r - operating 
# system release \s - operating system name \v - operating system version Rationale Warning messages 
# inform users who are attempting to login to the system of their legal status regarding
# the system and must include the name of the organization that owns the system and any monitoring
# policies that are in place. Displaying OS and patch level information in login banners also has the 
# side effect of providing detailed system information to attackers attempting to target specific 
# exploits of a system. Authorized users can easily get
###Recommendation###
# Edit the /etc/motd file with the appropriate contents according to your site policy,
# remove any instances of \m , \r , \s ,\v. , or references to the OS platform
######

# 1.7.1.2 Ensure local login warning banner is configured properly (fixed)

###Description###
# The contents of the /etc/issue file are displayed to users prior to login for local terminals. 
# Unix-based systems have typically displayed information about the OS release and patch level upon 
# logging in to the system. This information can be useful to developers who are developing 
# software for a particular OS platform. If mingetty(8) supports the following options, 
# they display operating system information: \m - machine architecture \r - operating system 
# release \s - operating system name \v - operating system version Rationale Warning messages 
# inform users who are attempting to login to the system of their legal status regarding the system 
# and must include the name of the organization that owns the system and any monitoring 
# policies that are in place. Displaying OS and patch level information in login banners also 
# has the side effect of providing detailed system information to attackers attempting to target 
# specific exploits of a system. Authorized users can easily get this information by running the 
# " uname -a " command once they have logged in.
###Recommendation###
# Edit the /etc/issue file with the appropriate contents according to your site policy,
# remove any instances of \m , \r , \s , \v or references to the OS platform: # echo
# "Authorized uses only. All activity may be monitored and reported." > /etc/issue
######

echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue

# 1.7.1.3 Ensure remote login warning banner is configured properly (fixed)

###Description### 
# The contents of the /etc/issue.net file are displayed to users prior to login for 
# remote connections from configured services. Unix-based systems have typically displayed 
# information about the OS release and patch level upon logging in to the system. This information 
# can be useful to developers who are developing software for a particular OS platform. If mingetty(8) 
# supports the following options, they display operating system information: \m - machine architecture 
# \r - operating system release \s - operating system name \v - operating system version Rationale 
# Warning messages inform users who are attempting to login to the system of their legal status regarding
# the system and must include the name of the organization that owns the system and any monitoring policies 
# that are in place. Displaying OS and patch level information in login banners also has the side effect of 
# providing detailed system information to attackers attempting to target specific exploits of a system. 
# Authorized users can easily get this information by running the " uname -a " command once they have logged in.
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


###Description###
# ICMP Redirects are used to send routing information to other hosts. As a host itself does not act as 
# a router (in a host only configuration), there is no need to send redirects. Rationale An attacker 
# could use a compromised host to send invalid ICMP redirects to other router devices in an attempt to 
# corrupt routing and have users access a system set up by the attacker as opposed to a valid system.
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

###Description###
# ICMP redirect messages are packets that convey routing information and tell your host 
# (acting as a router) to send packets via an alternate path. It is a way of allowing an outside 
# routing device to update your system routing tables. By setting net. ipv4.conf.all.accept_redirects 
# and net.ipv6.conf.all.accept_redirects to 0, the system will not accept any ICMP redirect messages, 
# and therefore, won't allow outsiders to update the system's routing tables. Rationale Attackers could 
# use bogus ICMP redirect messages to maliciously alter the system routing tables and get them to send 
# packets to incorrect networks and allow your system packets to be captured.
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

###Description### 
# Secure ICMP redirects are the same as ICMP redirects, except they come from gateways listed 
# on the default gateway list. It is assumed that these gateways are known to your system, and that 
# they are likely to be secure. Rationale It is still possible for even known gateways to be compromised. 
# Setting net.ipv4.conf.all.secure_redirec ts to 0 protects the system from routing table updates 
# by possibly compromised known gateways.
###Recommendation###
# Set the following parameters in /etc/sysctl.conf or a /etc/sysctl.d/* file: net.ipv4
# .conf.all.secure_redirects = 0net.ipv4.conf.default.secure_redirects = 0 Run the
# following commands to set the active kernel parameters: # sysctl -w net.ipv4.conf.all.secure_redirects=0# 
# sysctl -w net.ipv4.conf.default.secure_redirects=0# sysctl -w
# net.ipv4.route.flush=1
######

echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
sudo sysctl -w net.ipv4.conf.all.secure_redirects = 0
sudo sysctl -w net.ipv4.conf.default.secure_redirects = 0
sudo sysctl -w net.ipv4.route.flush = 1

# 3.2.4 Ensure suspicious packets are logged (fixed)

###Description###
# Description When enabled, this feature logs packets with un-routable source addresses to the 
# kernel log. Rationale Enabling this feature and logging these packets allows an administrator 
# to investigate the possibility that an attacker is sending spoofed packets to their system.
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

###Description###
# This setting disables the system's ability to accept IPv6 router advertisements. 
# Rationale It is recommended that systems not accept router advertisements as they could be tricked 
# into routing traffic to compromised machines. Setting hard routes within the system (usually a single 
# default route to a trusted router) protects the system from bad routes.
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

###Description###
# A default deny all policy on connections ensures that any unconfigured network usage 
# will be rejected. Rationale With a default accept policy the firewall will accept any 
# packet that is not configured to be denied. It is easier to white list acceptable usage 
# than to black list unacceptable usage.
###Recommendation###
# Run the following commands to implement a default DROP policy: # iptables -P
# INPUT DROP# iptables -P OUTPUT DROP# iptables -P FORWARD DROP
######

iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# 3.5.1.2 Ensure loopback traffic is configured (fixed)

###Description ###
# Configure the loopback interface to accept traffic. Configure all other interfaces to deny traffic 
# to the loopback network (127.0.0.0/8). Rationale Loopback traffic is generated between processes 
# on machine and is typically critical to operation of the system. The loopback interface is the 
# only place that loopback network (127.0.0.0/8) traffic should be seen, all other interfaces should 
# ignore traffic on this network as an anti-spoofing measure.
###Recommendation###
# Run the following commands to implement the loopback rules: # iptables -A INPUT
# -i lo -j ACCEPT# iptables -A OUTPUT -o lo -j ACCEPT# iptables -A INPUT -s
# 127.0.0.0/8 -j DROP
######

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -s 127.0.0.0/8 -j DROP

# 3.5.1.4 Ensure firewall rules exist for all open ports

###Description###
# Any ports that have been opened on non-loopback addresses need firewall rules to govern traffic. 
# Rationale Without a firewall rule configured for open ports default firewall policy will 
# drop all packets to these ports.
###Recommendation###
# For each port identified in the audit which does not have a firewall rule establish a
# proper rule for accepting inbound connections: 
# iptables -A INPUT -p <protocol> -- dport <port> -m state --state NEW -j ACCEPT
######

# 3.5.2.1 Ensure IPv6 default deny firewall policy (fixed)

###Description###
# A default deny all policy on connections ensures that any unconfigured network usage will be rejected. 
# Rationale With a default accept policy the firewall will accept any packet that is not configured to be denied. 
# It is easier to white list acceptable usage than to black list unacceptable usage.
###Recommendation###
# Run the following commands to implement a default DROP policy: # ip6tables -P
# INPUT DROP# ip6tables -P OUTPUT DROP# ip6tables -P FORWARD DROP
######

ip6tables -P INPUT DROP
ip6tables -P OUTPUT DROP
ip6tables -P FORWARD DROP

# 3.5.2.2 Ensure IPv6 loopback traffic is configured (fixed)

###Description###
# Configure the loopback interface to accept traffic. Configure all other interfaces to deny traffic 
# to the loopback network (::1). Rationale Loopback traffic is generated between processes on machine 
# and is typically critical to operation of the system. The loopback interface is the only place that 
# loopback network (::1) traffic should be seen, all other interfaces should ignore traffic on this 
# network as an anti- spoofing measure.
###Recommendation###
# Run the following commands to implement the loopback rules: # ip6tables -A INPUT -
# i lo -j ACCEPT# ip6tables -A OUTPUT -o lo -j ACCEPT# ip6tables -A INPUT -s ::1 -j
# DROP
######

ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT
ip6tables -A INPUT -s ::1 -j DROP

# 4.2.4 Ensure permissions on all logfiles are configured (fixed)

###Description###
# Log files stored in /var/log/ contain logged information from many services on the system, 
# or on log hosts others as well. Rationale It is important to ensure that log files have 
# the correct permissions to ensure that sensitive data is archived and protected.
###Recommendation###
# Run the following command to set permissions on all existing log files: # find -L /var/
# log -type f -exec chmod g-wx,o-rwx {} +
######

find -L /var/log -type f -exe chmod g-wx,o-rwx {} +

# 4.2.1.3 Ensure rsyslog default file permissions configured (worked)

echo "\$FileCreateMode 0640" >> /etc/rsyslog.conf

# 4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host

###Description###
# The rsyslog utility supports the ability to send logs it gathers to a remote log host running syslogd(8) 
# or to receive messages from remote hosts, reducing administrative overhead. Rationale Storing log data 
# on a remote host protects log integrity from local attacks. If an attacker gains root access on the 
# local system, they could tamper with or remove log data that is stored on the local system
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

# 5.2.4 Ensure SSH Protocol is set to 2 (worked)

cat /etc/ssh/sshd_config | grep -v Protocol > /etc/ssh/sshd_config.new
echo "Protocol 2" >> /etc/ssh/sshd_config.new

cp /etc/ssh/sshd_config.new /etc/ssh/sshd_config
rm /etc/ssh/sshd_config.new

# 5.2.5 Ensure SSH LogLevel is appropriate (worked)

cat /etc/ssh/sshd_config | grep -v LogLevel > /etc/ssh/sshd_config.new
echo "LogLevel VERBOSE" >> /etc/ssh/sshd_config.new

cp /etc/ssh/sshd_config.new /etc/ssh/sshd_config
rm /etc/ssh/sshd_config.new

# 5.2.6 Ensure SSH X11 forwarding is disabled

###Recommendation###
# Edit the /etc/ssh/sshd_config file to set the parameter as follows: X11Forwarding no
######

cat /etc/ssh/sshd_config | grep -v X11Forwarding > /etc/ssh/sshd_config.new
echo "X11Forwarding no" >> /etc/ssh/sshd_config.new

cp /etc/ssh/sshd_config.new /etc/ssh/sshd_config
rm /etc/ssh/sshd_config.new

# 5.2.7 Ensure SSH MaxAuthTries is set to 4 or less (worked)

cat /etc/ssh/sshd_config | grep -v MaxAuthTries > /etc/ssh/sshd_config.new
echo "MaxAuthTries 4" >> /etc/ssh/sshd_config.new

cp /etc/ssh/sshd_config.new /etc/ssh/sshd_config
rm /etc/ssh/sshd_config.new

# 5.2.8 Ensure SSH IgnoreRhosts is enabled (worked)

cat /etc/ssh/sshd_config | grep -v IgnoreRhosts > /etc/ssh/sshd_config.new
echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config.new

cp /etc/ssh/sshd_config.new /etc/ssh/sshd_config
rm /etc/ssh/sshd_config.new

# 5.2.9 Ensure SSH HostbasedAuthentication is disabled (worked)

cat /etc/ssh/sshd_config | grep -v HostbasedAuthentication > /etc/ssh/sshd_config.new
echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config.new

cp /etc/ssh/sshd_config.new /etc/ssh/sshd_config
rm /etc/ssh/sshd_config.new

# 5.2.10 Ensure SSH root login is disabled (worked)

cat /etc/ssh/sshd_config | grep -v PermitRootLogin > /etc/ssh/sshd_config.new
echo "PermitRootLogin no" >> /etc/ssh/sshd_config.new

cp /etc/ssh/sshd_config.new /etc/ssh/sshd_config
rm /etc/ssh/sshd_config.new

# 5.2.11 Ensure SSH PermitEmptyPasswords is disabled (worked)

cat /etc/ssh/sshd_config | grep -v PermitEmptyPasswords > /etc/ssh/sshd_config.new
echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config.new

cp /etc/ssh/sshd_config.new /etc/ssh/sshd_config
rm /etc/ssh/sshd_config.new

# 5.2.12 Ensure SSH PermitUserEnvironment is disabled (worked)

cat /etc/ssh/sshd_config | grep -v PermitUserEnvironment > /etc/ssh/sshd_config.new
echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config.new

cp /etc/ssh/sshd_config.new /etc/ssh/sshd_config
rm /etc/ssh/sshd_config.new

# 5.2.13 Ensure only strong ciphers are used

###Description###
# Description This variable limits the ciphers that SSH can use during communication. 
# Rationale Weak ciphers that are used for authentication to the cryptographic module cannot be relied upon to provide 
# confidentiality or integrity, and system data may
# be compromised The DES, Triple DES, and Blowfish ciphers, as used in SSH, have
# a birthday bound of approximately four billion blocks, which makes it easier for
# remote attackers to obtain cleartext data via a birthday attack against a long-duration encrypted session, aka a 
# "Sweet32" attack The RC4 algorithm, as used in the TLS protocol and SSL protocol, does not properly combine state data 
# with key data during the initialization phase, which makes it easier for remote attackers to conduct plaintext- recovery 
# attacks against the initial bytes of a stream by sniffing network traffic that occasionally relies on keys affected by 
# the Invariance Weakness, and then using a brute- force approach involving LSB values, aka the "Bar Mitzvah" issue 
# The passwords used during an SSH session encrypted with RC4 can be recovered by an attacker who is able to capture and replay 
# the session Error handling in the SSH protocol; Client and Server, when using a block cipher algorithm in Cipher 
# Block Chaining (CBC) mode, makes it easier for remote attackers to recover certain plaintext data from an arbitrary block
# of ciphertext in an SSH session via unknown vectors The mm_newkeys_from_blob function in monitor_wrap.c, when an 
# AES-GCM cipher is used, does not properly initialize memory for a MAC context data structure, which allows remote 
# authenticated users to bypass intended ForceCommand and login-shell restrictions via packet data that provides a 
# crafted callback address
###Recommendation###
# Edit the /etc/ssh/sshd_config file add/modify the Ciphers line to contain a comma
# separated list of the site approved ciphers Example: Ciphers chacha20-poly1305@op
# enssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ct
# r,aes128-ctr
######

# 5.2.14 Ensure only strong MAC algorithms are used

###Description### 
# This variable limits the types of MAC algorithms that SSH can use during communication. 
# Rationale MD5 and 96-bit MAC algorithms are considered weak and have been shown to increase exploitability 
# in SSH downgrade attacks. Weak algorithms continue to have a great deal of attention as a weak spot that can be 
# exploited with expanded computing power. An attacker that breaks the algorithm could take advantage 
# of a MiTM position to decrypt the SSH tunnel and capture credentials and information
###Recommendation###
# Edit the /etc/ssh/sshd_config file and add/modify the MACs line to contain a comma
# separated list of the site approved MACs Example: MACs hmac-sha2-512-etm@openss
# h.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
######

# 5.2.15 Ensure that strong Key Exchange algorithms are used

###Description### 
# Key exchange is any method in cryptography by which cryptographic keys are exchanged between two 
# parties, allowing use of a cryptographic algorithm. If the sender and receiver wish to exchange 
# encrypted messages, each must be equipped to encrypt messages to be sent and decrypt messages 
# received Rationale Key exchange methods that are considered weak should be removed. 
# A key exchange method may be weak because too few bits are used, or the hashing algorithm is considered too weak. 
# Using weak algorithms could expose connections to man-in-the-middle attacks
###Recommendation###
# Edit the /etc/ssh/sshd_config file add/modify the KexAlgorithms line to contain
# a comma separated list of the site approved key exchange algorithms Example:
# KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-gr
# oup14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sh
# a2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchangesha256
######

# 5.2.16 Ensure SSH Idle Timeout Interval is configured (fixed)

###Description###
# The two options ClientAliveInterval and ClientAliveCountMax control
# the timeout of ssh sessions. When the ClientAliveInterval variable is set, ssh sessions that have no 
# activity for the specified length of time are terminated. When the ClientAliveCountMax variable is set, 
# sshd will send client alive messages at every ClientAliveInterval interval. When the number of consecutive 
# client alive messages are sent with no response from the client, the ssh session is terminated. For example, 
# if the ClientAliveInterval is set to 15 seconds and the ClientAliveCountMax is set to 3, the client ssh session 
# will be terminated after 45 seconds of idle time. Rationale Having no timeout value associated with a connection could 
# allow an unauthorized user access to another user's ssh session (e.g. user walks away from their computer and doesn't 
# lock the screen). Setting a timeout value at least reduces the risk of this happening.. While the recommended setting 
# is 300 seconds (5 minutes), set this timeout value based on site policy. The recommended setting for ClientAliveCountMax is 0. 
# In this case, the client session will be terminated after 5 minutes of idle time and no keepalive messages will be sent.
###Recommendation###
# Edit the /etc/ssh/sshd_config file to set the parameters according to site policy:
# ClientAliveInterval 300 ClientAliveCountMax 0
######

cat /etc/ssh/sshd_config | grep -v ClientAliveInterval  > /etc/ssh/sshd_config.new
echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config.new

cp /etc/ssh/sshd_config.new /etc/ssh/sshd_config
rm /etc/ssh/sshd_config.new

cat /etc/ssh/sshd_config | grep -v ClientAliveCountMax  > /etc/ssh/sshd_config.new
echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config.new

cp /etc/ssh/sshd_config.new /etc/ssh/sshd_config
rm /etc/ssh/sshd_config.new

# 5.2.17 Ensure SSH LoginGraceTime is set to one minute or less (worked)

cat /etc/ssh/sshd_config | grep -v LoginGraceTime  > /etc/ssh/sshd_config.new
echo "LoginGraceTime 60">>/etc/ssh/sshd_config.new

cp /etc/ssh/sshd_config.new /etc/ssh/sshd_config
rm /etc/ssh/sshd_config.new

# 5.2.18 Ensure SSH access is limited 

###Description###
# There are several options available to limit which users and group can access the system via SSH.
# It is recommended that at least one of the following options be leveraged: AllowUsers The AllowUsers variable 
# gives the system administrator the option of allowing specific users to ssh into the system. The list consists 
# of space separated user names. Numeric user IDs are not recognized with this variable. If a system administrator 
# wants to restrict user access further by only allowing the allowed users to log in from a particular host, 
# the entry can be specified in the form of user@host. AllowGroups The AllowGroups variable gives the system administrator
# the option of allowing specific groups of users to ssh into the system. The list consists of space separated group names. 
# Numeric group IDs are not recognized with this variable. DenyUsers The DenyUsers variable gives the system administrator 
# the option of denying specific users to ssh into the system. The list consists of space separated user names. 
# Numeric user IDs are not recognized with this variable. If a system administrator wants to restrict user access further 
# by specifically denying a user's access from a particular host, the entry can be specified in the form of user@host. 
# DenyGroups The DenyGroups variable gives the system administrator the option of denying specific groups of users to ssh 
# into the system. The list consists of space separated group names. Numeric group IDs are not recognized with this variable. 
# Rationale Restricting which users can remotely access the system via SSH will help ensure that 
# only authorized users access the system.
###Recommendation###
# Edit the /etc/ssh/sshd_config file to set one or more of the parameter as follows:
# AllowUsers <userlist>AllowGroups <grouplist>DenyUsers <userlist>DenyGroups
# <grouplist>
######

# 5.2.19 Ensure SSH warning banner is configured (worked)

cat /etc/ssh/sshd_config | grep -v Banner > /etc/ssh/sshd_config.new
echo "Banner /etc/issue.net">>/etc/ssh/sshd_config.new

cp /etc/ssh/sshd_config.new /etc/ssh/sshd_config
rm /etc/ssh/sshd_config.new

# 5.3.1 Ensure password creation requirements are configured

###Description###
# The pam_pwquality.so module checks the strength of passwords. It performs checks such as making sure a password 
# is not a dictionary word, it is a certain length, contains a mix of characters (e.g. alphabet, numeric, other) and more. 
# The following are definitions of the pam_pwquality .so options. try_first_pass - retrieve
# the password from a previous stacked PAM module. If not available, then prompt the user for a password.retry=3 - 
# Allow 3 tries before sending back a failure. The following options are set in the /etc/security/pwquality.conf file: 
# minlen = 14 - password must be 14 characters or moredcredit = -1 - provide at least one digitucredit = -1 - provide at 
# least one uppercase characterocredit = -1 - provide at least one special characterlcredit = -1 - provide at least one 
# lowercase character The settings shown above are one possible policy. Alter these values to conform to your own organization's 
# password policies. Rationale Strong passwords protect systems from being hacked through brute force methods.
###Recommendation###
# Edit the /etc/pam.d/password-auth and /etc/pam.d/system-auth files to include the
# appropriate options for pam_pwquality.so and to conform to site policy: password
# requisite pam_pwquality.so try_first_pass retry=3 Edit /etc/security/pwquality.conf to
# add or update the following settings to conform to site policy: minlen = 14dcredit =
# -1ucredit = -1ocredit = -1lcredit = -1
######

# 5.3.2 Ensure lockout for failed password attempts is configured (fixed)

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

# 5.3.3 Ensure password reuse is limited (fixed)

###Recommendation###
# Edit the /etc/pam.d/password-auth and /etc/pam.d/system-auth files to include the
# remember option and conform to site policy as shown: password sufficient pam_unix.so
# remember=5 or password required pam_pwhistory.so remember=5
######

cat /etc/pam.d/password-auth | grep -v pam_unix.so > /etc/pam.d/password-auth.new
echo "pam_unix.so remember=5">>/etc/pam.d/password-auth.new

cp /etc/pam.d/password-auth.new /etc/pam.d/password-auth
rm /etc/pam.d/password-auth.new

cat /etc/pam.d/system-auth | grep -v pam_pwhistory.so > /etc/pam.d/system-auth.new
echo "pam_pwhistory.so remember=5">>/etc/pam.d/password-auth.new

cp /etc/pam.d/system-auth.new /etc/pam.d/system-auth
rm /etc/pam.d/system-auth.new

# 5.4.4 Ensure default user umask is 027 or more restrictive  (fixed)

###Recommendation###
# Edit the /etc/bashrc, /etc/profile and /etc/profile.d/*.sh files (and the appropriate files
# for any other shell supported on your system) and add or edit any umask parameters as
# follows: umask 027
######

cat /etc/bashrc | grep -v umask > /etc/bashrc.new
echo "umask 027">>/etc/bashrc.new

cp /etc/bashrc.new /etc/bashrc
rm /etc/bashrc.new

# 5.4.1.1 Ensure password expiration is 365 days or less (worked)

###Recommendation###
# Set the PASS_MAX_DAYS parameter to conform to site policy in /etc/login.defs :
# PASS_MAX_DAYS 90 Modify user parameters for all users with a password set to
# match: # chage --maxdays 90 <user>
######

cat /etc/login.defs | grep -v PASS_MAX_DAYS > /etc/login.defs.new
echo "PASS_MAX_DAYS 90">>/etc/login.defs.new

cp /etc/login.defs.new /etc/login.defs
rm /etc/login.defs.new

chage --maxdays 90 <user>

# 5.4.1.2 Ensure minimum days between password changes is 7 or more (fixed)

###Recommendation###
# Set the PASS_MIN_DAYS parameter to 7 in /etc/login.defs : PASS_MIN_DAYS 7
# Modify user parameters for all users with a password set to match: # chage --mindays 7
# <user>
######

cat /etc/login.defs | grep -v PASS_MIN_DAYS > /etc/login.defs.new
echo "PASS_MIN_DAYS 7" >> /etc/login.defs.new

cp /etc/login.defs.new /etc/login.defs
rm /etc/login.defs.new

chage --mindays 7 <user>

# 5.4.1.4 Ensure inactive password lock is 30 days or less (fixed)

###Recommendation###
# Run the following command to set the default password inactivity period to 30 days: #
# useradd -D -f 30 Modify user parameters for all users with a password set to match: #
# chage --inactive 30 <user>
######

useradd -D -f 30 
chage --inactive 30 <user>

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

# 1.6.1.2 Ensure the SELinux state is enforcing (fixed)
 
###Recommendation###
# Edit the /etc/selinux/config file to set the SELINUX parameter: SELINUX=enforcing
######

cat /etc/selinux/config | grep -v SELINUX > /etc/selinux/config.new
echo "SELINUX = enforcing">>/etc/selinux/config.new

cp /etc/selinux/config.new /etc/selinux/config
rm /etc/selinux/config.new

# 1.6.1.3 Ensure SELinux policy is configured (fixed)

###Recommendation###
# Edit the /etc/selinux/config file to set the SELINUXTYPE parameter:
# SELINUXTYPE=targeted
######

cat /etc/selinux/config | grep -v SELINUXTYPE > /etc/selinux/config.new
echo "SELINUXTYPE = targeted">>/etc/selinux/config.new

cp /etc/selinux/config.new /etc/selinux/config
rm /etc/selinux/config.new

# 1.6.1.6 Ensure no unconfined daemons exist (fixed)

###Recommendation###
# Investigate any unconfined daemons found during the audit action. They may need to
# have an existing security context assigned to them or a policy built for them.
######

# 3.6 Disable IPv6 (fixed)

###Recommendation###
# Edit /etc/default/grub and remove add ipv6.disable=1 to the
# GRUB_CMDLINE_LINUX parameters: GRUB_CMDLINE_LINUX="ipv6.disable=1"
# Run the following command to update the grub2 configuration: # grub2-mkconfig -o /
# boot/grub2/grub.cfg
######

GRUB_CMDLINE_LINUX="ipv6.disable=1"
grub2-mkconfig -o /boot/grub2/grub.cfg

# 4.1.4 Ensure events that modify date and time information are collected (worked)

echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/audit.rules
service auditd restart

# 4.1.5 Ensure events that modify user/group information are collected (worked)

echo "-w /etc/group -p wa -k identity" >>/etc/audit/rules.d/audit.rules
echo "-w /etc/passwd -p wa -k identity" >>/etc/audit/rules.d/audit.rules
echo "-w /etc/gshadow -p wa -k identity" >>/etc/audit/rules.d/audit.rules
echo "-w /etc/shadow -p wa -k identity" >>/etc/audit/rules.d/audit.rules
echo "-w /etc/security/opasswd -p wa -k identity" >>/etc/audit/rules.d/audit.rules
service auditd restart

# 4.1.6 Ensure events that modify the system's network environment are collected (worked)

echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/sysconfig/network -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/sysconfig/network-scripts/ -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules
service auditd restart

# 4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected (worked)

echo "-w /etc/selinux/ -p wa -k MAC-policy" >> /etc/audit/rules.d/audit.rules
echo "-w /usr/share/selinux/ -p wa -k MAC-policy" >> /etc/audit/rules.d/audit.rules
service auditd restart

# 4.1.8 Ensure login and logout events are collected (fixed)

###Recommendation###
# Add the following lines to the /etc/audit/rules.d/audit.rules file: 
# -w /var/log/lastlog -p wa -k logins-w /var/run/faillock/ -p wa -k logins
######

echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/audit.rules
echo "-w /var/run/faillog -p wa -k logins" >> /etc/audit/rules.d/audit.rules
service auditd restart

# 4.1.9 Ensure session initiation information is collected (worked)

echo "-w /var/run/utmp -p wa -k session" >> /etc/audit/rules.d/audit.rules
echo "-w /var/log/wtmp -p wa -k logins" >> /etc/audit/rules.d/audit.rules
echo "-w /var/log/btmp -p wa -k logins" >> /etc/audit/rules.d/audit.rules
service auditd restart

# 4.1.10 Ensure discretionary access control permission modification events are collected (fixed)

###Recommendation###
# For 32 bit systems add the following lines to the /etc/audit/rules.d/audit.rules file:
# -a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k 
# perm_mod-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!
# =4294967295 -k perm_mod-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S 
# removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod For 64 
# bit systems add the following lines to the /etc/audit/rules.d/audit.rules file: -a always,exit -F 
# arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod-a always,exit 
# -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod-a always,
# exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k 
# perm_mod-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F 
# auid! =4294967295 -k perm_mod-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr 
# -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid! =4294967295 -k perm_mod-a 
# always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S 
# fremovexattr -F auid>=1000 -F auid! =4294967295 -k perm_mod
######

echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules

service auditd restart

# 4.1.11 Ensure unsuccessful unauthorized file access attempts are collected (fixed)

###Recommendation###
# For 32 bit systems add the following lines to the /etc/audit/rules.d/audit.rules file: 
# -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=- EACCES 
# -F auid>=1000 -F auid!=4294967295 -k access-a always,exit -F arch=b32 -
# S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -
# F auid!=4294967295 -k access For 64 bit systems add the following lines to the /etc/ 
# audit/rules.d/audit.rules file: -a always,exit -F arch=b64 -S creat -S open -S openat -S 
# truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access- a always,exit 
# -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=- EACCES -F auid>=1000 
# -F auid!=4294967295 -k access-a always,exit -F arch=b64 -
# S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 
# -k access-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F 
# exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
######

echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access ">> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
service auditd restart

# 4.1.13 Ensure successful file system mounts are collected (fixed)

###Recommendation###
# For 32 bit systems add the following lines to the /etc/audit/rules.d/audit.rules file: -
# a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts For 64 bit 
# systems add the following lines to the /etc/audit/rules.d/audit.rules file: -a always,exit 
# -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts-a always,exit -F arch=b32 
# -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
######

echo "-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/audit.rules
service auditd restart

# 4.1.14 Ensure file deletion events by users are collected (fixed)

###Recommendation###
# For 32 bit systems add the following lines to the /etc/audit/rules.d/audit.rules file: 
# -a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000
# -F auid!=4294967295 -k delete For 64 bit systems add the following lines to the /etc/ 
# audit/rules.d/audit.rules file: -a always,exit -F arch=b64 -S unlink -S unlinkat -S rename 
# -S renameat -F auid>=1000 -F auid!=4294967295 -k delete-a always,exit -F arch=b32 -S unlink 
# -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
######

echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
service auditd restart

# 4.1.15 Ensure changes to system administration scope (sudoers) is collected (worked)

echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/sudoers.d/ -p wa -k scope" >> /etc/audit/rules.d/audit.rules
service auditd restart

# 4.1.16 Ensure system administrator actions (sudolog) are collected (worked)

echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/rules.d/audit.rules
service auditd restart

# 4.1.17 Ensure kernel module loading and unloading is collected (worked)

echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/rules.d/audit.rules
echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/rules.d/audit.rules
echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/audit.rules
service auditd restart

# 4.1.18 Ensure the audit configuration is immutable (worked)

echo "-e 2" >> /etc/audit/rules.d/audit.rules
service auditd restart

# 4.1.1.2 Ensure system is disabled when audit logs are full (worked)

cat /etc/audit/auditd.conf | grep -v "space_left_action" | grep -v "action_mail_acct" | grep -v "admin_space_left_action" > /etc/audit/auditd.conf.new

mv /etc/audit/auditd.conf.new /etc/audit/auditd.conf
echo "space_left_action = email" >> /etc/audit/auditd.conf
echo "action_mail_acct = root" >> /etc/audit/auditd.conf
echo "admin_space_left_action = halt" >> /etc/audit/auditd.conf

# 4.1.1.3 Ensure audit logs are not automatically deleted (worked)

cat /etc/audit/auditd.conf | grep -v "max_log_file_action" > /etc/audit/auditd.conf.new

mv /etc/audit/auditd.conf.new /etc/audit/auditd.conf
echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf

# 5.4.5 Ensure default user shell timeout is 900 seconds or less (fixed)

###Recommendation###
# Edit the /etc/bashrc and /etc/profile files (and the appropriate files 
# for any other shell supported on your system) and add or edit any umask parameters 
# as follows: TMOUT=600
######

echo "TMOUT=600" >>/etc/bashrc
echo "TMOUT=600" >>/etc/profile


