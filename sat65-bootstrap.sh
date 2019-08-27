cat >sat65-ks.cfg <<EOD
# version=DEVEL
# System authorization information
auth --enableshadow --passalgo=sha512
# Use CDROM installation media
cdrom
# Use text install
text
# Firewall configuration
firewall --enabled
# Keyboard layouts
keyboard --vckeymap=de --xlayouts='de'
# System language
lang en_US.UTF-8

# Network information
network --bootproto=static --device=eth0 --ip=10.11.12.13 --netmask=255.255.255.255 --gateway=10.11.12.1 --nameserver=10.11.12.2 --noipv6 --activate --interfacename=wan
network --bootproto=static --device=eth1 --ip=172.24.100.3 --netmask=255.255.255.0 --nodefroute --noipv6 --onboot=yes --interfacename=sat
network --bootproto=dhcp --device=eth2 --nodefroute --noipv6 --onboot=yes --interfacename=lan
network  --hostname=or-sat65.example.com

# Root password
# python -c 'import crypt; print(crypt.crypt("My Password", "$6$_My_PieceOfGrain"))'
rootpw --iscrypted $6$_My_PieceOfGrain$t.LcYtKxv3GrqNyiUOoE8d.SovHvq75z58Q23DRsZJ9qneueKzHSiI05yh3xo.vRlQolA9B27/GDiwABgftug1
# SELinux configuration
selinux --enforcing
# System services
services --enabled="chronyd"
# Do not configure the X Window System
skipx
# System timezone
timezone Europe/Berlin --isUtc --ntpservers=0.rhel.pool.ntp.org,1.rhel.pool.ntp.org,2.rhel.pool.ntp.org

# Disk Partitioning
# Ignore all Disks except vda
ignoredisk --only-use=vda
# Partition clearing information
clearpart --none --initlabel
# Clear the Master Boot Record
zerombr
# System bootloader configuration
bootloader --append=" crashkernel=auto" --location=mbr --boot-drive=vda
# Partition clearing information
clearpart --all --initlabel --drives=vda
# Partitioning
part /boot --fstype="xfs" --ondisk=vda --size=1024
part pv.01 --fstype="lvmpv" --ondisk=vda --size=20480
part pv.02 --fstype="lvmpv" --ondisk=vda --size=102400 --grow
volgroup vg_sys pv.01
volgroup vg_satellite pv.02
logvol /  --fstype="xfs" --percent=80 --name=root --vgname=vg_sys
logvol /var  --fstype="xfs" --percent=80 --name=var --vgname=vg_satellite

# Preinstallation Scripts
%pre --logfile /root/ks-pre.log
%end

# Postinstallation Scripts
%post --logfile /root/ks-post.log
set -x
subscription-manager register --org=6502464 --activationkey=sat65-531e5b45-d7a1-4846-84a2-1f71952486df
subscription-manager repos --disable="*"
subscription-manager repos \
    --enable=rhel-7-server-rpms \
    --enable=rhel-server-rhscl-7-rpms \
    --enable=rhel-7-server-satellite-6.5-rpms \
    --enable=rhel-7-server-satellite-maintenance-6-rpms \
    --enable=rhel-7-server-optional-rpms \
    --enable=rhel-7-server-ansible-2.6-rpms
subscription-manager release --unset
yum -y install vim wget git net-tools bind-utils bridge-utils bash-completion kexec-tools sos psacct
yum -y update
mkdir -m0700 /root/.ssh/
cat <<EOF >/root/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAyQ+Ro5u/qzoh2/aPW496ndiM2TtkcTC7tMECyYl2OVOnkVU43ayPP+KfuRmTYxCdd0oLuQebjb04+0cIit8wnDhSprILfkpCfwudYfKymXrKEkMVCI15HFv9JEgP4FZ0hjl2NmokdMvs7ADPTxvzK3VN7KCBaS3JxvJSl4AQhZ1w7zu4NFKvCVcv+AqpS5Q== admin@example.com
EOF
chmod 0600 /root/.ssh/authorized_keys
restorecon -R /root/.ssh/

yum -y install rng-tools
systemctl enable --now rngd

firewall-cmd --permanent --add-service='RH-Satellite-6' --add-service='dns' --add-service='dhcp' --add-service='tftp' --add-service='http' --add-service='https'
%end

# Packages
%packages
@^minimal
@core
chrony
kexec-tools
%end
EOD

echo virt-install \
--name sat65 \
--description "Satellite 6.5 Instance" \
--os-type=Linux \
--os-variant=rhel7 \
--ram=16384 \
--vcpus=4 \
--disk path=/var/lib/libvirt/images/Satellite-6.5.qcow2,bus=virtio,size=300 \
--network bridge=br0,mac=52:54:00:b0:12:7c,model=virtio \
--network network=satnet \
--network network=default \
--initrd-inject ./sat65-ks.cfg \
--location /srv/Images/ISO/rhel-server-7.6-x86_64-dvd.iso \
--extra-args="ks=file:/sat65-ks.cfg"
# --graphics none \
