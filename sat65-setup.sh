#!/bin/bash
# vim: ft=sh:sw=2:et
cat <<EOF


Satellite-6.5 Demo/Test/PoC Setup Script
========================================

This script is intended to automate a comprehensive Satellite-6.5 server installation for demo, test or PoC purposes.
 
The script helps to perform the initial steps to finish the prerequisites, it installs and configures the software,
it fills the Satellite with various types of content, it creates activation keys and content views,
it customizes some smart class parameter overrides and finally installs a couple of new hosts.

With this setup, the script is well suited as a Satellite-6 test.
In an PoC scenario, it allows to emphasize on the actual use cases and requirements from the very first moment.

This demo setup shows some of the features and benefits of Satellite-6.5:
- Satellite is configured to authenticate with an existing IPA server (IPA is prerequisite, out of scope for this demo).
- Satellite is configured to use the existing IPA CA (again, IPA is prerequisite, out of scope for this demo).
- Satellite is configured to register hosts automatically into the IPA REALM.
- The simple baseline host is hardened so that root login is disabled.
  Given the appropriate IPA setup (prerequisite, out of scope for this demo) users can log into the host and sudo if IPA authorization permits.
- A GIT server is created with a post-receive hook that automatically syncs new puppet classes from GIT to Satellite into a dedicated puppet only content view.
  This GIT setup demonstrates how to create a rapid puppet development workflow with Satellite-6.
- A dockerhost is created with appropriate partitioning and network configuration to demonstrate the value of a stable baseline (packages and configuration) to build and run docker containers.
- A comprehensive buildhost is created to demonstrate the value of the stable baseline (packages and configuration) for development and build environments.
  The buildhost puppet profile class demonstrates the adoption of a role-profile model with Satellite-6.
  The automation of the buildhost setup is taken so far that a complete jenkins build pipeline is set up and running to show a JBoss TicketMonster development workflow.

This demo is intended to run in a VM on a libvirt/KVM host. The Satellite VM requires least 8GB of RAM and 4 cores. 12GB RAM and 6 cores are recommended.
I recommend using a dedicated server from a hosting provider which is available for less than €50 per month.
The network setup must allow Satellite to run DHCP and TFTP on a dedicated interface.
With all features enabled, the demo setup will consume around 180GB of disk space for package content in /var/lib/pulp.
Using the immediate sync policy, the content sync alone takes more than 24 hours even with a high bandwidth internet connection.
In preparation for a Satellite-6 PoC this script can be used to perform this time consuming procedure ahead of the actual PoC engagement.

There is at least one manual intervention required directly after satellite-install has finished and a second halt is included right before the demo hosts are created at the end.
So be prepared to be around for at least an hour or so after starting the script to proceed after the first manual intervention.
After that, you may go home and proceed the next day...

You may want to run this script in a screen session.


The header section of this script declares a lot of variables that are used later on to customize the script.
Read through the values carefully and change where appropriate.
When finished, delete or comment the following exit command.

EOF
# exit 0

set -x
set -e
longname=$(hostname | tr '.' '_')

# This is a Sat6 engineering manifest. Replace with your custom manifest.
export MANIFEST=Satellite_65_Generated_July_16_2019.zip
# scp Satellite_65_Generated_July_16_2019.zip root@satellite65.example.com:/tmp
# scp sat65-setup.sh root@satellite65.example.com:

# The script is built such that the preparation steps can be skipped if later stages need to be extended or repeated.
# The higher the STAGE Level is, the more preparation steps are skipped.
# STAGE Level:
# 1 = preqequisite preparation
# 2 = Satellite 6 installation
# 3 = content sync
# 4 = environment setup
# 5 = content views
# 6 = host groups, activation keys, sc_params
# 7 = hosts
export STAGE=2

# This demo setup is built with IPA integration as one important feature to show.
# While it is possible to use IPA and leave Satellite with the self signed internal CA cert,
# it is recommended to demonstrate/test this feature as well.
# The IPA_EXT_CERT switch is mainly offered for debugging purposes.
export IPA_EXT_CERT=true


# The following four switches allow to adjust the size of the content stack synced into Satellite.
# Depending on the use cases you want to show, RHEL6_CONTENT may well be excluded. This saves a lot of space and time.
#
# The OPT_CONTENT includes additional stuff like RHEL supplementary repos as well as JBoss EAP, Satellite and Capsule repos.
# It is recommended to include this options content because it is required in all of the more advanced use cases.
#
# The extended content set may be omitted.
# It servers mainly as template for even more advanced use cases to be implemented in an PoC.
#
# The custom content set finally is exactly that. It is intended to include your own or the customers internal stuff.
export RHEL6_CONTENT=false
export OPT_CONTENT=true
export EXT_CONTENT=false
export CUST_CONTENT=true
export CUSTOM_REPO_HOST=sol.lunetix.org
export CUSTOM_REPO_IP=85.25.159.110

# The following block of parameters needs to reflect your environment.
# Most of the parameters are used with the satellite-installer
# The purpose should be pretty much self explanatory. In doubt, look at 'satellite-installer --help'
export SAT_CNET=172.24.100
export DNS_REV=100.24.172.in-addr.arpa
export SUBNET=${SAT_CNET}.0
export SUBNET_MASK=255.255.255.0
export DNS=${SAT_CNET}.2
export SAT_IP=${SAT_CNET}.3
export ORG="LunetIX"
export LOC="Orion"
export ADMIN=admin
export ADMIN_PASSWORD=$(pwmake 64)
export IPA_SERVER=sol.lunetix.org
export DOMAIN=lunetix.org
export REALM=LUNETIX.ORG
export REALM_PROXY_USER=realm-proxy
export C=DE
export ST=Berlin
export L=Berlin
export OU=IT-Ops
export DHCP_RANGE="${SAT_CNET}.20 ${SAT_CNET}.50"
export DHCP_GW=${SAT_CNET}.1
export DHCP_DNS=${SAT_CNET}.2
export SAT_INTERFACE=eth1
export SUBNET_NAME='kvmnet'
export SUBNET_IPAM_BEGIN=${SAT_CNET}.100
export SUBNET_IPAM_END=${SAT_CNET}.150
# The host prefix is used to distinguish the demo hosts created at the end of this script.
export HOST_PREFIX='kvm-'
# This is the default password used in hostgroup declarations.
export HOST_PASSWORD='Geheim!!'


export PREPARE_CAPSULE=true
export CAPSULE_NAME=pu-cap.lunetix.org
export CAPSULE_LOC="Puck"
longcapsulename=$(echo $CAPSULE_NAME | tr '.' '_')


# This demo is intended to run on a simple libvirt/KVM hypervisor.
# A dedicated server hosted by an internet service provider may be a cost effective choice for this ressource.
export CONFIGURE_LIBVIRT_RESOURCE=true
export COMPUTE_RES_FQDN="orion1318.server4you.de"
export COMPUTE_RES_NAME="KVM"

# This script alternatively allows to use a RHV virtualization backend using the following parameters
export CONFIGURE_RHEV_RESOURCE=false
# export COMPUTE_RES_FQDN="rhv.example.com"
# export COMPUTE_RES_NAME="RHV"
export RHV_VERSION_4=true
export RHV_RES_USER="admin@internal"
export RHV_RES_PASSWD="Geheim!!"
export RHV_RES_UUID="Default"

if [ $CONFIGURE_RHEV_RESOURCE = 'true' -a $CONFIGURE_LIBVIRT_RESOURCE = 'true' ]; then
    echo "Only one of CONFIGURE_RHEV_RESOURCE and CONFIGURE_LIBVIRT_RESOURCE may be true."
    exit 1
fi

# FIRST_SATELLITE matters only if you want to have more than one Sat work with the same IPA REALM infrastructure.
# If this is the case, you need to make sure to set this to false for all subsequent Satellite instances.
export FIRST_SATELLITE=false


# This is the end of the header section.
# Depending on the STAGE declared above, the script will start at some point and continue all the way to the end -- if everything goes well ;-)
# As mentioned before, there is a halt for manual intervention right after satellite-install and a second halt at the end before creating the demo hosts.


# Be prepared to wait a long time until the content sync has completed.

# BEGIN preqeq prep
if [ $STAGE -le 1 ]; then
    subscription-manager register || true
    subscription-manager repos --disable "*"
    subscription-manager repos --enable=rhel-7-server-rpms \
        --enable=rhel-server-rhscl-7-rpms \
        --enable=rhel-7-server-optional-rpms \
        --enable=rhel-7-server-satellite-6.5-rpms \
        --enable=rhel-7-server-satellite-maintenance-6-rpms \
        --enable=rhel-7-server-ansible-2.6-rpms

    subscription-manager release --unset
    yum install -y screen yum-utils vim

    rpm -Uvh https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm || true
    yum-config-manager --disable epel

    yum -y upgrade

    echo "${SAT_IP} $(hostname)" >>/etc/hosts
    yum install -y ipa-client ipa-admintools
    ipa-client-install --server=$IPA_SERVER --domain=$DOMAIN --realm=$REALM --ip-address=${SAT_IP}
    kinit admin@${REALM}
    ipa service-add HTTP/$(hostname)
    if [ $IPA_EXT_CERT = 'true' ]; then
        mkdir -p /root/certs
	openssl req -nodes -newkey rsa:2048 -keyout /root/certs/key.pem -out /root/certs/${longname}.csr -subj "/C=${C}/ST=${ST}/L=${L}/O=${ORG}/OU=${OU}/CN=$(hostname)"
        serial=$(ipa cert-request --add --principal=host/$(hostname) /root/certs/${longname}.csr|grep number:|cut -d' ' -f5)
        ipa cert-show --out /root/certs/${longname}.crt $serial
    fi
fi
# END preqeq prep

# BEGIN installation
if [ $STAGE -le 2 ]; then
    # yum -y install satellite foreman-proxy
    yum -y install satellite

    firewall-cmd --permanent --add-service='RH-Satellite-6' --add-service='dns' --add-service='dhcp' --add-service='tftp' --add-service='http' --add-service='https'
    # goferd
    firewall-cmd --permanent --add-port='5674/tcp'
    # VNC
    firewall-cmd --permanent --add-port='5901-5930/tcp'
    # OMAPI
    firewall-cmd --permanent --add-port='7911/tcp'
    # Capsule
    firewall-cmd --permanent --add-port="5000/tcp" --add-port="5646/tcp"
    firewall-cmd --reload

    mkdir -p /usr/share/foreman/.ssh
    ssh-keygen -f /usr/share/foreman/.ssh/id_rsa -t rsa -N ''
    ssh-keyscan -t ecdsa $COMPUTE_RES_NAME >/usr/share/foreman/.ssh/known_hosts
    chown -R foreman.foreman /usr/share/foreman/.ssh

    mkdir -p /root/.hammer
    cat > /root/.hammer/cli_config.yml <<EOF
:foreman:
    :host: 'https://$(hostname)/'
    :username: '$ADMIN'
    :password: '$ADMIN_PASSWORD'
    :request_timeout: -1
EOF

    if [ $IPA_EXT_CERT = 'true' ]; then
        katello-certs-check \
          -b /etc/ipa/ca.crt \
          -k /root/certs/key.pem \
          -c /root/certs/${longname}.crt
        CERT_ARGS="--certs-server-ca-cert=/etc/ipa/ca.crt \
               --certs-server-key=/root/certs/key.pem \
               --certs-server-cert=/root/certs/${longname}.crt \
               --certs-server-cert-req=/root/certs/${longname}.csr"
    fi

    if [ $FIRST_SATELLITE = 'true' ]; then
        foreman-prepare-realm admin ${REALM_PROXY_USER}
        mv freeipa.keytab /root/freeipa.keytab
    elif [ ! -f /root/freeipa.keytab ]; then
        read -p "

        Manual action required!

            To proceed you need to manually copy the freeipa.keytab from your existing Satellite server.
	    The file is located in /etc/foreman-proxy/freeipa.keytab.
	    Make sure it is owned by foreman-proxy.foreman-proxy and has permission 0600.
	    Do not run foreman-prepare-realm again. This will invalidate all pre-existing freeipa.keytab files.
            
            Hit Enter after the freeipa.keytab has been copied." answer

    else
        echo "Using existing keytab in /root/freeipa.keytab"
    fi
    cp /root/freeipa.keytab /etc/foreman-proxy
    chown foreman-proxy:foreman-proxy /etc/foreman-proxy/freeipa.keytab
    cp /etc/ipa/ca.crt /etc/pki/ca-trust/source/anchors/ipa.crt
    update-ca-trust enable
    update-ca-trust

    time satellite-installer --scenario satellite -v \
      --foreman-admin-password=$ADMIN_PASSWORD \
      --foreman-admin-username=$ADMIN \
      --foreman-initial-organization=$ORG \
      --foreman-initial-location=$LOC \
      --foreman-proxy-dns=true \
      --foreman-proxy-dns-interface=$SAT_INTERFACE \
      --foreman-proxy-dns-zone=$DOMAIN  \
      --foreman-proxy-dns-forwarders=$DNS \
      --foreman-proxy-dns-reverse=$DNS_REV  \
      --foreman-proxy-dhcp=true \
      --foreman-proxy-dhcp-interface=$SAT_INTERFACE \
      --foreman-proxy-dhcp-range="$DHCP_RANGE" \
      --foreman-proxy-dhcp-gateway=$DHCP_GW \
      --foreman-proxy-dhcp-nameservers=$DHCP_DNS \
      --foreman-proxy-tftp=true \
      --foreman-proxy-tftp-servername=$(hostname) \
      --foreman-proxy-puppetca=true ${CERT_ARGS} \
      --foreman-proxy-realm=true \
      --foreman-proxy-realm-keytab=/etc/foreman-proxy/freeipa.keytab \
      --foreman-proxy-realm-principal="${REALM_PROXY_USER}@${REALM}" \
      --foreman-proxy-realm-provider=freeipa \
      --foreman-ipa-authentication=true \
      --enable-foreman-plugin-openscap

    service foreman-proxy restart
    hammer capsule refresh-features --id=1
    hammer settings set --name default_download_policy --value on_demand
    hammer subscription upload --organization "$ORG" --file /tmp/${MANIFEST}
    # hammer subscription refresh-manifest --organization "$ORG"
    yum install -y puppet-foreman_scap_client
    yum install -y foreman-discovery-image
    foreman-rake foreman_openscap:bulk_upload:default
    mkdir -p /etc/puppet/environments/production/modules
    hammer realm create --realm-type='Red Hat Identity Management' --name=${REALM} --realm-proxy-id=1 --locations=${LOC} --organizations=${ORG}

    if [ $PREPARE_CAPSULE = 'true' ]; then
        hammer location create --name=$CAPSULE_LOC --description='Capsule Location'
        hammer location add-organization --name=$CAPSULE_LOC --organization=$ORG
        export CAPSULE_PASS=$(pwmake 64)
        hammer user create --login='capsule' --firstname='Satellite' --lastname='Capsule' --default-location=$CAPSULE_LOC --default-organization=$ORG --locale='de' --organizations=$ORG --locations=$CAPSULE_LOC --timezone='Berlin' --password="$CAPSULE_PASS" --admin=true --mail="capsule@${DOMAIN}" --auth-source-id=1
        cat > /root/.hammer/capsule_cli_config.yml <<EOF
:foreman:
    :host: 'https://$(hostname)/'
    :username: 'capsule'
    :password: '$CAPSULE_PASS'
    :request_timeout: -1
EOF
    fi

fi
# END installation


# BEGIN content sync
# Sync of Red Hat RPM packages adds up to ~160GB of disk space in /var and takes ~ 24hours to finish
if [ $STAGE -le 3 ]; then
    date
    # Essential RHEL7 Content
    hammer repository-set enable --organization "$ORG" --product 'Red Hat Enterprise Linux Server' --basearch='x86_64' --releasever='7.5' --name 'Red Hat Enterprise Linux 7 Server (Kickstart)' 
    hammer repository update --organization "$ORG" --product 'Red Hat Enterprise Linux Server' --name 'Red Hat Enterprise Linux 7 Server Kickstart x86_64 7.5' --download-policy immediate
    time hammer repository synchronize --organization "$ORG" --product 'Red Hat Enterprise Linux Server'  --name  'Red Hat Enterprise Linux 7 Server Kickstart x86_64 7.5' 2>/dev/null
    # 5099P, 3.73G, 28 min
    hammer repository-set enable --organization "$ORG" --product 'Red Hat Enterprise Linux Server' --basearch='x86_64' --releasever='7Server' --name 'Red Hat Enterprise Linux 7 Server (RPMs)'    
    time hammer repository synchronize --organization "$ORG" --product 'Red Hat Enterprise Linux Server'  --name  'Red Hat Enterprise Linux 7 Server RPMs x86_64 7Server' 2>/dev/null
    # 20120P, 27.3G, 127 min
    hammer repository-set enable --organization "$ORG" --product 'Red Hat Enterprise Linux Server' --basearch='x86_64' --name 'Red Hat Satellite Tools 6.5 (for RHEL 7 Server) (RPMs)'
    time hammer repository synchronize --organization "$ORG" --product 'Red Hat Enterprise Linux Server'  --name  'Red Hat Satellite Tools 6.5 for RHEL 7 Server RPMs x86_64'
    # 69P, 7.25MB, 50 sec
    hammer repository-set enable --organization "$ORG" --product 'Red Hat Enterprise Linux Server' --basearch='x86_64' --name 'Red Hat Satellite Tools 6.5 - Puppet 4 (for RHEL 7 Server) (RPMs)'
    time hammer repository synchronize --organization "$ORG" --product 'Red Hat Enterprise Linux Server'  --name  'Red Hat Satellite Tools 6.5 - Puppet 4 for RHEL 7 Server RPMs x86_64'
    # 1P 26MB 60s
    hammer repository-set enable --organization "$ORG" --product 'Red Hat Software Collections for RHEL Server' --basearch='x86_64' --releasever='7Server' --name 'Red Hat Software Collections RPMs for Red Hat Enterprise Linux 7 Server'
    time hammer repository synchronize --organization "$ORG" --product 'Red Hat Software Collections for RHEL Server'  --name  'Red Hat Software Collections RPMs for Red Hat Enterprise Linux 7 Server x86_64 7Server' 2>/dev/null
    # 9956P, 9.35G, 48 min

    hammer product create --name='Puppet Forge' --organization "$ORG"
    hammer repository create  --organization "$ORG" --name='Modules' --product='Puppet Forge' --content-type='puppet' --publish-via-http=true --url=http://forge.puppetlabs.com/
    time hammer repository synchronize --organization "$ORG" --product 'Puppet Forge'  --name  'Modules' 2>/dev/null
    # 4327P, 426M, 110 min
    du -sh /var/lib/pulp/content/units/puppet_module
    find /var/lib/pulp/content/units/puppet_module -name \*tar.gz|wc -l
    date
    df -h

    # Essential RHEL6 Content
    if [ $RHEL6_CONTENT = 'true' ]; then
        hammer repository-set enable --organization "$ORG" --product 'Red Hat Enterprise Linux Server' --basearch='x86_64' --releasever='6.9' --name 'Red Hat Enterprise Linux 6 Server (Kickstart)' 
        time hammer repository synchronize --organization "$ORG" --product 'Red Hat Enterprise Linux Server'  --name  'Red Hat Enterprise Linux 6 Server Kickstart x86_64 6.9' 2>/dev/null
        # 3852P 3.32G 45 min
        hammer repository-set enable --organization "$ORG" --product 'Red Hat Enterprise Linux Server' --basearch='x86_64' --releasever='6Server' --name 'Red Hat Enterprise Linux 6 Server (RPMs)'
        time hammer repository synchronize --organization "$ORG" --product 'Red Hat Enterprise Linux Server'  --name  'Red Hat Enterprise Linux 6 Server RPMs x86_64 6Server' 2>/dev/null
        # 18119P, 32.2G, 320 min
        hammer repository-set enable --organization "$ORG" --product 'Red Hat Enterprise Linux Server' --basearch='x86_64' --name 'Red Hat Satellite Tools 6.5 (for RHEL 6 Server) (RPMs)'
        time hammer repository synchronize --organization "$ORG" --product 'Red Hat Enterprise Linux Server'  --name  'Red Hat Satellite Tools 6.5 for RHEL 6 Server RPMs x86_64'
        hammer repository-set enable --organization "$ORG" --product 'Red Hat Enterprise Linux Server' --basearch='x86_64' --name 'Red Hat Satellite Tools 6.5 - Puppet 4 (for RHEL 6 Server) (RPMs)'
        time hammer repository synchronize --organization "$ORG" --product 'Red Hat Enterprise Linux Server'  --name  'Red Hat Satellite Tools 6.5 - Puppet 4 for RHEL 6 Server RPMs x86_64'
        hammer repository-set enable --organization "$ORG" --product 'Red Hat Software Collections for RHEL Server' --basearch='x86_64' --releasever='6Server' --name 'Red Hat Software Collections RPMs for Red Hat Enterprise Linux 6 Server'
        time hammer repository synchronize --organization "$ORG" --product 'Red Hat Software Collections for RHEL Server'  --name  'Red Hat Software Collections RPMs for Red Hat Enterprise Linux 6 Server x86_64 6Server' 2>/dev/null
        # 5945P, 5.27G, 82 min
        date
        df -h
    fi

    if [ $OPT_CONTENT = 'true' ]; then
        hammer repository-set enable --organization "$ORG" --product 'Red Hat Enterprise Linux Server' --basearch='x86_64' --name 'Red Hat Enterprise Linux 7 Server - Extras (RPMs)'    
        time hammer repository synchronize --organization "$ORG" --product 'Red Hat Enterprise Linux Server'  --name  'Red Hat Enterprise Linux 7 Server - Extras RPMs x86_64' 2>/dev/null
        # 282P, 630M, 7 min
        hammer repository-set enable --organization "$ORG" --product 'Red Hat Enterprise Linux Server' --basearch='x86_64' --releasever='7Server' --name 'Red Hat Enterprise Linux 7 Server - Optional (RPMs)'    
        time hammer repository synchronize --organization "$ORG" --product 'Red Hat Enterprise Linux Server'  --name  'Red Hat Enterprise Linux 7 Server - Optional RPMs x86_64 7Server' 2>/dev/null
        # 8763P, 11.5G, 120 min
        hammer repository-set enable --organization "$ORG" --product 'Red Hat Enterprise Linux Server' --basearch='x86_64' --releasever='7Server' --name 'Red Hat Enterprise Linux 7 Server - RH Common (RPMs)'    
        time hammer repository synchronize --organization "$ORG" --product 'Red Hat Enterprise Linux Server'  --name  'Red Hat Enterprise Linux 7 Server - RH Common RPMs x86_64 7Server' 2>/dev/null
        # 135P, 4.47G, 14 min
        hammer repository-set enable --organization "$ORG" --product 'Red Hat Enterprise Linux Server' --basearch='x86_64' --releasever='7Server' --name 'Red Hat Enterprise Linux 7 Server - Supplementary (RPMs)'    
        time hammer repository synchronize --organization "$ORG" --product 'Red Hat Enterprise Linux Server'  --name  'Red Hat Enterprise Linux 7 Server - Supplementary RPMs x86_64 7Server' 2>/dev/null
        # 129P, 3.18G, 10 min
        hammer repository-set enable --organization "$ORG" --product 'JBoss Enterprise Application Platform' --basearch='x86_64' --releasever='7Server' --name 'JBoss Enterprise Application Platform 7 (RHEL 7 Server) (RPMs)'
        time hammer repository synchronize --organization "$ORG" --product 'JBoss Enterprise Application Platform'  --name  'JBoss Enterprise Application Platform 7 RHEL 7 Server RPMs x86_64 7Server' 2>/dev/null
        # 
        hammer repository-set enable --organization "$ORG" --product 'Red Hat Virtualization' --basearch='x86_64' --releasever='7Server' --name 'Red Hat Virtualization 4 Management Agents for RHEL 7 (RPMs)'
        time hammer repository synchronize --organization "$ORG" --product 'Red Hat Virtualization'  --name  'Red Hat Virtualization 4 Management Agents for RHEL 7 RPMs x86_64 7Server' 2>/dev/null
        # 1047P, 27.9G, 7min
        hammer repository-set enable --organization "$ORG" --product 'Red Hat Satellite' --basearch='x86_64' --name 'Red Hat Satellite 6.5 (for RHEL 7 Server) (RPMs)'
        time hammer repository synchronize --organization "$ORG" --product 'Red Hat Satellite'  --name  'Red Hat Satellite 6.5 for RHEL 7 Server RPMs x86_64' 2>/dev/null
        # 302P, 420M, 3 min
        hammer repository-set enable --organization "$ORG" --product 'Red Hat Satellite Capsule' --basearch='x86_64' --name 'Red Hat Satellite Capsule 6.5 (for RHEL 7 Server) (RPMs)'
        time hammer repository synchronize --organization "$ORG" --product 'Red Hat Satellite Capsule'  --name  'Red Hat Satellite Capsule 6.5 for RHEL 7 Server RPMs x86_64' 2>/dev/null
        # 6P, 517k, 1min
        hammer repository-set enable --organization "$ORG" --product 'Red Hat Satellite Capsule' --basearch='x86_64' --name 'Red Hat Satellite Capsule 6.5 - Puppet 4 (for RHEL 7 Server) (RPMs)'
        time hammer repository synchronize --organization "$ORG" --product 'Red Hat Satellite Capsule'  --name  'Red Hat Satellite Capsule 6.5 - Puppet 4 for RHEL 7 Server RPMs x86_64' 2>/dev/null
        # 3P, 517k, 1min
        hammer repository-set enable --organization "$ORG" --product 'Red Hat OpenShift Container Platform' --basearch='x86_64' --name 'Red Hat OpenShift Container Platform 3.9 (RPMs)'
        time hammer repository synchronize --organization "$ORG" --product 'Red Hat OpenShift Container Platform'  --name  'Red Hat OpenShift Container Platform 3.9 RPMs x86_64' 2>/dev/null
        # 524P, 1.23G, 4 min
        wget https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-7Server
        hammer gpg create --organization "$ORG" --name 'GPG-EPEL7' --key RPM-GPG-KEY-EPEL-7Server
        hammer product create --name='EPEL' --organization "$ORG"
        hammer repository create  --organization "$ORG" --name='EPEL 7 - x86_64' --product='EPEL' --gpg-key='GPG-EPEL7' --content-type='yum' --publish-via-http=true --url=http://mirror.de.leaseweb.net/epel/7/x86_64/ --download-policy on_demand
        time hammer repository synchronize --organization "$ORG" --product 'EPEL'  --name  'EPEL 7 - x86_64' 2>/dev/null
        # 12513P, 13.3G, 87 min


        if [ $RHEL6_CONTENT = 'true' ]; then
            hammer repository-set enable --organization "$ORG" --product 'Red Hat Enterprise Linux Server' --basearch='x86_64' --name 'Red Hat Enterprise Linux 6 Server - Extras (RPMs)'    
            time hammer repository synchronize --organization "$ORG" --product 'Red Hat Enterprise Linux Server'  --name  'Red Hat Enterprise Linux 6 Server - Extras RPMs x86_64' 2>/dev/null
            hammer repository-set enable --organization "$ORG" --product 'Red Hat Enterprise Linux Server' --basearch='x86_64' --releasever='6Server' --name 'Red Hat Enterprise Linux 6 Server - Optional (RPMs)'    
            time hammer repository synchronize --organization "$ORG" --product 'Red Hat Enterprise Linux Server'  --name  'Red Hat Enterprise Linux 6 Server - Optional RPMs x86_64 6Server' 2>/dev/null
            # 10135P, 19.3G, 180 min
            hammer repository-set enable --organization "$ORG" --product 'Red Hat Enterprise Linux Server' --basearch='x86_64' --releasever='6Server' --name 'Red Hat Enterprise Linux 6 Server - Supplementary (RPMs)'    
            time hammer repository synchronize --organization "$ORG" --product 'Red Hat Enterprise Linux Server'  --name  'Red Hat Enterprise Linux 6 Server - Supplementary RPMs x86_64 6Server' 2>/dev/null
            # 297P, 4.2G, 12 min
            hammer repository-set enable --organization "$ORG" --product 'Red Hat Enterprise Linux Server' --basearch='x86_64' --releasever='6Server' --name 'Red Hat Enterprise Linux 6 Server - RH Common (RPMs)'    
            time hammer repository synchronize --organization "$ORG" --product 'Red Hat Enterprise Linux Server'  --name  'Red Hat Enterprise Linux 6 Server - RH Common RPMs x86_64 6Server' 2>/dev/null
        fi
        date
        df -h
    fi
    if [ $EXT_CONTENT = 'true' ]; then
        hammer repository-set enable --organization "$ORG" --product 'Red Hat Enterprise Linux Server' --basearch='x86_64' --releasever='7Server' --name 'Red Hat Ceph Storage Tools 1.3 for Red Hat Enterprise Linux 7 Server (RPMs)'
        time hammer repository synchronize --organization "$ORG" --product 'Red Hat Enterprise Linux Server'  --name  'Red Hat Ceph Storage Tools 1.3 for Red Hat Enterprise Linux 7 Server RPMs x86_64 7Server' 2>/dev/null
        hammer repository-set enable --organization "$ORG" --product 'Red Hat Enterprise Linux Server' --basearch='x86_64' --releasever='7Server' --name 'Red Hat Storage Native Client for RHEL 7 (RPMs)'
        time hammer repository synchronize --organization "$ORG" --product 'Red Hat Enterprise Linux Server'  --name  'Red Hat Storage Native Client for RHEL 7 RPMs x86_64 7Server' 2>/dev/null
        hammer repository-set enable --organization "$ORG" --product 'Red Hat Ceph Storage' --basearch='x86_64' --releasever='7Server' --name 'Red Hat Ceph Storage Installer 1.3 for Red Hat Enterprise Linux 7 Server (RPMs)'
        time hammer repository synchronize --organization "$ORG" --product 'Red Hat Ceph Storage'  --name  'Red Hat Ceph Storage Installer 1.3 for Red Hat Enterprise Linux 7 Server RPMs x86_64 7Server' 2>/dev/null


        hammer repository-set enable --organization "$ORG" --product 'Red Hat OpenStack' --basearch='x86_64' --releasever='7Server' --name 'Red Hat OpenStack Platform 8 Operational Tools for RHEL 7 (RPMs)'
        time hammer repository synchronize --organization "$ORG" --product 'Red Hat OpenStack'  --name  'Red Hat OpenStack Platform 8 Operational Tools for RHEL 7 RPMs x86_64 7Server' 2>/dev/null
        hammer repository-set enable --organization "$ORG" --product 'Red Hat OpenStack' --basearch='x86_64' --releasever='7Server' --name 'Red Hat OpenStack Platform 8 director for RHEL 7 (RPMs)'
        time hammer repository synchronize --organization "$ORG" --product 'Red Hat OpenStack'  --name  'Red Hat OpenStack Platform 8 director for RHEL 7 RPMs x86_64 7Server' 2>/dev/null
        hammer repository-set enable --organization "$ORG" --product 'Red Hat OpenStack' --basearch='x86_64' --releasever='7Server' --name 'Red Hat OpenStack Platform 8 for RHEL 7 (RPMs)'
        time hammer repository synchronize --organization "$ORG" --product 'Red Hat OpenStack'  --name  'Red Hat OpenStack Platform 8 for RHEL 7 RPMs x86_64 7Server' 2>/dev/null
        hammer repository-set enable --organization "$ORG" --product 'Red Hat Enterprise Linux Server' --basearch='x86_64' --releasever='7Server' --name 'Red Hat OpenStack Tools 7.0 for Red Hat Enterprise Linux 7 Server (RPMs)'
        time hammer repository synchronize --organization "$ORG" --product 'Red Hat Enterprise Linux Server'  --name  'Red Hat OpenStack Tools 7.0 for Red Hat Enterprise Linux 7 Server RPMs x86_64 7Server' 2>/dev/null

        hammer repository-set enable --organization "$ORG" --product 'Red Hat Virtualization Host' --basearch='x86_64' --name 'Red Hat Virtualization Host 7 (RPMs)'
        time hammer repository synchronize --organization "$ORG" --product 'Red Hat Virtualization Host'  --name  'Red Hat Virtualization Host 7 RPMs x86_64' 2>/dev/null
        hammer repository-set enable --organization "$ORG" --product 'Red Hat Virtualization' --basearch='x86_64' --name 'Red Hat Virtualization Manager 4.0 (RHEL 7 Server) (RPMs)'
        time hammer repository synchronize --organization "$ORG" --product 'Red Hat Virtualization'  --name  'Red Hat Virtualization Manager 4.0 RHEL 7 Server RPMs x86_64' 2>/dev/null

        hammer repository-set enable --organization "$ORG" --product 'Red Hat Enterprise Linux Atomic Host' --basearch='x86_64' --name 'Red Hat Enterprise Linux Atomic Host (RPMs)'
        time hammer repository synchronize --organization "$ORG" --product 'Red Hat Enterprise Linux Atomic Host'  --name  'Red Hat Enterprise Linux Atomic Host RPMs x86_64' 2>/dev/null

        # hammer repository-set enable --organization "$ORG" --product '' --basearch='x86_64' --releasever='7Server' --name ''
        # time hammer repository synchronize --organization "$ORG" --product ''  --name  '' 2>/dev/null

        if [ $RHEL6_CONTENT = 'true' ]; then
            hammer repository-set enable --organization "$ORG" --product 'JBoss Enterprise Application Platform' --basearch='x86_64' --releasever='7Server' --name 'JBoss Enterprise Application Platform 6 (RHEL 7 Server) (RPMs)'
            time hammer repository synchronize --organization "$ORG" --product 'JBoss Enterprise Application Platform'  --name  'JBoss Enterprise Application Platform 6 RHEL 7 Server RPMs x86_64 7Server' 2>/dev/null
        fi
        date
        df -h
    fi
    if [ $CUST_CONTENT = 'true' ]; then
	echo "$CUSTOM_REPO_IP	$CUSTOM_REPO_HOST" >>/etc/hosts
        hammer product create --name="$ORG" --organization "$ORG"
        hammer repository create  --organization "$ORG" --name='Puppet Modules' --product="$ORG" --content-type='puppet' --publish-via-http=true --url=http://${CUSTOM_REPO_HOST}/repos/puppet-modules/
        time hammer repository synchronize --organization "$ORG" --product="$ORG"  --name='Puppet Modules' 2>/dev/null
        hammer repository create  --organization "$ORG" --name='Packages' --product="$ORG" --content-type='yum' --publish-via-http=true --url=http://${CUSTOM_REPO_HOST}/repos/${ORG}-packages/ --download-policy immediate
        time hammer repository synchronize --organization "$ORG" --product="$ORG"  --name='Packages' 2>/dev/null
        wget http://pkg.jenkins.io/redhat/jenkins.io.key
        hammer gpg create --organization "$ORG" --name GPG-JENKINS --key jenkins.io.key
        hammer repository create  --organization "$ORG" --name='Jenkins' --product="$ORG" --gpg-key='GPG-JENKINS' --content-type='yum' --publish-via-http=true --url=http://${CUSTOM_REPO_HOST}/repos/Jenkins-packages/ --download-policy immediate
        time hammer repository synchronize --organization "$ORG" --product="$ORG"  --name='Jenkins' 2>/dev/null
        hammer product create --name='Maven' --organization "$ORG"
        hammer repository create  --organization "$ORG" --name='Maven 7Server' --product='Maven' --content-type='yum' --publish-via-http=true --url=https://repos.fedorapeople.org/repos/dchen/apache-maven/epel-7Server/x86_64/ --download-policy immediate
        time hammer repository synchronize --organization "$ORG" --product='Maven'  --name='Maven 7Server' 2>/dev/null
        wget http://packages.icinga.org/icinga.key
        hammer gpg create --organization "$ORG" --name GPG-ICINGA --key icinga.key
        hammer product create --name='Icinga' --organization "$ORG"
        hammer repository create  --organization "$ORG" --name='Icinga 7Server' --product='Icinga' --content-type='yum' --gpg-key='GPG-ICINGA' --publish-via-http=true --url=http://packages.icinga.org/epel/7Server/release --download-policy immediate
        time hammer repository synchronize --organization "$ORG" --product='Icinga'  --name='Icinga 7Server' 2>/dev/null
        date
        df -h
    fi
    hammer sync-plan create --name "daily sync" --enabled=true --interval daily --organization $ORG --sync-date "2018-05-01 01:00:00"
    for i in $(hammer --csv product list --organization $ORG --per-page 999 | grep -vi '^ID' | grep -vi not_synced | awk -F, {'{ if ($5!=0) print $1}'})
    do
      hammer product set-sync-plan --sync-plan "daily sync" --organization $ORG --id $i
    done

    export CVMANAGER_PASS=$(pwmake 64)
    hammer user create --login='cvmanager' --firstname='ContentView' --lastname='Manager' --default-location=$LOC --default-organization=$ORG --locale='de' --organizations=$ORG --locations=$LOC --timezone='Berlin' --password="$CVMANAGER_PASS" --roles='Manager' --mail="cvmanager@${DOMAIN}" --auth-source-id=1
    yum -y install ruby-devel gcc
    git clone https://github.com/RedHatSatellite/katello-cvmanager.git
    gem install apipie-bindings || true
    echo > /root/katello-cvmanager/UnStaged.yaml <<EOF
---
:settings:
  :user: cvmanager
  :pass: $CVMANAGER_PASS
  :uri: https://$(hostname)
  :timeout: 300
  :org: 1
  :lifecycle: 5
  :keep: 3
  :promote_cvs: true
  :checkrepos: true
:cv:
  RHEL7_Base: latest
  inf-builder-rhel7: latest
  inf-docker-rhel7: latest
  inf-git-rhel7: latest
  inf-hypervisor-rhel7: latest
  inf-ipa-rhel7: latest
  inf-oscp-rhel7: latest
:promote:
 - RHEL7_Base
 - inf-builder-rhel7
 - inf-docker-rhel7
 - inf-git-rhel7
 - inf-hypervisor-rhel7
 - inf-ipa-rhel7
 - inf-oscp-rhel7
:publish:
 - RHEL7_Base
 - inf-builder-rhel7
 - inf-docker-rhel7
 - inf-git-rhel7
 - inf-hypervisor-rhel7
 - inf-ipa-rhel7
 - inf-oscp-rhel7
EOF

    echo > /root/katello-cvmanager/daily_updates.sh <<EOF
#! /bin/bash
set -e
./cvmanager --config=UnStaged.yaml --wait publish
./cvmanager --config=UnStaged.yaml --wait update
./cvmanager --config=UnStaged.yaml --wait promote
./cvmanager --config=UnStaged.yaml --wait clean
EOF
    chmod +x /root/katello-cvmanager/daily_updates.sh

    crontab -l | { cat; echo "30 04 * * * cd /root/katello-cvmanager/ && /root/katello-cvmanager/daily_updates.sh | mail -E -s 'Satellite daily report: Content view updates' cvmanager@${DOMAIN}"; } | crontab -

fi
# END content sync

# BEGIN environment setup
if [ $STAGE -le 4 ]; then
    hammer lifecycle-environment create --organization "$ORG" --description 'Development' --name 'Development' --label development --prior Library
    hammer lifecycle-environment create --organization "$ORG" --description 'Test' --name 'Test' --label test --prior 'Development'
    hammer lifecycle-environment create --organization "$ORG" --description 'Production' --name 'Production' --label production --prior 'Test'
    hammer lifecycle-environment create --organization "$ORG" --description 'Latest packages without staging' --name 'UnStaged' --label unstaged --prior Library

    hammer domain update --id 1 --organizations "$ORG" --locations "$LOC"

    hammer subnet create --name $SUBNET_NAME \
      --network $SUBNET \
      --mask $SUBNET_MASK \
      --gateway $DHCP_GW \
      --dns-primary $DHCP_DNS \
      --ipam 'Internal DB' \
      --from $SUBNET_IPAM_BEGIN \
      --to $SUBNET_IPAM_END \
      --tftp-id 1 \
      --dhcp-id 1 \
      --dns-id 1 \
      --domain-ids 1 \
      --organizations "$ORG" \
      --locations "$LOC"

    if [ $CONFIGURE_LIBVIRT_RESOURCE = 'true' ]; then
        hammer compute-resource create --organizations "$ORG" --name "$COMPUTE_RES_NAME" --locations "$LOC" --provider Libvirt --url qemu+ssh://root@${COMPUTE_RES_FQDN}/system --set-console-password false
    fi

    if [ $CONFIGURE_RHEV_RESOURCE = 'true' ]; then
        hammer compute-resource create --name "${COMPUTE_RES_NAME}" --provider "Ovirt" --description "RHV4 Managment Server" --url "https://${COMPUTE_RES_FQDN}/ovirt-engine/api/v3" --user "${RHV_RES_USER}" --password "${RHV_RES_PASSWD}" --locations "$LOC" --organizations "$ORG" --uuid "${RHV_RES_UUID}"
    fi

    cat >kickstart-docker <<EOF
<%#
kind: ptable
name: Kickstart Docker
oses:
- CentOS 5
- CentOS 6
- CentOS 7
- Fedora 16
- Fedora 17
- Fedora 18
- Fedora 19
- Fedora 20
- RedHat 5
- RedHat 6
- RedHat 7
%>
zerombr
clearpart --all --initlabel

part  /boot     --asprimary  --size=1024
part  swap                             --size=1024
part  pv.01     --asprimary  --size=12000 --grow

volgroup dockerhost pv.01
logvol / --vgname=dockerhost --size=9000 --name=rootvol
EOF
    hammer partition-table create  --file=kickstart-docker --name='Kickstart Docker' --os-family='Redhat' --organizations="$ORG" --locations="$LOC"
    hammer os update --title 'RedHat 7.5' --partition-tables='Kickstart default','Kickstart Docker'
fi
# END environment setup

# BEGIN content view setup
if [ $STAGE -le 5 ]; then
    date
    hammer content-view create --organization "$ORG" --name 'RHEL7_Base' --label rhel7_base --description 'Core Build for RHEL 7'
    hammer content-view add-repository --organization "$ORG" --name 'RHEL7_Base' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 7 Server RPMs x86_64 7Server'
    hammer content-view add-repository --organization "$ORG" --name 'RHEL7_Base' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 7 Server Kickstart x86_64 7.5'
    hammer content-view add-repository --organization "$ORG" --name 'RHEL7_Base' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Satellite Tools 6.5 for RHEL 7 Server RPMs x86_64'
    hammer content-view add-repository --organization "$ORG" --name 'RHEL7_Base' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Satellite Tools 6.5 - Puppet 4 for RHEL 7 Server RPMs x86_64'
    hammer content-view puppet-module add --organization "$ORG" --content-view RHEL7_Base --author puppetlabs --name stdlib
    hammer content-view puppet-module add --organization "$ORG" --content-view RHEL7_Base --author puppetlabs --name concat
    hammer content-view puppet-module add --organization "$ORG" --content-view RHEL7_Base --author puppetlabs --name ntp
    hammer content-view puppet-module add --organization "$ORG" --content-view RHEL7_Base --author saz --name ssh
    time hammer content-view publish --organization "$ORG" --name RHEL7_Base --description 'Initial Publishing' 2>/dev/null
    time hammer content-view version promote --organization "$ORG" --content-view RHEL7_Base --to-lifecycle-environment UnStaged  2>/dev/null

    if [ $PREPARE_CAPSULE = 'true' ]; then
        hammer content-view create --organization "$ORG" --name 'inf-capsule' --label inf-capsule --description 'Satellite Capsule'
        hammer content-view add-repository --organization "$ORG" --name 'inf-capsule' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 7 Server RPMs x86_64 7Server'
        hammer content-view add-repository --organization "$ORG" --name 'inf-capsule' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 7 Server Kickstart x86_64 7.5'
        hammer content-view add-repository --organization "$ORG" --name 'inf-capsule' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Satellite Tools 6.5 for RHEL 7 Server RPMs x86_64'
        hammer content-view add-repository --organization "$ORG" --name 'inf-capsule' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 7 Server - Optional RPMs x86_64 7Server'
        hammer content-view add-repository --organization "$ORG" --name 'inf-capsule' --product 'Red Hat Software Collections for RHEL Server' --repository 'Red Hat Software Collections RPMs for Red Hat Enterprise Linux 7 Server x86_64 7Server'
        hammer content-view add-repository --organization "$ORG" --name 'inf-capsule' --product 'Red Hat Satellite Capsule' --repository 'Red Hat Satellite Capsule 6.5 for RHEL 7 Server RPMs x86_64'
        hammer content-view add-repository --organization "$ORG" --name 'inf-capsule' --product 'Red Hat Satellite Capsule' --repository 'Red Hat Satellite Capsule 6.5 - Puppet 4 for RHEL 7 Server RPMs x86_64'
        hammer content-view puppet-module add --organization "$ORG" --content-view inf-capsule --author puppetlabs --name stdlib
        hammer content-view puppet-module add --organization "$ORG" --content-view inf-capsule --author puppetlabs --name concat
        hammer content-view puppet-module add --organization "$ORG" --content-view inf-capsule --author puppetlabs --name ntp
        hammer content-view puppet-module add --organization "$ORG" --content-view inf-capsule --author saz --name ssh
        time hammer content-view publish --organization "$ORG" --name inf-capsule --description 'Initial Publishing' 2>/dev/null
        time hammer content-view version promote --organization "$ORG" --content-view inf-capsule --to-lifecycle-environment UnStaged  2>/dev/null
    fi

    hammer content-view create --organization "$ORG" --name 'inf-ipa-rhel7' --label inf-ipa-rhel7 --description ''
    hammer content-view add-repository --organization "$ORG" --name 'inf-ipa-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 7 Server RPMs x86_64 7Server'
    hammer content-view add-repository --organization "$ORG" --name 'inf-ipa-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 7 Server Kickstart x86_64 7.5'
    hammer content-view add-repository --organization "$ORG" --name 'inf-ipa-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Satellite Tools 6.5 for RHEL 7 Server RPMs x86_64'
    hammer content-view add-repository --organization "$ORG" --name 'inf-ipa-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Satellite Tools 6.5 - Puppet 4 for RHEL 7 Server RPMs x86_64'
    hammer content-view add-repository --organization "$ORG" --name 'inf-ipa-rhel7' --product 'Red Hat Software Collections for RHEL Server' --repository 'Red Hat Software Collections RPMs for Red Hat Enterprise Linux 7 Server x86_64 7Server'
    hammer content-view add-repository --organization "$ORG" --name 'inf-ipa-rhel7' --product 'EPEL' --repository 'EPEL 7 - x86_64'
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-ipa-rhel7 --author puppetlabs --name stdlib
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-ipa-rhel7 --author puppetlabs --name concat
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-ipa-rhel7 --author puppetlabs --name ntp
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-ipa-rhel7 --author saz --name ssh
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-ipa-rhel7 --author example42 --name puppi
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-ipa-rhel7 --author example42 --name monitor
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-ipa-rhel7 --author netmanagers --name fail2ban
    time hammer content-view publish --organization "$ORG" --name inf-ipa-rhel7 --description 'Initial Publishing' 2>/dev/null
    time hammer content-view version promote --organization "$ORG" --content-view inf-ipa-rhel7 --to-lifecycle-environment UnStaged  2>/dev/null

    hammer content-view create --organization "$ORG" --name 'inf-hypervisor-rhel7' --label inf-hypervisor-rhel7 --description ''
    hammer content-view add-repository --organization "$ORG" --name 'inf-hypervisor-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 7 Server RPMs x86_64 7Server'
    hammer content-view add-repository --organization "$ORG" --name 'inf-hypervisor-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Satellite Tools 6.5 for RHEL 7 Server RPMs x86_64'
    hammer content-view add-repository --organization "$ORG" --name 'inf-hypervisor-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Satellite Tools 6.5 - Puppet 4 for RHEL 7 Server RPMs x86_64'
    hammer content-view add-repository --organization "$ORG" --name 'inf-hypervisor-rhel7' --product 'Red Hat Virtualization' --repository 'Red Hat Virtualization 4 Management Agents for RHEL 7 RPMs x86_64 7Server'
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-hypervisor-rhel7 --author puppetlabs --name stdlib
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-hypervisor-rhel7 --author puppetlabs --name concat
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-hypervisor-rhel7 --author puppetlabs --name ntp
    time hammer content-view publish --organization "$ORG" --name inf-hypervisor-rhel7 --description 'Initial Publishing' 2>/dev/null
    time hammer content-view version promote --organization "$ORG" --content-view inf-hypervisor-rhel7 --to-lifecycle-environment UnStaged  2>/dev/null

    hammer content-view create --organization "$ORG" --name 'inf-builder-rhel7' --label inf-builder-rhel7 --description ''
    hammer content-view add-repository --organization "$ORG" --name 'inf-builder-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 7 Server RPMs x86_64 7Server'
    hammer content-view add-repository --organization "$ORG" --name 'inf-builder-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 7 Server Kickstart x86_64 7.5'
    hammer content-view add-repository --organization "$ORG" --name 'inf-builder-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Satellite Tools 6.5 for RHEL 7 Server RPMs x86_64'
    hammer content-view add-repository --organization "$ORG" --name 'inf-builder-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Satellite Tools 6.5 - Puppet 4 for RHEL 7 Server RPMs x86_64'
    hammer content-view add-repository --organization "$ORG" --name 'inf-builder-rhel7' --product 'Red Hat Software Collections for RHEL Server' --repository 'Red Hat Software Collections RPMs for Red Hat Enterprise Linux 7 Server x86_64 7Server'
    hammer content-view add-repository --organization "$ORG" --name 'inf-builder-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 7 Server - Supplementary RPMs x86_64 7Server'
    hammer content-view add-repository --organization "$ORG" --name 'inf-builder-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 7 Server - RH Common RPMs x86_64 7Server'
    hammer content-view add-repository --organization "$ORG" --name 'inf-builder-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 7 Server - Optional RPMs x86_64 7Server'
    hammer content-view add-repository --organization "$ORG" --name 'inf-builder-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 7 Server - Extras RPMs x86_64'
    hammer content-view add-repository --organization "$ORG" --name 'inf-builder-rhel7' --product 'JBoss Enterprise Application Platform' --repository 'JBoss Enterprise Application Platform 7 RHEL 7 Server RPMs x86_64 7Server'
    hammer content-view add-repository --organization "$ORG" --name 'inf-builder-rhel7' --product 'Maven' --repository 'Maven 7Server'
    hammer content-view add-repository --organization "$ORG" --name 'inf-builder-rhel7' --product 'EPEL' --repository 'EPEL 7 - x86_64'
    hammer content-view add-repository --organization "$ORG" --name 'inf-builder-rhel7' --product "$ORG" --repository "Packages"
    hammer content-view add-repository --organization "$ORG" --name 'inf-builder-rhel7' --product "$ORG" --repository "Jenkins"
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-builder-rhel7 --author puppetlabs --name stdlib
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-builder-rhel7 --author puppetlabs --name concat
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-builder-rhel7 --author puppetlabs --name ntp
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-builder-rhel7 --author saz --name ssh
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-builder-rhel7 --author puppetlabs --name postgresql
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-builder-rhel7 --author puppetlabs --name java
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-builder-rhel7 --author rtyler --name jenkins
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-builder-rhel7 --author LunetIX --name git
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-builder-rhel7 --author LunetIX --name buildhost
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-builder-rhel7 --author camptocamp --name archive
    time hammer content-view publish --organization "$ORG" --name inf-builder-rhel7 --description 'Initial Publishing'
    time hammer content-view version promote --organization "$ORG" --content-view inf-builder-rhel7 --to-lifecycle-environment UnStaged

    hammer content-view create --organization "$ORG" --name 'inf-oscp-rhel7' --label inf-oscp-rhel7 --description ''
    hammer content-view add-repository --organization "$ORG" --name 'inf-oscp-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 7 Server RPMs x86_64 7Server'
    hammer content-view add-repository --organization "$ORG" --name 'inf-oscp-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Satellite Tools 6.5 for RHEL 7 Server RPMs x86_64'
    hammer content-view add-repository --organization "$ORG" --name 'inf-oscp-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Satellite Tools 6.5 - Puppet 4 for RHEL 7 Server RPMs x86_64'
    hammer content-view add-repository --organization "$ORG" --name 'inf-oscp-rhel7' --product 'Red Hat Software Collections for RHEL Server' --repository 'Red Hat Software Collections RPMs for Red Hat Enterprise Linux 7 Server x86_64 7Server'
    hammer content-view add-repository --organization "$ORG" --name 'inf-oscp-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 7 Server - Optional RPMs x86_64 7Server'
    hammer content-view add-repository --organization "$ORG" --name 'inf-oscp-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 7 Server - Extras RPMs x86_64'
    hammer content-view add-repository --organization "$ORG" --name 'inf-oscp-rhel7' --product 'Red Hat OpenShift Container Platform' --repository 'Red Hat OpenShift Container Platform 3.9 RPMs x86_64'
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-oscp-rhel7 --author puppetlabs --name stdlib
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-oscp-rhel7 --author puppetlabs --name concat
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-oscp-rhel7 --author puppetlabs --name ntp
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-oscp-rhel7 --author saz --name ssh
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-oscp-rhel7 --author cristifalcas --name kubernetes
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-oscp-rhel7 --author cristifalcas --name etcd
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-oscp-rhel7 --author LunetIX --name docker
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-oscp-rhel7 --author crayfishx --name firewalld
    # hammer content-view puppet-module add --organization "$ORG" --content-view inf-oscp-rhel7 --author LunetIX --name oscp
    time hammer content-view publish --organization "$ORG" --name inf-oscp-rhel7 --description 'Initial Publishing'
    time hammer content-view version promote --organization "$ORG" --content-view inf-oscp-rhel7 --to-lifecycle-environment UnStaged

    hammer content-view create --organization "$ORG" --name 'inf-docker-rhel7' --label inf-docker-rhel7 --description ''
    hammer content-view add-repository --organization "$ORG" --name 'inf-docker-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 7 Server RPMs x86_64 7Server'
    hammer content-view add-repository --organization "$ORG" --name 'inf-docker-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Satellite Tools 6.5 for RHEL 7 Server RPMs x86_64'
    hammer content-view add-repository --organization "$ORG" --name 'inf-docker-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Satellite Tools 6.5 - Puppet 4 for RHEL 7 Server RPMs x86_64'
    hammer content-view add-repository --organization "$ORG" --name 'inf-docker-rhel7' --product 'Red Hat Software Collections for RHEL Server' --repository 'Red Hat Software Collections RPMs for Red Hat Enterprise Linux 7 Server x86_64 7Server'
    hammer content-view add-repository --organization "$ORG" --name 'inf-docker-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 7 Server - Optional RPMs x86_64 7Server'
    hammer content-view add-repository --organization "$ORG" --name 'inf-docker-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 7 Server - Extras RPMs x86_64'
    hammer content-view add-repository --organization "$ORG" --name 'inf-docker-rhel7' --product 'Red Hat OpenShift Container Platform' --repository 'Red Hat OpenShift Container Platform 3.9 RPMs x86_64'
    hammer content-view add-repository --organization "$ORG" --name 'inf-docker-rhel7' --product 'JBoss Enterprise Application Platform' --repository 'JBoss Enterprise Application Platform 7 RHEL 7 Server RPMs x86_64 7Server'
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-docker-rhel7 --author puppetlabs --name stdlib
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-docker-rhel7 --author puppetlabs --name concat
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-docker-rhel7 --author puppetlabs --name ntp
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-docker-rhel7 --author saz --name ssh
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-docker-rhel7 --author cristifalcas --name kubernetes
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-docker-rhel7 --author cristifalcas --name etcd
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-docker-rhel7 --author cristifalcas --name docker
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-docker-rhel7 --author crayfishx --name firewalld
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-docker-rhel7 --author LunetIX --name dockerhost
    time hammer content-view publish --organization "$ORG" --name inf-docker-rhel7 --description 'Initial Publishing'
    time hammer content-view version promote --organization "$ORG" --content-view inf-docker-rhel7 --to-lifecycle-environment UnStaged

    hammer content-view create --organization "$ORG" --name 'puppet-fasttrack' --label puppet-fasttrack --description 'Puppet only CV for fast module development workflow'
    hammer content-view puppet-module add --organization "$ORG" --content-view puppet-fasttrack --author puppetlabs --name stdlib
    hammer content-view puppet-module add --organization "$ORG" --content-view puppet-fasttrack --author puppetlabs --name concat
    hammer content-view puppet-module add --organization "$ORG" --content-view puppet-fasttrack --author puppetlabs --name ntp
    hammer content-view puppet-module add --organization "$ORG" --content-view puppet-fasttrack --author saz --name ssh
    hammer content-view puppet-module add --organization "$ORG" --content-view puppet-fasttrack --author puppetlabs --name postgresql
    hammer content-view puppet-module add --organization "$ORG" --content-view puppet-fasttrack --author puppetlabs --name java
    hammer content-view puppet-module add --organization "$ORG" --content-view puppet-fasttrack --author rtyler --name jenkins
    hammer content-view puppet-module add --organization "$ORG" --content-view puppet-fasttrack --author LunetIX --name git
    hammer content-view puppet-module add --organization "$ORG" --content-view puppet-fasttrack --author LunetIX --name buildhost
    hammer content-view puppet-module add --organization "$ORG" --content-view puppet-fasttrack --author camptocamp --name archive
    hammer content-view puppet-module add --organization "$ORG" --content-view puppet-fasttrack --author cristifalcas --name kubernetes
    hammer content-view puppet-module add --organization "$ORG" --content-view puppet-fasttrack --author cristifalcas --name etcd
    hammer content-view puppet-module add --organization "$ORG" --content-view puppet-fasttrack --author LunetIX --name docker
    hammer content-view puppet-module add --organization "$ORG" --content-view puppet-fasttrack --author LunetIX --name oscp
    hammer content-view puppet-module add --organization "$ORG" --content-view puppet-fasttrack --author crayfishx --name firewalld
    hammer content-view puppet-module add --organization "$ORG" --content-view puppet-fasttrack --author LunetIX --name dockerhost
    time hammer content-view publish --organization "$ORG" --name puppet-fasttrack --description 'Initial Publishing'
    time hammer content-view version promote --organization "$ORG" --content-view puppet-fasttrack --to-lifecycle-environment UnStaged

    hammer content-view create --organization "$ORG" --name 'inf-git-rhel7' --label inf-git-rhel7 --description ''
    hammer content-view add-repository --organization "$ORG" --name 'inf-git-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 7 Server RPMs x86_64 7Server'
    hammer content-view add-repository --organization "$ORG" --name 'inf-git-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Satellite Tools 6.5 for RHEL 7 Server RPMs x86_64'
    hammer content-view add-repository --organization "$ORG" --name 'inf-git-rhel7' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Satellite Tools 6.5 - Puppet 4 for RHEL 7 Server RPMs x86_64'
    hammer content-view add-repository --organization "$ORG" --name 'inf-git-rhel7' --product 'Red Hat Software Collections for RHEL Server' --repository 'Red Hat Software Collections RPMs for Red Hat Enterprise Linux 7 Server x86_64 7Server'
    hammer content-view add-repository --organization "$ORG" --name 'inf-git-rhel7' --product 'EPEL' --repository 'EPEL 7 - x86_64'
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-git-rhel7 --author puppetlabs --name stdlib
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-git-rhel7 --author puppetlabs --name concat
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-git-rhel7 --author puppetlabs --name ntp
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-git-rhel7 --author saz --name ssh
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-git-rhel7 --author LunetIX --name git
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-git-rhel7 --author example42 --name puppi
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-git-rhel7 --author example42 --name monitor
    hammer content-view puppet-module add --organization "$ORG" --content-view inf-git-rhel7 --author netmanagers --name fail2ban
    time hammer content-view publish --organization "$ORG" --name inf-git-rhel7 --description 'Initial Publishing'
    time hammer content-view version promote --organization "$ORG" --content-view inf-git-rhel7 --to-lifecycle-environment UnStaged

    if [ $RHEL6_CONTENT = 'true' ]; then
        hammer content-view create --organization "$ORG" --name 'RHEL6_Base' --label rhel6_base --description 'Core Build for RHEL 6'
        hammer content-view add-repository --organization "$ORG" --name 'RHEL6_Base' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 6 Server RPMs x86_64 6Server'
        hammer content-view add-repository --organization "$ORG" --name 'RHEL6_Base' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Satellite Tools 6.5 for RHEL 6 Server RPMs x86_64'
        hammer content-view add-repository --organization "$ORG" --name 'RHEL6_Base' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Satellite Tools 6.5 - Puppet 4 for RHEL 6 Server RPMs x86_64'
        hammer content-view puppet-module add --organization "$ORG" --content-view RHEL6_Base --author puppetlabs --name stdlib
        hammer content-view puppet-module add --organization "$ORG" --content-view RHEL6_Base --author puppetlabs --name concat
        hammer content-view puppet-module add --organization "$ORG" --content-view RHEL6_Base --author puppetlabs --name ntp
        hammer content-view puppet-module add --organization "$ORG" --content-view RHEL6_Base --author saz --name ssh
        time hammer content-view publish --organization "$ORG" --name RHEL6_Base --description 'Initial Publishing' 2>/dev/null
        time hammer content-view version promote --organization "$ORG" --content-view RHEL6_Base --to-lifecycle-environment UnStaged  2>/dev/null
    fi


    # hammer content-view create --organization "$ORG" --name 'CV' --label CV --description ''
    # hammer content-view add-repository --organization "$ORG" --name 'CV' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 7 Server RPMs x86_64 7Server'
    # hammer content-view add-repository --organization "$ORG" --name 'CV' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Satellite Tools 6.5 for RHEL 7 Server RPMs x86_64'
    # hammer content-view add-repository --organization "$ORG" --name 'CV' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Satellite Tools 6.5 - Puppet 4 for RHEL 7 Server RPMs x86_64'
    # hammer content-view puppet-module add --organization "$ORG" --content-view CV --author puppetlabs --name stdlib
    # hammer content-view puppet-module add --organization "$ORG" --content-view CV --author puppetlabs --name concat
    # hammer content-view puppet-module add --organization "$ORG" --content-view CV --author puppetlabs --name ntp
    # hammer content-view puppet-module add --organization "$ORG" --content-view CV --author saz --name ssh
    # time hammer content-view publish --organization "$ORG" --name CV --description 'Initial Publishing' 2>/dev/null
    # time hammer content-view version promote --organization "$ORG" --content-view CV --to-lifecycle-environment UnStaged  2>/dev/null
    
fi
# END content view setup

# BEGIN activation key and hostgroup setup
if [ $STAGE -le 6 ]; then
    PuppetForge_Sub_ID=$(hammer --output='csv' subscription list --organization=$ORG --search='Puppet Forge' | tail -n+2 | head -n1 | cut -d',' -f1)
    EPEL_Sub_ID=$(hammer --output='csv' subscription list --organization=$ORG --search='EPEL' | tail -n+2 | head -n1 | cut -d',' -f1)
    ORG_Sub_ID=$(hammer --output='csv' subscription list --organization=$ORG --search="$ORG" | tail -n+2 | head -n1 | cut -d',' -f1)
    Maven_Sub_ID=$(hammer --output='csv' subscription list --organization=$ORG --search='Maven' | tail -n+2 | head -n1 | cut -d',' -f1)
    JBoss_Sub_ID=$(hammer --output='csv' subscription list --organization=$ORG --search='Red Hat JBoss Enterprise Application Platform, 16-Core Premium' | tail -n+2 | head -n1 | cut -d',' -f1)
    RHEV_Sub_ID=$(hammer --output='csv' subscription list --organization=$ORG --search='Red Hat Virtualization (2-sockets), Standard' | tail -n+2 | head -n1 | cut -d',' -f1)
    OSCP_Sub_ID=$(hammer --output='csv' subscription list --organization=$ORG --search='OpenShift Container Platform, Premium 2-Core' | tail -n+2 | head -n1 | cut -d',' -f1)
    RHEL_Sub_ID=$(hammer --output='csv' subscription list --organization=$ORG --search='Red Hat Enterprise Linux Server with Smart Management, Standard (Physical or Virtual Nodes)' | grep -v 'ATOM\|Resilient\|Hyperscale' | tail -n+2 | head -n1 | cut -d',' -f1)

    hammer medium create --path=http://$(hostname)/pulp/repos/${ORG}/Library/content/dist/rhel/server/7/7.5/x86_64/kickstart/ --organizations="$ORG" --locations="$LOC" --os-family=Redhat --name="RHEL 7.5 Kickstart" --operatingsystems="RedHat 7.5"

    uuid=$(uuidgen)
    hammer activation-key create --organization="$ORG" --name="el7base-${uuid}" --unlimited-hosts --lifecycle-environment='UnStaged' --content-view='RHEL7_Base'
    hammer activation-key add-subscription --organization="$ORG" --name="el7base-${uuid}" --subscription-id="$PuppetForge_Sub_ID" 
    hammer activation-key add-subscription --organization="$ORG" --name="el7base-${uuid}" --subscription-id="$RHEL_Sub_ID" 
    hammer activation-key content-override --organization="$ORG" --name="el7base-${uuid}" --content-label='rhel-7-server-satellite-tools-6.5-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name="el7base-${uuid}" --content-label='rhel-7-server-satellite-tools-6.5-puppet4-rpms' --value=1
    hammer activation-key update --organization="$ORG" --name="el7base-${uuid}" --release-version='7Server' --service-level='Standard' --auto-attach=0
    hammer hostgroup create --query-organization="$ORG" --organizations="$ORG" --locations="$LOC" \
      --architecture='x86_64' --content-source-id=1 --puppet-ca-proxy-id=1 --puppet-proxy-id=1 \
      --domain="$DOMAIN" --realm="$REALM" --subnet="$SUBNET_NAME" \
      --medium='RHEL 7.5 Kickstart' --pxe-loader='PXELinux BIOS' \
      --lifecycle-environment='UnStaged' --operatingsystem='RedHat 7.5' --partition-table='Kickstart default' \
      --root-pass="$HOST_PASSWORD" --puppet-classes='ssh::server,ntp'  --content-view='RHEL7_Base' \
      --environment="KT_${ORG}_unstaged_rhel7_base_2" --name='RHEL7_Base'
    hammer hostgroup set-parameter --hostgroup='RHEL7_Base' --name='kt_activation_keys' --value="el7base-${uuid}"
    hammer hostgroup set-parameter --hostgroup='RHEL7_Base' --name='enable-puppet4' --value='true'

    if [ $PREPARE_CAPSULE = 'true' ]; then
        CAPSULE_Sub_ID=$(hammer --output='csv' subscription list --organization=$ORG --search='Red Hat Satellite Capsule Server' | tail -n+2 | head -n1 | cut -d',' -f1)
        uuid=$(uuidgen)
        hammer activation-key create --organization="$ORG" --name="cap63-${uuid}" --max-hosts=2 --lifecycle-environment='UnStaged' --content-view='inf-capsule'
        hammer activation-key add-subscription --organization="$ORG" --name="cap63-${uuid}" --subscription-id="$PuppetForge_Sub_ID" 
        hammer activation-key add-subscription --organization="$ORG" --name="cap63-${uuid}" --subscription-id="$RHEL_Sub_ID" 
        hammer activation-key add-subscription --organization="$ORG" --name="cap63-${uuid}" --subscription-id="$CAPSULE_Sub_ID" 
        hammer activation-key content-override --organization="$ORG" --name="cap63-${uuid}" --content-label='rhel-7-server-satellite-tools-6.5-rpms' --value=1
        hammer activation-key content-override --organization="$ORG" --name="cap63-${uuid}" --content-label='rhel-7-server-satellite-tools-6.5-puppet4-rpms' --value=1
        hammer activation-key content-override --organization="$ORG" --name="cap63-${uuid}" --content-label='rhel-7-server-satellite-capsule-6.5-rpms' --value=1
        hammer activation-key content-override --organization="$ORG" --name="cap63-${uuid}" --content-label='rhel-server-rhscl-7-rpms' --value=1
        hammer activation-key update --organization="$ORG" --name="cap63-${uuid}" --release-version='7Server' --service-level='Standard' --auto-attach=0
        environment=$(hammer --output=csv environment list --search='unstaged_inf_capsule' --puppet-class='stdlib' | tail -n+2 | head -n1 | cut -d',' -f2)
        hammer hostgroup create --query-organization="$ORG" --organizations="$ORG" --locations="$LOC" \
          --architecture='x86_64' --content-source-id=1 --puppet-ca-proxy-id=1 --puppet-proxy-id=1 \
          --domain="$DOMAIN" --realm="$REALM" --subnet="$SUBNET_NAME" \
          --medium='RHEL 7.5 Kickstart' --pxe-loader='PXELinux BIOS' \
          --lifecycle-environment='UnStaged' --operatingsystem='RedHat 7.5' --partition-table='Kickstart default' \
          --root-pass="$HOST_PASSWORD" --puppet-classes='ssh::server,ntp'  --content-view='inf-capsule' \
          --environment="${environment}" --name='inf-capsule'
        hammer hostgroup set-parameter --hostgroup='inf-capsule' --name='kt_activation_keys' --value="cap63-${uuid}"
        hammer hostgroup set-parameter --hostgroup='inf-capsule' --name='enable-puppet4' --value='true'
    fi

    hammer activation-key create --organization="$ORG" --name='inf-builder-rhel7' --max-hosts=5 --lifecycle-environment='UnStaged' --content-view='inf-builder-rhel7'
    hammer activation-key add-subscription --organization="$ORG" --name='inf-builder-rhel7' --subscription-id="$PuppetForge_Sub_ID" 
    hammer activation-key add-subscription --organization="$ORG" --name='inf-builder-rhel7' --subscription-id="$RHEL_Sub_ID" 
    hammer activation-key add-subscription --organization="$ORG" --name='inf-builder-rhel7' --subscription-id="$ORG_Sub_ID" 
    hammer activation-key add-subscription --organization="$ORG" --name='inf-builder-rhel7' --subscription-id="$EPEL_Sub_ID" 
    hammer activation-key add-subscription --organization="$ORG" --name='inf-builder-rhel7' --subscription-id="$Maven_Sub_ID" 
    hammer activation-key add-subscription --organization="$ORG" --name='inf-builder-rhel7' --subscription-id="$JBoss_Sub_ID" 
    hammer activation-key content-override --organization="$ORG" --name='inf-builder-rhel7' --content-label='rhel-7-server-satellite-tools-6.5-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-builder-rhel7' --content-label='rhel-7-server-satellite-tools-6.5-puppet4-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-builder-rhel7' --content-label='rhel-server-rhscl-7-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-builder-rhel7' --content-label='rhel-7-server-optional-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-builder-rhel7' --content-label='rhel-7-server-supplementary-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-builder-rhel7' --content-label='rhel-7-server-rh-common-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-builder-rhel7' --content-label='jb-eap-7-for-rhel-7-server-rpms' --value=1
    hammer activation-key update --organization="$ORG" --name='inf-builder-rhel7' --release-version='7Server' --service-level='Standard' --auto-attach=0
    environment=$(hammer --output=csv environment list --search='unstaged_inf_builder_rhel7' --puppet-class='stdlib' | tail -n+2 | head -n1 | cut -d',' -f2)
    hammer hostgroup create --query-organization="$ORG" --organizations="$ORG" --locations="$LOC" \
      --architecture='x86_64' --content-source-id=1 --puppet-ca-proxy-id=1 --puppet-proxy-id=1 \
      --domain="$DOMAIN" --realm="$REALM" --subnet="$SUBNET_NAME" \
      --medium='RHEL 7.5 Kickstart' --pxe-loader='PXELinux BIOS' \
      --lifecycle-environment='UnStaged' --operatingsystem='RedHat 7.5' --partition-table='Kickstart default' \
      --root-pass="$HOST_PASSWORD" --puppet-classes='ssh::server,ntp,buildhost'  --content-view='inf-builder-rhel7' \
      --environment="$environment" --name='inf-builder-rhel7'
    hammer hostgroup set-parameter --hostgroup='inf-builder-rhel7' --name='kt_activation_keys' --value='inf-builder-rhel7'
    hammer hostgroup set-parameter --hostgroup='inf-builder-rhel7' --name='enable-puppet4' --value='true'

    hammer activation-key create --organization="$ORG" --name='inf-hypervisor-rhel7' --max-hosts=5 --lifecycle-environment='UnStaged' --content-view='inf-hypervisor-rhel7'
    hammer activation-key add-subscription --organization="$ORG" --name='inf-hypervisor-rhel7' --subscription-id="$PuppetForge_Sub_ID" 
    hammer activation-key add-subscription --organization="$ORG" --name='inf-hypervisor-rhel7' --subscription-id="$RHEV_Sub_ID" 
    hammer activation-key add-subscription --organization="$ORG" --name='inf-hypervisor-rhel7' --subscription-id="$RHEL_Sub_ID" 
    hammer activation-key content-override --organization="$ORG" --name='inf-hypervisor-rhel7' --content-label='rhel-7-server-satellite-tools-6.5-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-hypervisor-rhel7' --content-label='rhel-7-server-satellite-tools-6.5-puppet4-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-hypervisor-rhel7' --content-label='rhel-server-rhscl-7-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-hypervisor-rhel7' --content-label='rhel-7-server-rhev-mgmt-agent-rpms' --value=1
    hammer activation-key update --organization="$ORG" --name='inf-hypervisor-rhel7' --release-version='7Server' --service-level='Standard' --auto-attach=0
    environment=$(hammer --output=csv environment list --search='unstaged_inf_hypervisor_rhel7' --puppet-class='stdlib' | tail -n+2 | head -n1 | cut -d',' -f2)
    hammer hostgroup create --query-organization="$ORG" --organizations="$ORG" --locations="$LOC" \
      --architecture='x86_64' --content-source-id=1 --puppet-ca-proxy-id=1 --puppet-proxy-id=1 \
      --domain="$DOMAIN" --realm="$REALM" --subnet="$SUBNET_NAME" \
      --medium='RHEL 7.5 Kickstart' --pxe-loader='PXELinux BIOS' \
      --lifecycle-environment='UnStaged' --operatingsystem='RedHat 7.5' --partition-table='Kickstart default' \
      --root-pass="$HOST_PASSWORD" --puppet-classes='ssh::server,ntp'  --content-view='inf-hypervisor-rhel7' \
      --environment="$environment" --name='inf-hypervisor-rhel7'
    hammer hostgroup set-parameter --hostgroup='inf-hypervisor-rhel7' --name='kt_activation_keys' --value='inf-hypervisor-rhel7'
    hammer hostgroup set-parameter --hostgroup='inf-hypervisor-rhel7' --name='enable-puppet4' --value='true'

    hammer activation-key create --organization="$ORG" --name='inf-git-rhel7' --max-hosts=5 --lifecycle-environment='UnStaged' --content-view='inf-git-rhel7'
    hammer activation-key add-subscription --organization="$ORG" --name='inf-git-rhel7' --subscription-id="$PuppetForge_Sub_ID" 
    hammer activation-key add-subscription --organization="$ORG" --name='inf-git-rhel7' --subscription-id="$RHEL_Sub_ID" 
    hammer activation-key add-subscription --organization="$ORG" --name='inf-git-rhel7' --subscription-id="$ORG_Sub_ID" 
    hammer activation-key add-subscription --organization="$ORG" --name='inf-git-rhel7' --subscription-id="$EPEL_Sub_ID" 
    hammer activation-key content-override --organization="$ORG" --name='inf-git-rhel7' --content-label='rhel-7-server-satellite-tools-6.5-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-git-rhel7' --content-label='rhel-7-server-satellite-tools-6.5-puppet4-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-git-rhel7' --content-label='rhel-server-rhscl-7-rpms' --value=1
    hammer activation-key update --organization="$ORG" --name='inf-git-rhel7' --release-version='7Server' --service-level='Standard' --auto-attach=0
    environment=$(hammer --output=csv environment list --search='unstaged_inf_git_rhel7' --puppet-class='stdlib' | tail -n+2 | head -n1 | cut -d',' -f2)
    hammer hostgroup create --query-organization="$ORG" --organizations="$ORG" --locations="$LOC" \
      --architecture='x86_64' --content-source-id=1 --puppet-ca-proxy-id=1 --puppet-proxy-id=1 \
      --domain="$DOMAIN" --realm="$REALM" --subnet="$SUBNET_NAME" \
      --medium='RHEL 7.5 Kickstart' --pxe-loader='PXELinux BIOS' \
      --lifecycle-environment='UnStaged' --operatingsystem='RedHat 7.5' --partition-table='Kickstart default' \
      --root-pass="$HOST_PASSWORD" --puppet-classes='ssh::server,ntp,git::server'  --content-view='inf-git-rhel7' \
      --environment="$environment" --name='inf-git-rhel7'
    hammer hostgroup set-parameter --hostgroup='inf-git-rhel7' --name='kt_activation_keys' --value='inf-git-rhel7'
    hammer hostgroup set-parameter --hostgroup='inf-git-rhel7' --name='enable-puppet4' --value='true'

    hammer activation-key create --organization="$ORG" --name='inf-docker-rhel7' --max-hosts=5 --lifecycle-environment='UnStaged' --content-view='inf-docker-rhel7'
    hammer activation-key add-subscription --organization="$ORG" --name='inf-docker-rhel7' --subscription-id="$PuppetForge_Sub_ID" 
    hammer activation-key add-subscription --organization="$ORG" --name='inf-docker-rhel7' --subscription-id="$RHEL_Sub_ID" 
    hammer activation-key add-subscription --organization="$ORG" --name='inf-docker-rhel7' --subscription-id="$ORG_Sub_ID" 
    hammer activation-key add-subscription --organization="$ORG" --name='inf-docker-rhel7' --subscription-id="$EPEL_Sub_ID" 
    hammer activation-key add-subscription --organization="$ORG" --name='inf-docker-rhel7' --subscription-id="$JBoss_Sub_ID" 
    hammer activation-key add-subscription --organization="$ORG" --name='inf-docker-rhel7' --subscription-id="$OSCP_Sub_ID" 
    hammer activation-key content-override --organization="$ORG" --name='inf-docker-rhel7' --content-label='rhel-7-server-satellite-tools-6.5-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-docker-rhel7' --content-label='rhel-7-server-satellite-tools-6.5-puppet4-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-docker-rhel7' --content-label='rhel-server-rhscl-7-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-docker-rhel7' --content-label='rhel-7-server-optional-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-docker-rhel7' --content-label='rhel-7-server-extras-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-docker-rhel7' --content-label='rhel-7-server-supplementary-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-docker-rhel7' --content-label='rhel-7-server-rh-common-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-docker-rhel7' --content-label='jb-eap-7-for-rhel-7-server-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-docker-rhel7' --content-label='rhel-7-server-ose-3.2-rpms' --value=1
    hammer activation-key update --organization="$ORG" --name='inf-docker-rhel7' --release-version='7Server' --service-level='Standard' --auto-attach=0
    environment=$(hammer --output=csv environment list --search='unstaged_inf_docker_rhel7' --puppet-class='stdlib' | tail -n+2 | head -n1 | cut -d',' -f2)
    hammer hostgroup create --query-organization="$ORG" --organizations="$ORG" --locations="$LOC" \
      --architecture='x86_64' --content-source-id=1 --puppet-ca-proxy-id=1 --puppet-proxy-id=1 \
      --domain="$DOMAIN" --realm="$REALM" --subnet="$SUBNET_NAME" \
      --medium='RHEL 7.5 Kickstart' --pxe-loader='PXELinux BIOS' \
      --lifecycle-environment='UnStaged' --operatingsystem='RedHat 7.5' --partition-table='Kickstart default' \
      --root-pass="$HOST_PASSWORD" --puppet-classes='ssh::server,ntp,dockerhost'  --content-view='inf-docker-rhel7' \
      --environment="$environment" --name='inf-docker-rhel7'
    hammer hostgroup set-parameter --hostgroup='inf-docker-rhel7' --name='kt_activation_keys' --value='inf-docker-rhel7'
    hammer hostgroup set-parameter --hostgroup='inf-docker-rhel7' --name='enable-puppet4' --value='true'

    hammer activation-key create --organization="$ORG" --name='inf-oscp-rhel7' --max-hosts=5 --lifecycle-environment='UnStaged' --content-view='inf-oscp-rhel7'
    hammer activation-key add-subscription --organization="$ORG" --name='inf-oscp-rhel7' --subscription-id="$PuppetForge_Sub_ID" 
    hammer activation-key add-subscription --organization="$ORG" --name='inf-oscp-rhel7' --subscription-id="$RHEL_Sub_ID" 
    hammer activation-key add-subscription --organization="$ORG" --name='inf-oscp-rhel7' --subscription-id="$ORG_Sub_ID" 
    hammer activation-key add-subscription --organization="$ORG" --name='inf-oscp-rhel7' --subscription-id="$EPEL_Sub_ID" 
    hammer activation-key add-subscription --organization="$ORG" --name='inf-oscp-rhel7' --subscription-id="$JBoss_Sub_ID" 
    hammer activation-key add-subscription --organization="$ORG" --name='inf-oscp-rhel7' --subscription-id="$OSCP_Sub_ID" 
    hammer activation-key content-override --organization="$ORG" --name='inf-oscp-rhel7' --content-label='rhel-7-server-satellite-tools-6.5-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-oscp-rhel7' --content-label='rhel-7-server-satellite-tools-6.5-puppet4-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-oscp-rhel7' --content-label='rhel-server-rhscl-7-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-oscp-rhel7' --content-label='rhel-7-server-optional-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-oscp-rhel7' --content-label='rhel-7-server-extras-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-oscp-rhel7' --content-label='rhel-7-server-supplementary-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-oscp-rhel7' --content-label='rhel-7-server-rh-common-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-oscp-rhel7' --content-label='jb-eap-7-for-rhel-7-server-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-oscp-rhel7' --content-label='rhel-7-server-ose-3.2-rpms' --value=1
    hammer activation-key update --organization="$ORG" --name='inf-oscp-rhel7' --release-version='7Server' --service-level='Standard' --auto-attach=0
    environment=$(hammer --output=csv environment list --search='unstaged_inf_oscp' --puppet-class='stdlib' | tail -n+2 | head -n1 | cut -d',' -f2)
    hammer hostgroup create --query-organization="$ORG" --organizations="$ORG" --locations="$LOC" \
      --architecture='x86_64' --content-source-id=1 --puppet-ca-proxy-id=1 --puppet-proxy-id=1 \
      --domain="$DOMAIN" --realm="$REALM" --subnet="$SUBNET_NAME" \
      --medium='RHEL 7.5 Kickstart' --pxe-loader='PXELinux BIOS' \
      --lifecycle-environment='UnStaged' --operatingsystem='RedHat 7.5' --partition-table='Kickstart default' \
      --root-pass="$HOST_PASSWORD" --puppet-classes='ssh::server,ntp,oscp'  --content-view='inf-oscp-rhel7' \
      --environment="$environment" --name='inf-oscp-rhel7'
    hammer hostgroup set-parameter --hostgroup='inf-oscp-rhel7' --name='kt_activation_keys' --value='inf-oscp-rhel7'
    hammer hostgroup set-parameter --hostgroup='inf-oscp-rhel7' --name='enable-puppet4' --value='true'

    hammer activation-key create --organization="$ORG" --name='inf-ipa-rhel7' --max-hosts=5 --lifecycle-environment='UnStaged' --content-view='inf-ipa-rhel7'
    hammer activation-key add-subscription --organization="$ORG" --name='inf-ipa-rhel7' --subscription-id="$PuppetForge_Sub_ID" 
    hammer activation-key add-subscription --organization="$ORG" --name='inf-ipa-rhel7' --subscription-id="$RHEL_Sub_ID" 
    hammer activation-key add-subscription --organization="$ORG" --name='inf-ipa-rhel7' --subscription-id="$EPEL_Sub_ID" 
    hammer activation-key content-override --organization="$ORG" --name='inf-ipa-rhel7' --content-label='rhel-7-server-satellite-tools-6.5-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-ipa-rhel7' --content-label='rhel-7-server-satellite-tools-6.5-puppet4-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name='inf-ipa-rhel7' --content-label='rhel-server-rhscl-7-rpms' --value=1
    hammer activation-key update --organization="$ORG" --name='inf-ipa-rhel7' --release-version='7Server' --service-level='Standard' --auto-attach=0
    environment=$(hammer --output=csv environment list --search='unstaged_inf_ipa_rhel7' --puppet-class='stdlib' | tail -n+2 | head -n1 | cut -d',' -f2)
    hammer hostgroup create --query-organization="$ORG" --organizations="$ORG" --locations="$LOC" \
      --architecture='x86_64' --content-source-id=1 --puppet-ca-proxy-id=1 --puppet-proxy-id=1 \
      --domain="$DOMAIN" --realm="$REALM" --subnet="$SUBNET_NAME" \
      --medium='RHEL 7.5 Kickstart' --pxe-loader='PXELinux BIOS' \
      --lifecycle-environment='UnStaged' --operatingsystem='RedHat 7.5' --partition-table='Kickstart default' \
      --root-pass="$HOST_PASSWORD" --puppet-classes='ssh::server,ntp'  --content-view='inf-ipa-rhel7' \
      --partition-table='Kickstart Docker' --environment="$environment" --name='inf-ipa-rhel7'
    hammer hostgroup set-parameter --hostgroup='inf-ipa-rhel7' --name='kt_activation_keys' --value='inf-ipa-rhel7'
    hammer hostgroup set-parameter --hostgroup='inf-ipa-rhel7' --name='enable-puppet4' --value='true'

    if [ $RHEL6_CONTENT = 'true' ]; then
        hammer activation-key create --organization="$ORG" --name='RHEL6_Base' --unlimited-hosts --lifecycle-environment='UnStaged' --content-view='RHEL6_Base'
        hammer activation-key add-subscription --organization="$ORG" --name='RHEL6_Base' --subscription-id="$PuppetForge_Sub_ID" 
        hammer activation-key add-subscription --organization="$ORG" --name='RHEL6_Base' --subscription-id="$RHEL_Sub_ID" 
        hammer activation-key content-override --organization="$ORG" --name='RHEL6_Base' --content-label='rhel-6-server-satellite-tools-6.5-rpms' --value=1
        hammer activation-key update --organization="$ORG" --name='RHEL6_Base' --release-version='6Server' --service-level='Standard' --auto-attach=0
        environment=$(hammer --output=csv environment list --search='unstaged_rhel6_base' --puppet-class='stdlib' | tail -n+2 | head -n1 | cut -d',' -f2)
        hammer hostgroup create --query-organization="$ORG" --organizations="$ORG" --locations="$LOC" \
          --architecture='x86_64' --content-source-id=1 --puppet-ca-proxy-id=1 --puppet-proxy-id=1 \
          --domain="$DOMAIN" --realm="$REALM" --subnet="$SUBNET_NAME" \
          --medium='RHEL 6.9 Kickstart' --pxe-loader='PXELinux BIOS' \
          --lifecycle-environment='UnStaged' --operatingsystem='RedHat 6.9' --partition-table='Kickstart default' \
          --root-pass="$HOST_PASSWORD" --puppet-classes='ssh::server,ntp'  --content-view='RHEL6_Base' \
          --environment="$environment" --name='RHEL6_Base'
        hammer hostgroup set-parameter --hostgroup='RHEL6_Base' --name='kt_activation_keys' --value='RHEL6_Base'
        hammer hostgroup set-parameter --hostgroup='RHEL6_Base' --name='enable-puppet4' --value='true'
    fi


    param_id=$(hammer --output=csv sc-param list --puppet-class='ssh::server' --search='options' | tail -n+2 | head -n1 | cut -d',' -f1)
    hammer sc-param update --puppet-class='ssh::server' --override=1 --id=$param_id \
        --default-value='{ "PermitRootLogin": false, "Protocol": 2, "UsePrivilegeSeparation": "sandbox", "SyslogFacility": "AUTHPRIV", "AuthorizedKeysFile": ".ssh/authorized_keys", "PasswordAuthentication": true, "GSSAPICleanupCredentials": false, "KerberosAuthentication": false, "PubkeyAuthentication": true, "GSSAPIAuthentication": true, "AuthorizedKeysCommand": "/usr/bin/sss_ssh_authorizedkeys", "AuthorizedKeysCommandUser": "nobody" }' \
        --override-value-order='operatingsystemmajrelease,fqdn,hostgroup,os,domain'
    hammer sc-param add-override-value --puppet-class='ssh::server' --smart-class-parameter-id=$param_id --match='operatingsystemmajrelease=6' \
        --value='{ "PermitRootLogin": false, "Protocol": 2, "SyslogFacility": "AUTHPRIV", "AuthorizedKeysFile": ".ssh/authorized_keys", "PasswordAuthentication": true, "GSSAPICleanupCredentials": false, "KerberosAuthentication": false, "PubkeyAuthentication": true, "GSSAPIAuthentication": true, "AuthorizedKeysCommand": "/usr/bin/sss_ssh_authorizedkeys" }'

    param_id=$(hammer --output=csv sc-param list --puppet-class='buildhost' --search='deploy_demo' | tail -n+2 | head -n1 | cut -d',' -f1)
    hammer sc-param update --puppet-class='buildhost' --override=1 --id=$param_id \
        --default-value='false'
    param_id=$(hammer --output=csv sc-param list --puppet-class='buildhost' --search='ci_git_host' | tail -n+2 | head -n1 | cut -d',' -f1)
    hammer sc-param update --puppet-class='buildhost' --override=1 --id=$param_id \
        --default-value="${HOST_PREFIX}-git.${DOMAIN}"
    param_id=$(hammer --output=csv sc-param list --puppet-class='buildhost' --search='ci_target_env' | tail -n+2 | head -n1 | cut -d',' -f1)
    hammer sc-param update --puppet-class='buildhost' --override=1 --id=$param_id \
        --default-value=2
fi
# END activation key and hostgroup setup

    if [ $CONFIGURE_RHEV_RESOURCE = 'true' ]; then
        if [ $RHV_VERSION_4 = 'true' ]; then
            read -p "

Manual action required!

    To proceed, you need to manually add the ca.crt for the RHV compute resource.
    
    Download the RHV rhvm.crt with
    curl -o rhvm.crt http://${COMPUTE_RES_FQDN}/ovirt-engine/services/pki-resource?resource=ca-certificate&format=X509-PEM-CA
    
    Log into your Satellite-6.5 as admin and go to Infrastructure->Compute Resources.
    Paste the content of the downloaded rhvm.crt into the X509 Certification Authorities field.


    Hit Enter after the certificate is stored." answer
        fi
    fi

    if [ $CONFIGURE_LIBVIRT_RESOURCE = 'true' ]; then
        read -p "

        Manual action required!

        To proceed you need to manually add /usr/share/foreman/.ssh/id_rsa.pub to root@${COMPUTE_RES_FQDN}:.ssh/authorized_keys

        Hit Enter after the key has been authorized." answer
    fi

    read -p "

Manual action required!

    To proceed you need to manually adjust Compute Profiles.
    Log into your Satellite-6.5 as admin and go to Infrastructure->Compute Profiles.
    Go through all profile sizes and make sure the network interfaces are correctly selected for the Satellite subnet.

    Hit Enter after all Compute Profiles are set up correctly." answer

    read -p "

Manual action required!

    To proceed you may need to fix realm settings.
    Edit /etc/foreman-proxy/settings.d/realm_freeipa.yml
    and make sure it reads
    :principal: realm-proxy@${REALM}

    In case you need to edit the file, you also need to restart Satellite

    katello-service restart

    Hit Enter after realm settings are verified to be correct." answer


# Check your kickstart-network-setup snippet and check if you need to adjust for your
# network setup. The following lines may serve as an example:
# sed -ri 's/^PEERDNS=yes/PEERDNS=no/' /etc/sysconfig/network-scripts/ifcfg-eth1
# sed -ri 's/^ONBOOT=no/ONBOOT=yes/' /etc/sysconfig/network-scripts/ifcfg-eth1
# echo "DEFROUTE=no" >>/etc/sysconfig/network-scripts/ifcfg-eth0
# systemctl restart network

hammer host create --organization="$ORG" --location="$LOC" --compute-resource="$COMPUTE_RES_NAME" --compute-profile='1-Small' --hostgroup='RHEL7_Base' --name="${HOST_PREFIX}-rhel7std01"
hammer host start --name="${HOST_PREFIX}-rhel7std01.${DOMAIN}"
hammer host create --organization="$ORG" --location="$LOC" --compute-resource="$COMPUTE_RES_NAME" --compute-profile='2-Medium' --hostgroup='inf-git-rhel7' --name="${HOST_PREFIX}-git"
hammer host start --name="${HOST_PREFIX}-git.${DOMAIN}"
hammer host create --organization="$ORG" --location="$LOC" --compute-resource="$COMPUTE_RES_NAME" --compute-profile='2-Medium' --hostgroup='inf-docker-rhel7' --name="${HOST_PREFIX}-docker01"
hammer host start --name="${HOST_PREFIX}-docker01.${DOMAIN}"
hammer host create --organization="$ORG" --location="$LOC" --compute-resource="$COMPUTE_RES_NAME" --compute-profile='3-Large' --hostgroup='inf-builder-rhel7' --name="${HOST_PREFIX}-build01"
hammer host start --name="${HOST_PREFIX}-build01.${DOMAIN}"

