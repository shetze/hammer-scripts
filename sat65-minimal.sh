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
exit 0

set -x
set -e
longname=$(hostname | tr '.' '_')

# scp Satellite_65_Generated_July_16_2019.zip root@satellite65.example.com:/tmp
# scp sat65-setup.sh root@satellite65.example.com:

# The script is built such that the preparation steps can be skipped if later stages need to be extended or repeated.
# The higher the STAGE Level is, the more preparation steps are skipped.
# STAGE Level:
# 1 = preqequisite preparation
# 2 = Satellite 6 installation
# 3 = environment setup
# 4 = basic content view creation
# 5 = content sync
# 6 = content view customizing and promotion
# 7 = activation key, hostgroup setup, sc_params
# 8 = creation of example hosts
export STAGE=1

# This demo setup is built with IPA integration as one important feature to show.
# While it is possible to use IPA and leave Satellite with the self signed internal CA cert,
# it is recommended to demonstrate/test this feature as well.
# The IPA_EXT_CERT switch is mainly offered for debugging purposes.
export IPA_EXT_CERT=false

# You may also use another exteral CA to provide Satellite with a signed certificate
export CUST_EXT_CERT=true



# Product / Repo List and Mapping
# CSV Fields:
# Index ; Priority ; CV-Mapping ; Repo-Name ; Prod-Name ; Prod-Family ; Architecture ; Release-Version

# Priority selects products based on a decimal encoded bit matrix. Essential
# content has assigned priority bit 1. All additional product selections are
# triggered by the appropriate bits in the priority value.


ESSENTIAL_CONTENT=1
RHEL8_CONTENT=2
RHEL7_CONTENT=4
RHEL6_CONTENT=8
MISC_CONTENT=16
DEV_CONTENT=32
JBOSS_CONTENT=64
EXT_CONTENT=128
OSCP_CONTENT=256
OSE_CONTENT=512
RHV_CONTENT=1024


export CONTENT_MASK=$((ESSENTIAL_CONTENT + RHEL6_CONTENT + RHEL7_CONTENT + RHEL8_CONTENT))

# CV-Mapping assigns products to Content Views based on a decimal encoded bit matrix.

# CV_RHEL7_Base=1
# CV_inf_capsule=2
# CV_inf_ipa_rhel7=4
# CV_inf_hypervisor_rhel7=8
# CV_inf_builder_rhel7=16
# CV_inf_oscp_rhel7=32
# CV_inf_eap_rhel7=64
# CV_inf_docker_rhel7=128
# CV_inf_git_rhel7=256
# CV_RHEL6_Base=512
# CV_RHEL8_Base=1024
# CV_RHEL8_Ext=2048
# CV_puppet_fasttrack=4096

CV_array=(RHEL7-Base RHEL6-Base RHEL8-Base RHEL8-Ext)


# The following block of parameters needs to reflect your environment.
# Most of the parameters are used with the satellite-installer
# The purpose should be pretty much self explanatory. In doubt, look at 'satellite-installer --help'
export ORG="BSS_SM"
export LOC="WDF"
export ADMIN=admin
export ADMIN_PASSWORD=$(pwmake 64)
export CUST_CA_CERT=/root/certs/bundle.crt
export CUST_CERT_KEY=/root/certs/$(hostname -s)_key.pem
export CUST_CERT_CSR=/root/certs/$(hostname -s)_csr.pem
export CUST_CERT=/root/certs/$(hostname -s).crt

# This is a Sat6 manifest. Replace with your custom manifest.
export MANIFEST=/tmp/Satellite_65_Generated_July_16_2019.zip

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

    # mkdir -p /usr/share/foreman/.ssh
    # ssh-keygen -f /usr/share/foreman/.ssh/id_rsa -t rsa -N ''
    # chown -R foreman.foreman /usr/share/foreman/.ssh

    mkdir -p /root/.hammer
    cat > /root/.hammer/cli_config.yml <<EOF
:foreman:
    :host: 'https://$(hostname)/'
    :username: '$ADMIN'
    :password: '$ADMIN_PASSWORD'
    :request_timeout: -1
EOF

    if [ $CUST_EXT_CERT = 'true' ]; then
        katello-certs-check \
          -b ${CUST_CA_CERT} \
          -k ${CUST_CERT_KEY} \
          -c ${CUST_CERT}
        CERT_ARGS="--certs-server-ca-cert=${CUST_CA_CERT} \
               --certs-server-key=${CUST_CERT_KEY} \
               --certs-server-cert=${CUST_CERT} \
               --certs-server-cert-req=${CUST_CERT_CSR}"
        cp ${CUST_CA_CERT} /etc/pki/ca-trust/source/anchors/
    fi
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

    update-ca-trust enable
    update-ca-trust

    time satellite-installer --scenario satellite -v \
      --foreman-admin-password=$ADMIN_PASSWORD \
      --foreman-admin-username=$ADMIN \
      --foreman-initial-organization=$ORG \
      --foreman-initial-location=$LOC \
      --enable-foreman-plugin-openscap \
      ${CERT_ARGS}

    hammer settings set --name default_download_policy --value on_demand
    hammer subscription upload --organization "$ORG" --file ${MANIFEST}
    hammer subscription refresh-manifest --organization "$ORG"
fi
# END installation

# BEGIN environment setup
if [ $STAGE -le 3 ]; then
    hammer lifecycle-environment create --organization "$ORG" --description 'Development' --name 'Development' --label development --prior Library
    hammer lifecycle-environment create --organization "$ORG" --description 'Test' --name 'Test' --label test --prior 'Development'
    hammer lifecycle-environment create --organization "$ORG" --description 'Production' --name 'Production' --label production --prior 'Test'
    hammer lifecycle-environment create --organization "$ORG" --description 'Latest packages without staging' --name 'UnStaged' --label unstaged --prior Library

    hammer domain update --id 1 --organizations "$ORG" --locations "$LOC"

fi
# END environment setup

# BEGIN basic content view creation
if [ $STAGE -le 4 ]; then
    for index in ${!CV_array[*]}
    do
        LABEL=$(echo ${CV_array[$index]} | tr '[:upper:]' '[:lower:]')
        hammer content-view create --organization "$ORG" --name "${CV_array[$index]}" --label "$LABEL" --description "Installer Provided Content View $LABEL" 
    done
fi
# END content view setup

BIFS=$IFS
IFS=';'
function init_repo {
	index=$1
	prio_map=$2
	cv_map=$3
	repo_name=$4
	prod_name=$5
	product=$6
	arch=$7
	releasever=$8
	policy=$9
	priority=${10}

	if [[ $index == \#* ]]; then return 0; fi

	include='true'
	for bit in 1 2 4 8 16 32 64 128 256 512 1024 2048 4096
	do
		map_mask=$(( prio_map & bit ))
		prio_mask=$(( priority & bit ))
		if [ $map_mask -gt 0 -a $prio_mask -eq 0 ]
		then
		        include='false'
		fi
		
	done
	if [ $include = 'true' ]
	then
		if [ ${releasever} != '000' ]
		then
		    release_opt="--releasever=${releasever}"
		else
		    release_opt=""
		fi
    		hammer repository-set enable --organization "$ORG" --product "${product}" --basearch="${arch}" ${release_opt} --name "${prod_name}"
    		hammer repository update --organization "$ORG" --product "${product}" --name "${repo_name}" --download-policy "${policy}"
    		time hammer repository synchronize --organization "$ORG" --product "${product}"  --name  "${repo_name}"
		for idx in ${!CV_array[*]}
		do
		    bit=$((2**idx))
		    if [ $(( cv_map & bit )) -gt 0 ]
			then
        		    hammer content-view add-repository --organization "$ORG" --name "${CV_array[$idx]}" --product "${product}" --repository "${repo_name}"
		    fi
		done
	else
	    echo Excluded in prio $priority: $prio_map [$index] $repo_name
	fi


}


# BEGIN content sync
# Sync of Red Hat RPM packages adds up to ~160GB of disk space in /var and takes ~ 24hours to finish
if [ $STAGE -le 5 ]; then
    date

while read -r line
do
	IFS=';' init_repo $line $CONTENT_MASK 
done <<EOF
1;68;0;JBoss Enterprise Application Platform 6 RHEL 7 Server RPMs x86_64 7Server;JBoss Enterprise Application Platform 6 (RHEL 7 Server) (RPMs);JBoss Enterprise Application Platform;x86_64;7Server;on_demand
2;68;64;JBoss Enterprise Application Platform 7 RHEL 7 Server RPMs x86_64 7Server;JBoss Enterprise Application Platform 7 (RHEL 7 Server) (RPMs);JBoss Enterprise Application Platform;x86_64;7Server;on_demand
3;36;0;Red Hat Ceph Storage Installer 1.3 for Red Hat Enterprise Linux 7 Server RPMs x86_64 7Server;Red Hat Ceph Storage Installer 1.3 for Red Hat Enterprise Linux 7 Server (RPMs);Red Hat Ceph Storage;x86_64;7Server;on_demand
4;36;0;Red Hat Ceph Storage Tools 1.3 for Red Hat Enterprise Linux 7 Server RPMs x86_64 7Server;Red Hat Ceph Storage Tools 1.3 for Red Hat Enterprise Linux 7 Server (RPMs);Red Hat Enterprise Linux Server;x86_64;7Server;on_demand
5;136;0;Red Hat Enterprise Linux 6 Server - Extras RPMs x86_64;Red Hat Enterprise Linux 6 Server - Extras (RPMs);Red Hat Enterprise Linux Server;x86_64;000;immediate
6;9;512;Red Hat Enterprise Linux 6 Server Kickstart x86_64 6.9;Red Hat Enterprise Linux 6 Server (Kickstart);Red Hat Enterprise Linux Server;x86_64;6.9;immediate
7;40;0;Red Hat Enterprise Linux 6 Server - Optional RPMs x86_64 6Server;Red Hat Enterprise Linux 6 Server - Optional (RPMs);Red Hat Enterprise Linux Server;x86_64;6Server;immediate
8;136;0;Red Hat Enterprise Linux 6 Server - RH Common RPMs x86_64 6Server;Red Hat Enterprise Linux 6 Server - RH Common (RPMs);Red Hat Enterprise Linux Server;x86_64;6Server;on_demand
9;9;512;Red Hat Enterprise Linux 6 Server RPMs x86_64 6Server;Red Hat Enterprise Linux 6 Server (RPMs);Red Hat Enterprise Linux Server;x86_64;6Server;immediate
10;40;0;Red Hat Enterprise Linux 6 Server - Supplementary RPMs x86_64 6Server;Red Hat Enterprise Linux 6 Server - Supplementary (RPMs);Red Hat Enterprise Linux Server;x86_64;6Server;on_demand
11;132;0;Red Hat Enterprise Linux 7 Server - Extras RPMs x86_64;Red Hat Enterprise Linux 7 Server - Extras (RPMs);Red Hat Enterprise Linux Server;x86_64;000;on_demand
12;5;511;Red Hat Enterprise Linux 7 Server Kickstart x86_64 7.7;Red Hat Enterprise Linux 7 Server (Kickstart);Red Hat Enterprise Linux Server;x86_64;7.7;immediate
13;292;178;Red Hat Enterprise Linux 7 Server - Optional RPMs x86_64 7Server;Red Hat Enterprise Linux 7 Server - Optional (RPMs);Red Hat Enterprise Linux Server;x86_64;7Server;on_demand
14;36;16;Red Hat Enterprise Linux 7 Server - RH Common RPMs x86_64 7Server;Red Hat Enterprise Linux 7 Server - RH Common (RPMs);Red Hat Enterprise Linux Server;x86_64;7Server;on_demand
15;5;511;Red Hat Enterprise Linux 7 Server RPMs x86_64 7Server;Red Hat Enterprise Linux 7 Server (RPMs);Red Hat Enterprise Linux Server;x86_64;7Server;immediate
16;36;16;Red Hat Enterprise Linux 7 Server - Supplementary RPMs x86_64 7Server;Red Hat Enterprise Linux 7 Server - Supplementary (RPMs);Red Hat Enterprise Linux Server;x86_64;7Server;on_demand
17;260;32;Red Hat Enterprise Linux Atomic Host RPMs x86_64;Red Hat Enterprise Linux Atomic Host (RPMs);Red Hat Enterprise Linux Atomic Host;x86_64;000;on_demand
18;260;32;Red Hat OpenShift Container Platform 3.9 RPMs x86_64;Red Hat OpenShift Container Platform 3.9 (RPMs);Red Hat OpenShift Container Platform;x86_64;000;on_demand
19;516;0;Red Hat OpenStack Platform 8 director for RHEL 7 RPMs x86_64 7Server;Red Hat OpenStack Platform 8 director for RHEL 7 (RPMs);Red Hat OpenStack;x86_64;7Server;on_demand
20;516;0;Red Hat OpenStack Platform 8 for RHEL 7 RPMs x86_64 7Server;Red Hat OpenStack Platform 8 for RHEL 7 (RPMs);Red Hat OpenStack;x86_64;7Server;on_demand
21;516;0;Red Hat OpenStack Platform 8 Operational Tools for RHEL 7 RPMs x86_64 7Server;Red Hat OpenStack Platform 8 Operational Tools for RHEL 7 (RPMs);Red Hat OpenStack;x86_64;7Server;on_demand
22;516;0;Red Hat OpenStack Tools 7.0 for Red Hat Enterprise Linux 7 Server RPMs x86_64 7Server;Red Hat OpenStack Tools 7.0 for Red Hat Enterprise Linux 7 Server (RPMs);Red Hat Enterprise Linux Server;x86_64;7Server;on_demand
23;5;2;Red Hat Satellite 6.5 for RHEL 7 Server RPMs x86_64;Red Hat Satellite 6.5 (for RHEL 7 Server) (RPMs);Red Hat Satellite;x86_64;000;immediate
24;5;2;Red Hat Satellite Capsule 6.5 for RHEL 7 Server RPMs x86_64;Red Hat Satellite Capsule 6.5 (for RHEL 7 Server) (RPMs);Red Hat Satellite Capsule;x86_64;000;immediate
25;5;2;Red Hat Satellite Maintenance 6 for RHEL 7 Server RPMs x86_64;Red Hat Satellite Maintenance 6 (for RHEL 7 Server) (RPMs);Red Hat Enterprise Linux Server;x86_64;000;immediate
26;9;512;Red Hat Satellite Tools 6.5 for RHEL 6 Server RPMs x86_64;Red Hat Satellite Tools 6.5 (for RHEL 6 Server) (RPMs);Red Hat Enterprise Linux Server;x86_64;000;immediate
27;5;511;Red Hat Satellite Tools 6.5 for RHEL 7 Server RPMs x86_64;Red Hat Satellite Tools 6.5 (for RHEL 7 Server) (RPMs);Red Hat Enterprise Linux Server;x86_64;000;immediate
28;9;512;Red Hat Ansible Engine 2.6 RPMs for Red Hat Enterprise Linux 7 Server x86_64;Red Hat Ansible Engine 2.6 RPMs for Red Hat Enterprise Linux 7 Server;Red Hat Ansible Engine;x86_64;000;immediate
29;5;511;Red Hat Satellite Tools 6.3 - Puppet 4 for RHEL 7 Server RPMs x86_64;Red Hat Satellite Tools 6.3 - Puppet 4 (for RHEL 7 Server) (RPMs);Red Hat Enterprise Linux Server;x86_64;000;immediate
30;9;0;Red Hat Software Collections RPMs for Red Hat Enterprise Linux 6 Server x86_64 6Server;Red Hat Software Collections RPMs for Red Hat Enterprise Linux 6 Server;Red Hat Software Collections for RHEL Server;x86_64;6Server;on_demand
31;5;438;Red Hat Software Collections RPMs for Red Hat Enterprise Linux 7 Server x86_64 7Server;Red Hat Software Collections RPMs for Red Hat Enterprise Linux 7 Server;Red Hat Software Collections for RHEL Server;x86_64;7Server;on_demand
32;132;0;Red Hat Storage Native Client for RHEL 7 RPMs x86_64 7Server;Red Hat Storage Native Client for RHEL 7 (RPMs);Red Hat Enterprise Linux Server;x86_64;7Server;on_demand
33;132;0;Red Hat Virtualization 4 Management Agents for RHEL 7 RPMs x86_64 7Server;Red Hat Virtualization 4 Management Agents for RHEL 7 (RPMs);Red Hat Virtualization;x86_64;7Server;on_demand
34;1028;0;Red Hat Virtualization Host 7 RPMs x86_64;Red Hat Virtualization Host 7 (RPMs);Red Hat Virtualization Host;x86_64;000;on_demand
35;1028;0;Red Hat Virtualization Manager 4.0 RHEL 7 Server RPMs x86_64;Red Hat Virtualization Manager 4.0 (RHEL 7 Server) (RPMs);Red Hat Virtualization;x86_64;000;on_demand
36;3;3072;Red Hat Enterprise Linux 8 for x86_64 - BaseOS RPMs x86_64 8;Red Hat Enterprise Linux 8 for x86_64 - BaseOS (RPMs);Red Hat Enterprise Linux for x86_64;x86_64;8;immediate
37;3;3072;Red Hat Enterprise Linux 8 for x86_64 - BaseOS Kickstart x86_64 8;Red Hat Enterprise Linux 8 for x86_64 - BaseOS (Kickstart);Red Hat Enterprise Linux for x86_64;x86_64;8;immediate
38;3;3072;Red Hat Enterprise Linux 8 for x86_64 - AppStream RPMs x86_64 8;Red Hat Enterprise Linux 8 for x86_64 - AppStream (RPMs);Red Hat Enterprise Linux for x86_64;x86_64;8;immediate
39;3;3072;Red Hat Enterprise Linux 8 for x86_64 - AppStream Kickstart x86_64 8;Red Hat Enterprise Linux 8 for x86_64 - AppStream (Kickstart);Red Hat Enterprise Linux for x86_64;x86_64;8;immediate
40;3;3072;Red Hat Satellite Tools 6.5 for RHEL 8 x86_64 RPMs x86_64;Red Hat Satellite Tools 6.5 for RHEL 8 x86_64 (RPMs);Red Hat Enterprise Linux for x86_64;x86_64;000;immediate
41;34;2048;Red Hat Enterprise Linux 8 for x86_64 - Supplementary RPMs x86_64 8;Red Hat Enterprise Linux 8 for x86_64 - Supplementary (RPMs);Red Hat Enterprise Linux for x86_64;x86_64;8;immediate
EOF

IFS=$BIFS

    hammer sync-plan create --name "nightly sync" --enabled=true --interval daily --organization $ORG --sync-date "2018-05-01 01:00:00"
    for i in $(hammer --csv product list --organization $ORG --per-page 999 | grep -vi '^ID' | grep -vi not_synced | awk -F, {'{ if ($5!=0) print $1}'})
    do
      hammer product set-sync-plan --sync-plan "nightly sync" --organization $ORG --id $i
    done

    export CVMANAGER_PASS=$(pwmake 64)
    hammer user create --login='cvmanager' --firstname='ContentView' --lastname='Manager' --default-location=$LOC --default-organization=$ORG --locale='de' --organizations=$ORG --locations=$LOC --timezone='Berlin' --password="$CVMANAGER_PASS" --roles='Manager' --mail="cvmanager@${DOMAIN}" --auth-source-id=1
    yum -y install ruby-devel gcc gcc-c++
    git clone https://github.com/RedHatSatellite/katello-cvmanager.git
    gem install apipie-bindings || true
    cat > /root/katello-cvmanager/UnStaged.yaml <<EOF
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
  RHEL7-Base: latest
  inf-builder-rhel7: latest
  inf-docker-rhel7: latest
  inf-git-rhel7: latest
  inf-hypervisor-rhel7: latest
  inf-ipa-rhel7: latest
  inf-oscp-rhel7: latest
:promote:
 - RHEL7-Base
 - inf-builder-rhel7
 - inf-docker-rhel7
 - inf-git-rhel7
 - inf-hypervisor-rhel7
 - inf-ipa-rhel7
 - inf-oscp-rhel7
:publish:
 - RHEL7-Base
 - inf-builder-rhel7
 - inf-docker-rhel7
 - inf-git-rhel7
 - inf-hypervisor-rhel7
 - inf-ipa-rhel7
 - inf-oscp-rhel7
EOF

    cat > /root/katello-cvmanager/daily_updates.sh <<EOF
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

# BEGIN content view customizing and promotion
if [ $STAGE -le 6 ]; then
    date

    time hammer content-view publish --organization "$ORG" --name RHEL8-Base --description 'Initial Publishing' 2>/dev/null
    time hammer content-view version promote --organization "$ORG" --content-view RHEL8-Base --to-lifecycle-environment UnStaged  2>/dev/null

    time hammer content-view publish --organization "$ORG" --name RHEL8-Ext --description 'Initial Publishing' 2>/dev/null
    time hammer content-view version promote --organization "$ORG" --content-view RHEL8-Ext --to-lifecycle-environment UnStaged  2>/dev/null

    time hammer content-view publish --organization "$ORG" --name RHEL7-Base --description 'Initial Publishing' 2>/dev/null
    time hammer content-view version promote --organization "$ORG" --content-view RHEL7-Base --to-lifecycle-environment UnStaged  2>/dev/null

    if [ $RHEL6_CONTENT = 'true' ]; then
        time hammer content-view publish --organization "$ORG" --name RHEL6-Base --description 'Initial Publishing' 2>/dev/null
        time hammer content-view version promote --organization "$ORG" --content-view RHEL6-Base --to-lifecycle-environment UnStaged  2>/dev/null
    fi

fi
# END content view setup


# BEGIN activation key and hostgroup setup
if [ $STAGE -le 7 ]; then
    # JBoss_Sub_ID=$(hammer --output='csv' subscription list --organization=$ORG --search='Red Hat JBoss Enterprise Application Platform, 16-Core Premium' | tail -n+2 | head -n1 | cut -d',' -f1)
    # RHEV_Sub_ID=$(hammer --output='csv' subscription list --organization=$ORG --search='Red Hat Virtualization (2-sockets), Standard' | tail -n+2 | head -n1 | cut -d',' -f1)
    # OSCP_Sub_ID=$(hammer --output='csv' subscription list --organization=$ORG --search='OpenShift Container Platform, Premium 2-Core' | tail -n+2 | head -n1 | cut -d',' -f1)
    RHEL_Sub_ID=$(hammer --output='csv' subscription list --organization=$ORG --search='Red Hat Enterprise Linux Server with Smart Management, Standard (Physical or Virtual Nodes)' | grep -v 'ATOM\|Resilient\|Hyperscale' | tail -n+2 | head -n1 | cut -d',' -f1)

    uuid=$(uuidgen)
    hammer activation-key create --organization="$ORG" --name="el7base-${uuid}" --unlimited-hosts --lifecycle-environment='UnStaged' --content-view='RHEL7-Base'
    hammer activation-key add-subscription --organization="$ORG" --name="el7base-${uuid}" --subscription-id="$RHEL_Sub_ID" 
    hammer activation-key content-override --organization="$ORG" --name="el7base-${uuid}" --content-label='rhel-7-server-satellite-tools-6.5-rpms' --value=1
    hammer activation-key content-override --organization="$ORG" --name="el7base-${uuid}" --content-label='rhel-7-server-satellite-tools-6.5-puppet4-rpms' --value=1
    hammer activation-key update --organization="$ORG" --name="el7base-${uuid}" --release-version='7Server' --service-level='Standard' --auto-attach=0
    environment=$(hammer --output=csv environment list --search='unstaged_rhel7_base' | tail -n+2 | head -n1 | cut -d',' -f2)
    hammer hostgroup create --query-organization="$ORG" --organizations="$ORG" --locations="$LOC" \
      --architecture='x86_64' --content-source-id=1 --puppet-ca-proxy-id=1 --puppet-proxy-id=1 \
      --lifecycle-environment='UnStaged' --operatingsystem='RedHat 7.7' --partition-table='Kickstart default' \
      --content-view='RHEL7-Base' \
      --environment="${environment}" --name='RHEL7-Base'
    hammer hostgroup set-parameter --hostgroup='RHEL7-Base' --name='kt_activation_keys' --value="el7base-${uuid}"

    uuid=$(uuidgen)
    hammer activation-key create --organization="$ORG" --name="el8base-${uuid}" --unlimited-hosts --lifecycle-environment='UnStaged' --content-view='RHEL8-Base'
    hammer activation-key content-override --organization="$ORG" --name="el8base-${uuid}" --content-label='satellite-tools-6.5-for-rhel-8-x86_64-rpms' --value=1
    hammer activation-key update --organization="$ORG" --name="el8base-${uuid}" --release-version='8' --service-level='Standard' --auto-attach=0
    environment=$(hammer --output=csv environment list --search='unstaged_rhel8_base' | tail -n+2 | head -n1 | cut -d',' -f2)
    hammer hostgroup create --query-organization="$ORG" --organizations="$ORG" --locations="$LOC" \
      --architecture='x86_64' --content-source-id=1 --puppet-ca-proxy-id=1 --puppet-proxy-id=1 \
      --lifecycle-environment='UnStaged' --operatingsystem='RedHat 8.0' --partition-table='Kickstart default' \
      --content-view='RHEL8-Base' \
      --environment="${environment}" --name='RHEL8-Base'
    hammer hostgroup set-parameter --hostgroup='RHEL8-Base' --name='kt_activation_keys' --value="el8base-${uuid}"
    hammer hostgroup set-parameter --hostgroup='RHEL8-Base' --name='enable-puppet4' --value='true'

    if [ $RHEL6_CONTENT = 'true' ]; then
        hammer activation-key create --organization="$ORG" --name='RHEL6_Base' --unlimited-hosts --lifecycle-environment='UnStaged' --content-view='RHEL6_Base'
        hammer activation-key add-subscription --organization="$ORG" --name='RHEL6_Base' --subscription-id="$RHEL_Sub_ID" 
        hammer activation-key content-override --organization="$ORG" --name='RHEL6_Base' --content-label='rhel-6-server-satellite-tools-6.5-rpms' --value=1
        hammer activation-key update --organization="$ORG" --name='RHEL6_Base' --release-version='6Server' --service-level='Standard' --auto-attach=0
        environment=$(hammer --output=csv environment list --search='unstaged_rhel6_base' --puppet-class='stdlib' | tail -n+2 | head -n1 | cut -d',' -f2)
        hammer hostgroup create --query-organization="$ORG" --organizations="$ORG" --locations="$LOC" \
          --architecture='x86_64' --content-source-id=1 --puppet-ca-proxy-id=1 --puppet-proxy-id=1 \
          --lifecycle-environment='UnStaged' --operatingsystem='RedHat 6.9' --partition-table='Kickstart default' \
          --content-view='RHEL6_Base' \
          --environment="$environment" --name='RHEL6_Base'
        hammer hostgroup set-parameter --hostgroup='RHEL6_Base' --name='kt_activation_keys' --value='RHEL6_Base'
        hammer hostgroup set-parameter --hostgroup='RHEL6_Base' --name='enable-puppet4' --value='true'
    fi

fi
# END activation key and hostgroup setup

