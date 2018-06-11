#!/bin/bash
# vim: ft=sh:sw=2:et
cat <<EOF


Capsule-6.3 Demo/Test/PoC Setup Script
========================================

This script is intended to automate a Capsule-6.3 server installation on top of a Satellite-6.3 setup for demo, test or PoC purposes.
 
The script helps to perform the initial steps to finish the prerequisites, it installs and configures the software,
it fills the Capsule with various types of content, it creates activation keys and content views,
it customizes some smart class parameter overrides and finally installs a couple of new hosts.

With this setup, the script is well suited as a Capsule-6 test.
In an PoC scenario, it allows to emphasize on the actual use cases and requirements from the very first moment.

This demo setup shows some of the features and benefits of Capsule-6.3:
- Capsule is configured to use the existing IPA CA (again, IPA is prerequisite, out of scope for this demo).
- Capsule is configured to register hosts automatically into the IPA REALM.
- The simple baseline host is hardened so that root login is disabled.

This demo is intended to run in a VM on a libvirt/KVM host. The Capsule VM requires least 8GB of RAM and 4 cores. 12GB RAM and 6 cores are recommended.
I recommend using a dedicated server from a hosting provider which is available for less than €50 per month.
The network setup must allow Capsule to run DHCP and TFTP on a dedicated interface.
With all features enabled, the demo setup will consume around 180GB of disk space for package content in /var/lib/pulp.
Using the immediate sync policy, the content sync alone takes more than 24 hours even with a high bandwidth internet connection.
In preparation for a Capsule-6 PoC this script can be used to perform this time consuming procedure ahead of the actual PoC engagement.

There is at least one manual intervention required directly after
satellite-install has finished and a second halt is included right before the
demo hosts are created at the end.  So be prepared to be around for at least an
hour or so after starting the script to proceed after the first manual
intervention.  After that, you may go home and proceed the next day...

You may want to run this script in a screen session.

The header section of this script declares a lot of variables that are used later on to customize the script.
Read through the values carefully and change where appropriate.
When finished, delete or comment the following exit command.

EOF
exit 0

set -x
set -e
longname=$(hostname | tr '.' '_')

# STAGE Level:
# 1 = preqequisite preparation
# 2 = Capsule 6 installation
export STAGE=1

# This demo setup is built with IPA integration as one important feature to show.
# While it is possible to use IPA and leave Capsule with the self signed internal CA cert,
# it is recommended to demonstrate/test this feature as well.
# The IPA_EXT_CERT switch is mainly offered for debugging purposes.
export IPA_EXT_CERT=true


# The following block of parameters needs to reflect your environment.
# Most of the parameters are used with the satellite-installer
# The purpose should be pretty much self explanatory. In doubt, look at 'satellite-installer --help'
export SAT_IP=172.24.200.3
export SAT_NAME=satellite.example.com
export CAP_IP=172.24.100.5
export ORG="ACME"
export LOC="Elsewhere"
export ADMIN=capsule
export ADMIN_PASSWORD=',4d4jynIt3KZOD'
export IPA_SERVER=ipa.example.com
export DOMAIN=example.com
export REALM=EXAMPLE.COM
export C=DE
export ST=Berlin
export L=Berlin
export OU=IT-Ops
export DNS=172.24.100.2
export DNS_REV=100.24.172.in-addr.arpa
export DHCP_RANGE="172.24.100.20 172.24.100.50"
export DHCP_GW=172.24.100.1
export DHCP_DNS=172.24.100.2
export CAP_INTERFACE=eth1
export SUBNET=172.24.100.0
export SUBNET_MASK=255.255.255.0
export SUBNET_NAME='elsenet'
export SUBNET_IPAM_BEGIN=172.24.100.100
export SUBNET_IPAM_END=172.24.100.150
# The host prefix is used to distinguish the demo hosts created at the end of this script.
export HOST_PREFIX='el-'
# This is the default password used in hostgroup declarations.
export HOST_PASSWORD='Geheim!!'

# This demo is intended to run on a simple libvirt/KVM hypervisor.
# A dedicated server hosted by an internet service provider may be a cost effective choice for this ressource.
export CONFIGURE_LIBVIRT_RESOURCE=true
export COMPUTE_RES_FQDN="kvm2.hoster.com"
export COMPUTE_RES_NAME="Else"

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

# This is the end of the header section.
# Depending on the STAGE declared above, the script will start at some point and continue all the way to the end -- if everything goes well ;-)
# As mentioned before, there is a halt for manual intervention right after satellite-install and a second halt at the end before creating the demo hosts.



# BEGIN preqeq prep
if [ $STAGE -le 1 ]; then
    echo "${CAP_IP} $(hostname)" >>/etc/hosts
    rpm -Uvh http://$SAT_NAME/pub/katello-ca-consumer-latest.noarch.rpm || true
    subscription-manager register || true
    subscription-manager repos --disable "*"
    subscription-manager repos --enable=rhel-7-server-rpms \
        --enable=rhel-server-rhscl-7-rpms \
        --enable=rhel-7-server-optional-rpms \
        --enable=rhel-7-server-satellite-tools-6.3-rpms \
        --enable=rhel-7-server-satellite-capsule-6.3-rpms \
        --enable=rhel-7-server-satellite-capsule-6.3-puppet4-rpms
    rpm -Uvh https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm || true
    yum-config-manager --disable epel
    yum -y upgrade
    yum install -y screen yum-utils vim katello-agent

    yum install -y ipa-client ipa-admintools
#    ipa-client-install --server=$IPA_SERVER --domain=$DOMAIN --realm=$REALM
    kinit admin@${REALM}
    ipa service-add HTTP/$(hostname)
    if [ $IPA_EXT_CERT = 'true' ]; then
        mkdir -p /root/certs
	openssl req -nodes -newkey rsa:2048 -keyout /root/certs/key.pem -out /root/certs/${longname}.csr -subj "/C=${C}/ST=${ST}/L=${L}/O=${ORG}/OU=${OU}/CN=$(hostname)"
        serial=$(ipa cert-request --add --principal=host/$(hostname) /root/certs/${longname}.csr|grep number:|cut -d' ' -f5)
        ipa cert-show --out /root/certs/${longname}.crt $serial
    fi


    read -p "

Manual action required!

    To proceed you need to copy /root/certs/key.pem /root/certs/${longname}.crt and /root/certs/${longname}.csr to /root/capsule-certs/
    on the Satellite server and generate the capsule cert package.

    capsule-certs-generate --foreman-proxy-fqdn "$(hostname)" --certs-tar  "~/$(hostname)-certs.tar" --server-cert "/root/capsule-certs/${longname}.crt" --server-cert-req "/root/capsule-certs/${longname}.csr" --server-key "/root/capsule-certs/key.pem"--server-ca-cert "/etc/ipa/ca.crt"

    Then you need to edit this script, insert the OAUTH keys for the capsule integration as provided by capsule-certs-generate and proceed with stage 2.
    Hit Enter to exit Stage 1." answer

    exit 0
fi
# END preqeq prep

export OAUTH_CONSUMER_KEY='5RDhyAovwyDkysG6bQGbUBcJWayKaTYL'
export OAUTH_CONSUMER_SEC='uYhAqHTj55Y7VQaMtECA3JjZyCSyM8SG'
export PROXY_OAUTH_SECRET='Y4xmYLy3rLQJoEp2EipK7im9vzrK3wHD'

# BEGIN installation
if [ $STAGE -le 2 ]; then
    yum -y install satellite-capsule qpid-dispatch-router tfm-rubygem-hammer*

    firewall-cmd --permanent --add-port="53/udp" --add-port="53/tcp" \
    --add-port="67/udp" --add-port="69/udp" \
    --add-port="80/tcp" --add-port="443/tcp" \
    --add-port="5000/tcp" --add-port="5647/tcp" \
    --add-port="8000/tcp" --add-port="8140/tcp" \
    --add-port="8443/tcp" --add-port="9090/tcp"

    firewall-cmd --reload

    if [ ! -f /root/.hammer/cli_config.yml ]; then
        mkdir -p /root/.hammer
        cat > /root/.hammer/cli_config.yml <<EOF
:foreman:
    :host: 'https://$SAT_NAME/'
    :username: '$ADMIN'
    :password: '$ADMIN_PASSWORD'
    :request_timeout: -1
EOF
    fi

    if [ ! -f /root/freeipa.keytab ]; then
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
    chmod 0600 /etc/foreman-proxy/freeipa.keytab
    cp /etc/ipa/ca.crt /etc/pki/ca-trust/source/anchors/ipa.crt
    update-ca-trust enable
    update-ca-trust


    time satellite-installer --scenario capsule -v \
      --foreman-proxy-content-parent-fqdn           "$SAT_NAME"\
      --foreman-proxy-register-in-foreman           "true"\
      --foreman-proxy-foreman-base-url              "https://$SAT_NAME"\
      --foreman-proxy-trusted-hosts                 "$SAT_NAME"\
      --foreman-proxy-trusted-hosts                 "$(hostname)"\
      --foreman-proxy-oauth-consumer-key            "$OAUTH_CONSUMER_KEY"\
      --foreman-proxy-oauth-consumer-secret         "$OAUTH_CONSUMER_SEC"\
      --foreman-proxy-content-pulp-oauth-secret     "$PROXY_OAUTH_SECRET"\
      --foreman-proxy-content-certs-tar             "/root/$(hostname)-certs.tar"\
      --puppet-server-foreman-url                   "https://$SAT_NAME"\
      --foreman-proxy-dns=true \
      --foreman-proxy-dns-interface=$CAP_INTERFACE \
      --foreman-proxy-dns-zone=$DOMAIN  \
      --foreman-proxy-dns-forwarders=$DNS \
      --foreman-proxy-dns-reverse=$DNS_REV  \
      --foreman-proxy-dhcp=true \
      --foreman-proxy-dhcp-interface=$CAP_INTERFACE \
      --foreman-proxy-dhcp-range="$DHCP_RANGE" \
      --foreman-proxy-dhcp-gateway=$DHCP_GW \
      --foreman-proxy-dhcp-nameservers=$DHCP_DNS \
      --foreman-proxy-tftp=true \
      --foreman-proxy-tftp-servername=$CAP_IP \
      --foreman-proxy-puppetca=true \
      --foreman-proxy-realm=true \
      --foreman-proxy-realm-keytab=/etc/foreman-proxy/freeipa.keytab \
      --foreman-proxy-realm-principal="realm-proxy@${REALM}" \
      --foreman-proxy-realm-provider=freeipa \
      --enable-foreman-proxy-plugin-openscap \
      --enable-foreman-proxy-plugin-discovery \
      --enable-foreman-proxy-plugin-remote-execution-ssh


    service foreman-proxy restart
    yum install -y puppet-foreman_scap_client
    yum install -y foreman-discovery-image
    mkdir -p /etc/puppet/environments/production/modules

fi
# END installation

exit 0

# BEGIN environment setup
if [ $STAGE -le 3 ]; then
    hammer capsule content add-lifecycle-environment --name=$(hostname) --organization=$ORG --environment=Production

    hammer domain update --id 1 --organizations "$ORG" --locations "$LOC"

    CAPSULE_ID=$(hammer --output='csv' capsule list --search=$(hostname) | tail -n+2 | head -n1 | cut -d',' -f1)

    hammer subnet create --name $SUBNET_NAME \
      --network $SUBNET \
      --mask $SUBNET_MASK \
      --gateway $DHCP_GW \
      --dns-primary $DHCP_DNS \
      --ipam 'Internal DB' \
      --from $SUBNET_IPAM_BEGIN \
      --to $SUBNET_IPAM_END \
      --tftp-id $CAPSULE_ID \
      --dhcp-id $CAPSULE_ID \
      --dns-id $CAPSULE_ID \
      --domain-ids 1 \
      --organizations "$ORG" \
      --locations "$LOC"

    if [ $CONFIGURE_LIBVIRT_RESOURCE = 'true' ]; then
        hammer compute-resource create --organizations "$ORG" --name "$COMPUTE_RES_NAME" --locations "$LOC" --provider Libvirt --url qemu+ssh://root@${COMPUTE_RES_FQDN}/system --set-console-password false
    fi

    if [ $CONFIGURE_RHEV_RESOURCE = 'true' ]; then
        hammer compute-resource create --name "${COMPUTE_RES_NAME}" --provider "Ovirt" --description "RHV4 Managment Server" --url "https://${COMPUTE_RES_FQDN}/ovirt-engine/api/v3" --user "${RHV_RES_USER}" --password "${RHV_RES_PASSWD}" --locations "$LOC" --organizations "$ORG" --uuid "${RHV_RES_UUID}"
    fi

    LOC_IDS=''
    for LOC in $(hammer --output=csv location list|tail -n+2|cut -d',' -f1); do LOC_IDS="${LOC_IDS}${LOC_IDS:+,}$LOC"; done

    hammer location add-medium --name=$LOC --medium="RHEL 7.5 Kickstart"
    hammer location add-hostgroup --name=$LOC --hostgroup='RHEL7_Base'
    hammer location add-domain --name=$LOC --domain=$DOMAIN
    hammer realm update --name=$REALM --location-ids=$LOC_IDS
    hammer capsule content synchronize --organization=$ORG --name=$(hostname)

fi
# END environment setup

    if [ $CONFIGURE_LIBVIRT_RESOURCE = 'true' ]; then
        read -p "

        Manual action required!

        To proceed you need to manually add /usr/share/foreman/.ssh/id_rsa.pub to root@${COMPUTE_RES_FQDN}:.ssh/authorized_keys

        Hit Enter after the key has been authorized." answer
    fi

    read -p "

Manual action required!

    To proceed you need to manually adjust Compute Profiles.
    Log into your Satellite-6.3 as admin and go to Infrastructure->Compute Profiles.
    Go through all profile sizes and make sure the network interfaces are correctly selected for the Capsule subnet.

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

