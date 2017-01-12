#!/bin/bash
# vim: ft=sh:sw=2:et
# set -x
# set -e

# This script prepares a Satellite-6 server to provision RHEL as RHV hypervisor.
# It first make sure all required products/repos are enabled and synced into Satellite.
# Then the script creates a Content View with those repos and a number of Puppet modules
# required to implement the hypervisor role.
# This hypervisor profile and the cockpit module it depends on can be found on Github:
# https://github.com/shetze/puppet-modules
# The other dependencies can be resolved with modules from PuppetForge.
#
# After the Content View has been published and promoted, an Activation Key and
# Hostgroup are created for provisioning of new hosts for that hypervisor role.
#
# At last, a couple of smart class parameters are made available to the Hostgroup
# for configuration of the hypervisor hosts.


# The following block of parameters needs to reflect your environment.
# The purpose should be pretty much self explanatory.
export ORG="LunetIX"
export LOC="BX-Lab"
export DOMAIN=lunetix.org
export REALM=LUNETIX.ORG
export SUBNET_NAME='BX-Front'
# This is the default password used in hostgroup declarations.
export HOST_PASSWORD='Geheim!!'

export profile_name='hypervisor'
export profile_type='inf'
export profile_gen='rhel7'
export stage='Development'
export stage_prefix='dev'

hypervisor_view=${profile_type}-${profile_name}-${profile_gen}
hypervisor_group=${stage_prefix}-${profile_name}-${profile_gen}
hypervisor_env=${stage}_${profile_type}_${profile_name}_${profile_gen}


cat <<EOD | tr -d "'" |
'Red Hat Enterprise Linux Server','Red Hat Enterprise Linux 7 Server (RPMs)','x86_64','7Server',''
'Red Hat Enterprise Linux Server','Red Hat Enterprise Linux 7 Server - Extras (RPMs)','x86_64','','immediate'
'Red Hat Enterprise Linux Server','Red Hat Satellite Tools 6.2 (for RHEL 7 Server) (RPMs)','x86_64','',''
'Red Hat Enterprise Virtualization','Red Hat Virtualization 4 Management Agents for RHEL 7 (RPMs)','x86_64','7Server','on-demand'
EOD

while IFS=, read product reposet basearch releasever policy; do
  if [ -n $releasever ]; then releasestr=" $releasever"; else releasestr="$releasever"; fi
  repo=$(echo $reposet $basearch$releasestr|tr -d "()")
  echo Ensure availability for repo: $repo
  hammer repository-set info --organization "$ORG" --product "$product" --name "$reposet" >/dev/null 2>/dev/null
  if [ $? != 0 ]; then echo "product not found: make sure you have a subscription for $product in your manifest"; fi
  hammer repository info --organization "$ORG" --product "$product" --name "$repo" >/dev/null 2>/dev/null
  if [ $? != 0 ]; then
    echo "Enabling repo $repo"
    if [ -n $releasever ]; then
      hammer repository-set enable --organization "$ORG" --product "$product" --basearch="$basearch" --name "$reposet"
    else
      hammer repository-set enable --organization "$ORG" --product "$product" --basearch="$basearch" --releasever="$releasever" --name "$reposet"
    fi
    if [ -n $policy ]; then
     hammer repository update --organization "$ORG" --product "$product" --name "$repo" --download-policy "$policy"
    fi
    time hammer repository synchronize --organization "$ORG" --product "$product" --name "$repo" 2>/dev/null
  fi
done

hammer content-view info --organization "$ORG" --name "$hypervisor_view" >/dev/null 2>/dev/null
if [ $? != 0 ]; then
  echo "add Content View $hypervisor_view"
  cfx_firewall_id=$(hammer --output=csv puppet-module list --organization=$ORG --search "crayfishx firewalld 2.2.0"| tail -n+2 | head -n1 | cut -d',' -f1)
  hammer content-view create --organization "$ORG" --name "$hypervisor_view" --label "$hypervisor_view" --description 'RHV Hypervisor'
  hammer content-view add-repository --organization "$ORG" --name "$hypervisor_view" --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 7 Server RPMs x86_64 7Server'
  hammer content-view add-repository --organization "$ORG" --name "$hypervisor_view" --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Satellite Tools 6.2 for RHEL 7 Server RPMs x86_64'
  hammer content-view add-repository --organization "$ORG" --name "$hypervisor_view" --product 'Red Hat Enterprise Virtualization' --repository 'Red Hat Enterprise Virtualization Management Agents for RHEL 7 RPMs x86_64 7Server'
  hammer content-view puppet-module add --organization "$ORG" --content-view "$hypervisor_view" --author puppetlabs --name stdlib
  hammer content-view puppet-module add --organization "$ORG" --content-view "$hypervisor_view" --author puppetlabs --name concat
  hammer content-view puppet-module add --organization "$ORG" --content-view "$hypervisor_view" --author puppetlabs --name ntp
  hammer content-view puppet-module add --organization "$ORG" --content-view "$hypervisor_view" --author saz --name ssh
  hammer content-view puppet-module add --organization "$ORG" --content-view "$hypervisor_view" --id $cfx_firewall_id
  hammer content-view puppet-module add --organization "$ORG" --content-view "$hypervisor_view" --author LunetIX --name hypervisor
  hammer content-view puppet-module add --organization "$ORG" --content-view "$hypervisor_view" --author LunetIX --name cockpit
  time hammer content-view publish --organization "$ORG" --name "$hypervisor_view" --description 'Initial Publishing' 2>/dev/null
  time hammer content-view version promote --organization "$ORG" --content-view "$hypervisor_view" --to-lifecycle-environment "$stage"  2>/dev/null
else
  echo "Content View $hypervisor_view already exists, change manually if required"
fi


hammer activation-key info --organization "$ORG" --name "$hypervisor_group" >/dev/null 2>/dev/null
if [ $? != 0 ]; then
  echo "add Activation Key $hypervisor_group"
  RHEL_Sub_ID=$(hammer --output='csv' subscription list --organization=$ORG --search='Red Hat Enterprise Linux Server with Smart Management, Standard (Physical or Virtual Nodes)' | grep -v 'ATOM\|Resilient\|Hyperscale' | tail -n+2 | head -n1 | cut -d',' -f1)
  PuppetForge_Sub_ID=$(hammer --output='csv' subscription list --organization=$ORG --search='Puppet Forge' | tail -n+2 | head -n1 | cut -d',' -f1)
  RHEV_Sub_ID=$(hammer --output='csv' subscription list --organization=$ORG --search='Red Hat Enterprise Virtualization (2-sockets), Standard' | tail -n+2 | head -n1 | cut -d',' -f1)

  hammer activation-key create --organization="$ORG" --name="$hypervisor_group" --unlimited-hosts --lifecycle-environment="$stage" --content-view="$hypervisor_view"
  hammer activation-key add-subscription --organization="$ORG" --name="$hypervisor_group" --subscription-id="$PuppetForge_Sub_ID" 
  hammer activation-key add-subscription --organization="$ORG" --name="$hypervisor_group" --subscription-id="$RHEV_Sub_ID" 
  hammer activation-key add-subscription --organization="$ORG" --name="$hypervisor_group" --subscription-id="$RHEL_Sub_ID" 
  hammer activation-key content-override --organization="$ORG" --name="$hypervisor_group" --content-label='rhel-7-server-satellite-tools-6.2-rpms' --value=1
  hammer activation-key content-override --organization="$ORG" --name="$hypervisor_group" --content-label='rhel-7-server-rhv-4-mgmt-agent-rpms' --value=1
  hammer activation-key content-override --organization="$ORG" --name="$hypervisor_group" --content-label='rhel-7-server-extras-rpms' --value=1
  hammer activation-key update --organization="$ORG" --name="$hypervisor_group" --release-version='7Server' --service-level='Standard' --auto-attach=0
else
  echo "Activation Key $hypervisor_group already exists, change manually if required"
fi

hammer hostgroup info --name "$hypervisor_group" >/dev/null 2>/dev/null
if [ $? != 0 ]; then
  echo "add Host Group $hypervisor_group"
  environment=$(hammer --output=csv environment list --search="$hypervisor_env" --puppet-class='stdlib' | tail -n+2 | head -n1 | cut -d',' -f2)
  hammer hostgroup create --organization="$ORG" --organizations="$ORG" --locations="$LOC" \
    --architecture='x86_64' --content-source-id=1 --puppet-ca-proxy-id=1 --puppet-proxy-id=1 \
    --domain="$DOMAIN" --realm="$REALM" --subnet="$SUBNET_NAME" \
    --medium='LunetIX/Library/Red_Hat_Server/Red_Hat_Enterprise_Linux_7_Server_Kickstart_x86_64_7_3' \
    --lifecycle-environment="$stage" --operatingsystem='RedHat 7.3' --partition-table='Kickstart default' \
    --root-pass="$HOST_PASSWORD" --puppet-classes='ssh::server,ntp,hypervisor'  --content-view="$hypervisor_view" \
    --environment="$environment" --name="$hypervisor_group"
  hammer hostgroup set-parameter --hostgroup="$hypervisor_group" --name='kt_activation_keys' --value="$hypervisor_group"

  echo "change smart class parameter settings"
  param_id=$(hammer --output=csv sc-param list --puppet-class='ssh::server' --search='options' | tail -n+2 | head -n1 | cut -d',' -f1)
  hammer sc-param add-override-value --puppet-class='ssh::server' --smart-class-parameter-id=$param_id --match="hostgroup=$hypervisor_view" \
    --value='{ "PermitRootLogin": true, "Protocol": 2, "UsePrivilegeSeparation": "sandbox", "SyslogFacility": "AUTHPRIV", "AuthorizedKeysFile": ".ssh/authorized_keys", "PasswordAuthentication": true, "GSSAPICleanupCredentials": false, "KerberosAuthentication": false, "PubkeyAuthentication": true, "GSSAPIAuthentication": true, "AuthorizedKeysCommand": "/usr/bin/sss_ssh_authorizedkeys", "AuthorizedKeysCommandUser": "nobody" }'
  param_id=$(hammer --output=csv sc-param list --puppet-class='hypervisor' --search='cockpit_cert' | tail -n+2 | head -n1 | cut -d',' -f1)
  hammer sc-param update --puppet-class='hypervisor' --override=1 --id=$param_id --default-value='undef'
  param_id=$(hammer --output=csv sc-param list --puppet-class='hypervisor' --search='iscsi_initiator_name' | tail -n+2 | head -n1 | cut -d',' -f1)
  hammer sc-param update --puppet-class='hypervisor' --override=1 --id=$param_id --default-value="undef"
  param_id=$(hammer --output=csv sc-param list --puppet-class='hypervisor' --search='ssh_host_key_pub' | tail -n+2 | head -n1 | cut -d',' -f1)
  hammer sc-param update --puppet-class='hypervisor' --override=1 --id=$param_id --default-value='undef'
  param_id=$(hammer --output=csv sc-param list --puppet-class='hypervisor' --search='ssh_host_key_sec' | tail -n+2 | head -n1 | cut -d',' -f1)
  hammer sc-param update --puppet-class='hypervisor' --override=1 --id=$param_id --default-value='undef'
else
  echo "Host Group $hypervisor_group already exists, change manually if required"
fi

echo Done
