#! /bin/bash

clear

echo
echo
echo "This script is a pretty much complete series of commands to walk through the"
echo "OpenTLC Satellite 6.1 implementation lab."
echo "It performs the steps and activities described in"
echo "http://file.rdu.redhat.com/~rjerrido/Satellite_61_Implementation_Beta/"
echo
echo "In order to allow automatic remote execution of commands on the client,"
echo "this script must run as root user on the satellite instance."
echo
echo "The total run time of this script is approximately 210 minutes (3 hrs 30 min)."
echo
echo "You should run this script in a screen session!"
echo "Consider capturing the output with tee:"
echo "./Sat61-Lab-Hammer.sh 2>&1 | tee labScript.out"
echo
echo "There is only one interactive step required to start the performance."
echo "Please Type in your OpenTLC username followed by your password to download the Satellite Manifest."
read -p "OpenLC username (something like jdoe-redhat.com):" TLCUSER
echo
echo

export TLCUSER
GUID=$(hostname -s|cut -d'-' -f2)
export GUID
export ORG='Default Organization'
export ORG_LABEL='Default_Organization'
export LOC='Default Location'
export adminpasswd='2vhf8GM9mbaetYBh'


wget --user $TLCUSER -P /tmp --ask-password https://www.opentlc.com/classes/si-class/materials/Sat6_Class_manifest.zip

echo
echo "That was it, now the show can begin..."
echo
date
echo Lab0
echo "opening firewall ports for Satellite server"
lokkit --port 443:tcp --port 5671:tcp --port 80:tcp --port 8140:tcp --port 9090:tcp --port 8443:tcp --port 5674:tcp --port 67:udp --port 69:udp

echo Lab2
echo "installing and configuring Satellite-6"
echo yum takes ~8 min
echo katello-installer takes ~20 min
time yum install -q -y katello-installer
date
time katello-installer --capsule-tftp true --capsule-dhcp true --foreman-admin-username admin --foreman-admin-password "$adminpasswd" --foreman-initial-organization "$ORG" --foreman-initial-location "$LOC"

mkdir ~/.hammer 2>/dev/null
cat > .hammer/cli_config.yml <<EOF
:foreman:
    :host: 'https://sat-$GUID.rhpds.opentlc.com/'
    :username: 'admin'
    :password: '$adminpasswd'

EOF

echo Lab3
echo "loading manifest into Satellite"
hammer subscription upload --organization "$ORG" --file /tmp/Sat6_Class_manifest.zip
hammer subscription refresh-manifest --organization "$ORG"
hammer organization update --id 1 --redhat-repository-url http://sat-$GUID.rhpds.opentlc.com/pub/cds/prod

echo Lab4
echo "selecting Red Hat products to manage with Satellite"
hammer repository-set enable --organization "$ORG" --product 'Red Hat Enterprise Linux Server' --basearch='x86_64' --releasever='6Server' --name 'Red Hat Enterprise Linux 6 Server (RPMs)'    
hammer repository-set enable --organization "$ORG" --product 'Red Hat Enterprise Linux Server' --basearch='x86_64' --releasever='6.6' --name 'Red Hat Enterprise Linux 6 Server (Kickstart)' 
hammer repository-set enable --organization "$ORG" --product 'Red Hat Enterprise Linux Server' --basearch='x86_64' --name 'Red Hat Satellite Tools 6.1 (for RHEL 6 Server) (RPMs)'

echo Lab5
echo "sync of Red Hat Product repos takes ~90min"
date
time hammer repository synchronize --organization "$ORG" --product 'Red Hat Enterprise Linux Server'  --name  'Red Hat Satellite Tools 6.1 for RHEL 6 Server RPMs x86_64'
time hammer repository synchronize --organization "$ORG" --product 'Red Hat Enterprise Linux Server'  --name  'Red Hat Enterprise Linux 6 Server Kickstart x86_64 6.6' 2>/dev/null
time hammer repository synchronize --organization "$ORG" --product 'Red Hat Enterprise Linux Server'  --name  'Red Hat Enterprise Linux 6 Server RPMs x86_64 6Server' 2>/dev/null
date

echo Lab6

echo "no automation"

echo Lab7
echo "registering remote client to Satellite via ssh"
ssh cli-$GUID.rhpds.opentlc.com yum -y install http://sat-$GUID.rhpds.opentlc.com/pub/katello-ca-consumer-latest.noarch.rpm
echo -e "admin\n$adminpasswd\n" | ssh cli-$GUID.rhpds.opentlc.com subscription-manager register --org=$ORG_LABEL --environment=Library

echo Lab8
echo "integrating remote client as content host to Satellite via ssh"
ssh cli-$GUID.rhpds.opentlc.com subscription-manager list --available
ssh cli-$GUID.rhpds.opentlc.com subscription-manager attach --auto
ssh cli-$GUID.rhpds.opentlc.com subscription-manager repos --enable  rhel-6-server-satellite-tools-6.1-rpms
ssh cli-$GUID.rhpds.opentlc.com yum -q -y install katello-agent
ssh cli-$GUID.rhpds.opentlc.com chkconfig --list goferd
ssh cli-$GUID.rhpds.opentlc.com service goferd status

echo Lab9
echo "creating Satellite Class product"
hammer product create --name='Satellite Class' --organization "$ORG"
hammer content-host update --organization "$ORG" --name cli-$GUID.rhpds.opentlc.com --release-ver 6Server
# !!! Subscription->Add->Satellite Class is missing?

echo Lab10
echo "adding Simple Modules repo to Satellite Class"
hammer repository create  --organization "$ORG" --name='Simple Modules' --product='Satellite Class' --content-type='puppet' --publish-via-http=true

echo Lab11
echo "uploading puppet modules to Simple Modules"
hammer repository upload-content --organization "$ORG" --name "Simple Modules" --product "Satellite Class" --path /var/www/html/pub/simple_modules/puppetlabs-ntp-3.0.3.tar.gz
hammer repository upload-content --organization "$ORG" --name "Simple Modules" --product "Satellite Class" --path /var/www/html/pub/simple_modules/thoraxe-motd-0.1.1.tar.gz


echo Lab13
echo "creating Wordpress product"
hammer product create --organization "$ORG" --name 'Wordpress'
hammer repository create  --organization "$ORG" --name='Wordpress Packages' --product='Wordpress' --content-type='yum' --publish-via-http=true --url=http://sat-$GUID.rhpds.opentlc.com/pub/wordpress/el6/x86_64
time hammer repository synchronize --organization "$ORG"  --product='Wordpress' --name='Wordpress Packages'


echo Lab14
echo "adding Wordpress Puppet Modules repo and loading with content"
hammer repository create  --organization "$ORG" --name='Wordpress Puppet Modules' --product='Wordpress' --content-type='puppet' --publish-via-http=true
hammer repository upload-content --organization "$ORG" --name='Wordpress Puppet Modules' --product='Wordpress' --path /var/www/html/pub/wordpress-puppet/puppetlabs-concat-1.1.0-rc1.tar.gz
hammer repository upload-content --organization "$ORG" --name='Wordpress Puppet Modules' --product='Wordpress' --path /var/www/html/pub/wordpress-puppet/puppetlabs-firewall-1.0.0.tar.gz
hammer repository upload-content --organization "$ORG" --name='Wordpress Puppet Modules' --product='Wordpress' --path /var/www/html/pub/wordpress-puppet/puppetlabs-mysql-2.2.1.tar.gz
hammer repository upload-content --organization "$ORG" --name='Wordpress Puppet Modules' --product='Wordpress' --path /var/www/html/pub/wordpress-puppet/puppetlabs-stdlib-4.1.0.tar.gz
hammer repository upload-content --organization "$ORG" --name='Wordpress Puppet Modules' --product='Wordpress' --path /var/www/html/pub/wordpress-puppet/summit-wordpress-0.0.1.tar.gz

echo Lab15
echo "creating life cycle environments"
hammer lifecycle-environment create --organization "$ORG" --description 'Development' --name 'Development' --label development --prior Library
hammer lifecycle-environment create --organization "$ORG" --description 'Production' --name 'Production' --label production --prior 'Development'

echo Lab16
echo "creating content views"
hammer content-view create --organization "$ORG" --name 'RHEL6_Base' --label rhel6_base --description 'Core Build for RHEL 6'
hammer content-view add-repository --organization "$ORG" --name 'RHEL6_Base' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 6 Server RPMs x86_64 6Server'
hammer content-view add-repository --organization "$ORG" --name 'RHEL6_Base' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Enterprise Linux 6 Server Kickstart x86_64 6.6'
hammer content-view add-repository --organization "$ORG" --name 'RHEL6_Base' --product 'Red Hat Enterprise Linux Server' --repository 'Red Hat Satellite Tools 6.1 for RHEL 6 Server RPMs x86_64'
hammer content-view puppet-module add --organization "$ORG" --content-view RHEL6_Base --author thoraxe --name motd

echo Lab17
echo publishing content view RHEL6_Base takes ~10min
date
time hammer content-view publish --organization "$ORG" --name RHEL6_Base --description 'Initial Publishing' 2>/dev/null
# wait for publish to finish

echo Lab18
echo promoting RHEL6_Base takes ~5min
date
time hammer content-view version promote --organization "$ORG" --content-view RHEL6_Base --to-lifecycle-environment Development  2>/dev/null
# wait for promotion to finish
hammer content-host update --organization "$ORG" --name cli-$GUID.rhpds.opentlc.com --lifecycle-environment Development --content-view 'RHEL6_Base'

echo Lab19
echo "creating host group"
hammer hostgroup create --content-source-id 1 --content-view RHEL6_Base --lifecycle-environment Development --locations "$LOC" --name RHEL6_Dev_Servers --organizations "$ORG" --puppet-ca-proxy sat-$GUID.rhpds.opentlc.com --puppet-proxy  sat-$GUID.rhpds.opentlc.com --puppet-classes "motd"

echo Lab20
echo "installing puppet on remote client via ssh"
ssh cli-$GUID.rhpds.opentlc.com yum -y install puppet
ssh cli-$GUID.rhpds.opentlc.com puppet config set server sat-$GUID.rhpds.opentlc.com --section agent

echo Lab21
echo "running puppet on remote client via ssh and signing cert locally"
ssh cli-$GUID.rhpds.opentlc.com puppet agent --test --onetime
puppet cert sign cli-$GUID.rhpds.opentlc.com

echo Lab22
echo "running puppet agent on remote client again"
ssh cli-$GUID.rhpds.opentlc.com puppet agent --test --onetime

echo Lab23
echo "adding host group to freshly integrated puppet host"
hammer host update --name cli-$GUID.rhpds.opentlc.com --organization "$ORG" --location "$LOC" --hostgroup RHEL6_Dev_Servers --environment "KT_${ORG_LABEL}_development_rhel6_base_2"

echo Lab24

echo "no automation"

echo Lab25

echo "no automation"

echo Lab26

echo "no automation"

echo Lab27
echo "add puppet modules to RHEL6_Base content view"
hammer content-view puppet-module add --organization "$ORG" --content-view RHEL6_Base --author puppetlabs --name stdlib
hammer content-view puppet-module add --organization "$ORG" --content-view RHEL6_Base --author puppetlabs --name ntp

echo publishing v2 of RHEL6_Base takes ~10min
date
time hammer content-view publish --organization "$ORG" --name RHEL6_Base --description 'Adding NTP module and dependencies.'  2>/dev/null
# wait for publish to finish
echo promoting v2 of RHEL6_Base takes ~10min
date
time hammer content-view version promote --organization "$ORG" --content-view RHEL6_Base --to-lifecycle-environment Development --version 2.0 2>/dev/null
# wait for promote to finish

echo Lab28

echo "no automation"

echo Lab29

echo "no automation"

echo Lab30

echo "no automation"

echo Lab31

echo "no automation"

echo Lab32
echo "loading kickstart template"
hammer template create  --name "My_Kickstart" --locations "$LOC" --organizations "$ORG" --type provision --file /var/www/html/pub/materials/kickstart_template.erb --operatingsystems 'RedHat 6.6'

echo Lab33
echo "assigning kickstart template to OS"
hammer template list | grep My
hammer os list
hammer os set-default-template --config-template-id 50 --id 1

echo Lab34
echo "create domain and subnet"
hammer subnet create --organizations "$ORG" --locations "$LOC" --name "VM-Net" --network '192.168.0.0' --mask '255.255.0.0' --gateway '192.168.0.2' --dns-primary '192.168.0.1' --from '192.168.100.100' --to '192.168.100.110'
hammer domain update --name rhpds.opentlc.com --organizations "$ORG"  --locations "$LOC"
hammer subnet update --name VM-Net --dhcp-id 1 --tftp-id 1 --organizations "$ORG" --domains rhpds.opentlc.com --locations "$LOC"


echo Lab35
echo "update hostgroup for kickstart, domain and subnet"
hammer hostgroup update --organizations "$ORG" --name 'RHEL6_Dev_Servers' --architecture x86_64 --domain rhpds.opentlc.com --subnet VM-Net --partition-table 'Kickstart default' --operatingsystem 'RedHat 6.6' --medium "${ORG_LABEL}/Library/Red_Hat_Server/Red_Hat_Enterprise_Linux_6_Server_Kickstart_x86_64_6_6"
hammer host create --name pxeclient --hostgroup RHEL6_Dev_Servers --mac "52:54:00:ca:92:ee" --ip "192.168.100.100" --build yes --location "$LOC" --organization "$ORG" --root-pass "r3dh4t12" --environment KT_"${ORG_LABEL}_development_rhel6_base_2"

echo Lab36

echo "no automation"

echo Lab37
echo "create activation key"
RHEL_SUB_ID=$(hammer --csv --csv-separator ':' subscription list --organization "$ORG" | grep 'Red Hat Enterprise Linux Server, Standard (Physical or Virtual Nodes)' | cut -f 8 -d ':')
SAT_CLASS_SUB_ID=$(hammer --csv --csv-separator ':' subscription list --organization "$ORG" | grep 'Satellite Class' | cut -f 8 -d ':')
hammer activation-key create --organization "$ORG" --description 'Basic RHEL6 Key for Registering to Dev' --content-view 'RHEL6_Base' --unlimited-content-hosts yes --name ak-Reg_To_Dev --lifecycle-environment 'Development'
hammer activation-key add-subscription --organization "$ORG" --name ak-Reg_To_Dev --subscription-id $RHEL_SUB_ID
hammer activation-key add-subscription --organization "$ORG" --name ak-Reg_To_Dev --subscription-id $SAT_CLASS_SUB_ID
hammer hostgroup set-parameter --name kt_activation_keys --value 'ak-Reg_To_Dev' --hostgroup 'RHEL6_Dev_Servers'

echo Lab38
echo "prepare remote client for pxe boot of VM"
hammer bootdisk host --file /tmp/pxeclient.rhpds.opentlc.com.iso --host pxeclient.rhpds.opentlc.com
scp /var/lib/tftpboot/boot/* cli-$GUID.rhpds.opentlc.com:/var/lib/libvirt/images
# ssh cli-$GUID.rhpds.opentlc.com virsh start --console pxeclient


echo Lab39
echo "create Wordpress content view"
hammer content-view create --organization "$ORG" --name 'Wordpress View' --label wordpress_view --description 'Wordpress View'
hammer content-view add-repository --organization "$ORG" --name 'Wordpress View' --product 'Wordpress' --repository 'Wordpress Packages'
hammer content-view puppet-module add --organization "$ORG" --content-view 'Wordpress View'  --author puppetlabs --name firewall 
hammer content-view puppet-module add --organization "$ORG" --content-view 'Wordpress View'  --author puppetlabs --name mysql
hammer content-view puppet-module add --organization "$ORG" --content-view 'Wordpress View'  --author puppetlabs --name concat
hammer content-view puppet-module add --organization "$ORG" --content-view 'Wordpress View'  --author summit --name wordpress
time hammer content-view publish --organization "$ORG" --name 'Wordpress View' --description 'Initial Publishing' 2>/dev/null
time hammer content-view version promote --organization "$ORG" --content-view 'Wordpress View' --to-lifecycle-environment Development 2>/dev/null

echo Lab40
echo "create Webserver composite content view"
RHEL6_BASE_ID=$(hammer --csv --csv-separator ':' content-view list --organization "$ORG"|grep RHEL6_Base| cut -f 1 -d ':')
Wordpress_ID=$(hammer --csv --csv-separator ':' content-view list --organization "$ORG"|grep "Wordpress View"| cut -f 1 -d ':')
hammer content-view info --id $RHEL6_BASE_ID --organization "$ORG"
hammer content-view info --id $Wordpress_ID --organization "$ORG"
hammer content-view create --organization "$ORG" --composite --component-ids 3,4 --name 'Web Server View' --label web_server_view --description 'Web Server View'

echo Lab41

echo publish Web Server View takes ~12min
date
time hammer content-view publish --organization "$ORG" --name 'Web Server View' --description 'Initial Publishing' 2>/dev/null
# 12 min
echo promote Web Server View takes ~6min
date
time hammer content-view version promote --organization "$ORG" --content-view 'Web Server View' --to-lifecycle-environment Development 2>/dev/null
# 6 min

echo Lab42
echo "create activation key for Wordpress"
WORDPRESS_SUB_ID=$(hammer --csv --csv-separator ':' subscription list --organization "$ORG" | grep 'Wordpress' | cut -f 8 -d ':')
hammer activation-key create --organization "$ORG" --description 'Registering to Wordpress' --content-view 'Web Server View' --unlimited-content-hosts yes --name ak-Wordpress --lifecycle-environment 'Development'
hammer activation-key add-subscription --organization "$ORG" --name ak-Wordpress --subscription-id $WORDPRESS_SUB_ID

echo Lab43
echo "create hostgroup for Wordpress"
hammer hostgroup create --architecture x86_64 --content-source-id 1 --content-view 'Web Server View' --domain rhpds.opentlc.com --lifecycle-environment Development --locations "$LOC" --name 'LAMP Wordpress' --organizations "$ORG" --puppet-ca-proxy sat-$GUID.rhpds.opentlc.com --puppet-proxy sat-$GUID.rhpds.opentlc.com --subnet VM-Net --partition-table 'Kickstart default' --operatingsystem 'RedHat 6.6' --puppet-classes "wordpress" --medium "${ORG_LABEL}/Library/Red_Hat_Server/Red_Hat_Enterprise_Linux_6_Server_Kickstart_x86_64_6_6"  --parent RHEL6_Dev_Servers

hammer hostgroup set-parameter --name kt_activation_keys --value 'ak-Wordpress,ak-Reg_To_Development' --hostgroup 'LAMP Wordpress'

echo Lab44

echo "no automation"
echo Lab45

echo "no automation"
echo "Lab walkthrou is finished"
date

exit 0

# cleanup
# this section cleans up server and client in order to start the whole Lab all over again.
GUID=$(hostname -s|cut -d'-' -f2)
export GUID
ssh cli-$GUID.rhpds.opentlc.com subscription-manager unregister
ssh cli-$GUID.rhpds.opentlc.com yum -y erase katello-ca-consumer*
ssh cli-$GUID.rhpds.opentlc.com yum -y erase katello-agent puppet
ssh cli-$GUID.rhpds.opentlc.com rm -fr /var/lib/puppet
/usr/share/katello/script/katello-remove
