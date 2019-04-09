# In many cases it is required to link hosts managed by Satellite to an external CMDB and
# add labels or group systems according to external parameters.
# This script shows how to attach labels and organize hosts in collections using
# a simple CSV list with such data.
# The first parameter "Service Group" is translated into a Host Collection,
# the other parameters are set as host parameters.

# The script relies on hosts with valid Hostname to be present in Satellite.

# The CSV for this examples takes the following entries:

# Service Group,Service Team,System Status,Hostname,Virtualization Area
# Storage,Linux L1,Live,host01.example.com,Convered Cloud
# Network,Linux L2,Live,host02.example.com,Public Cloud
# Business,Linux L3,Build Up,host03.example.com,On premise 
# Backup,Linux L2,Offline,host04.example.com,On premise
# Business,Linux L3,Disassembling,host05.example.com,On premise


export ORG="ACME"

while IFS=, read -r service_group service_team system_status hostname virtualization_area
do
    hammer host-collection info --organization=${ORG} --name="$service_group" >/dev/null 2>&1 || \
      hammer host-collection create --organization=${ORG} --name="$service_group"
    hammer host-collection add-host --organization=${ORG} --name "$service_group" --hosts "$hostname"
    hammer host set-parameter --host $hostname --name system_status --value="$system_status"
    hammer host set-parameter --host $hostname --name service_team --value="$service_team"
    hammer host set-parameter --host $hostname --name virtualization_area --value="$virtualization_area"
done < inventory.csv


# hammer host info --name $name
# hammer host list --search "params.system_status=Live"
