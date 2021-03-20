'''
Gran the IP addresses of all instances in an autoscaling group
and update the route53 dns records everytime the IP changes.
'''

import boto3

# functin returns list of IP addresses of instances with specific name tag
def get_ec2_ip():
	# connect to ec2
	ec2 = boto3.resource('ec2')

	# list to store the results
	ec2_ip_list = []
	ec2_info = {}
	newlist = []
	# get all instances that are in running state
	instances = ec2.instances.filter(Filters=[{
	    'Name': 'instance-state-name',
	    'Values': ['running']}])

	for instance in instances:
		for tag in instance.tags:
			if 'Name' in tag['Key']:
				name = tag['Value']

		if name == 'custom_name':
			ec2_ip_list.append(instance.private_ip_address)

	return ec2_ip_list


# functions adds IP address to route53
def create_route53(hosted_zone_id, ec2_ip_autoscaling_list):
	dns = boto3.client('route53')

	zones = dns.get_hosted_zone(Id=hosted_zone_id)
	# print(zones)
	name = zones['HostedZone']['Name']

	# random_string = ''.join(random.choice(string.digits) for _ in range(4))
	response = dns.change_resource_record_sets(
	    HostedZoneId=hosted_zone_id,
	    ChangeBatch={
	        "Comment": "Automatic DNS update of EC2 instances",
	        "Changes": [
	            {
	                "Action": "UPSERT",
	                "ResourceRecordSet": {
	                    "Name": 'udp.'+name,
	                    "Type": "A",
	                    # 'SetIdentifier': '9812',
	                    # 'Weight': 123,
	                    # "Region": "us-east-2",
	                    # 'MultiValueAnswer': True,
	                    "TTL": 300,
	                    "ResourceRecords": ec2_ip_autoscaling_list
	                }
	            }]
	    })

def main():
	hosted_zoneid = 'insert-zone-id'
	ec2_ip_autoscaling_list = [] # formatted list to feed to the route53 function
	ec2_ips = get_ec2_ip() # get the list of IP's
	for ec2_ip in ec2_ips:
		ec2_ip_autoscaling_list.append({'Value': ec2_ip}) # manipulate the list to get formatted list of dicts to feed to the route53 function
	create_route53(hosted_zone_id, ec2_ip_autoscaling_list)
	

if __name__ == '__main__':
	main()
