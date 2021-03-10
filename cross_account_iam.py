'''
Usage: Given a list of AWS account ID's, get all IAM information like a mapping of 
IAM users to their Groups, Permissions and Policies.

Required:
 1. A list of AWS account ID's.
 2. A cross account IAM role named "some-name" in each target AWS account with appropriate
    permissions like iamreadyonly.

The script is run from a centralized AWS account either as lambda function or could utilize the IAM user's
creds to run from local
'''

import boto3
from botocore.exceptions import ClientError
import csv
import requests
from datetime import date
import datetime
import os

# list of AWS account id's
account_ids = ['', '']

# get the target IAM role ARN that will be assumed by the script
role_arns = []
for account_id in account_ids:
    role_arns.append('arn:aws-us-gov:iam::'+account_id+':role/some-name')

temp_file = 'temp_file.csv' # temp file to store the results and ship it to smartsheet
today_date = datetime.datetime.now().strftime("%B-%d-%Y-%H:%M:%S") # date required in the sheet name

# Smartsheet API information, this is lambda format and will need to be modified
my_bearer = os.environ['BEARER']
folder_id = os.environ['FOLDER_ID']
base_url = '' # url to upload the results (smartsheet api)
sheet_name = 'IAM-'+today_date
headers = {'Authorization': 'Bearer '+my_bearer+'', 'Content-Disposition': 'attachment', 'Content-Type': 'text/csv', }


aws_profile_name = '' # aws profile from where the code is run (if not run as lambda)

# assume the target IAM role
def assume_role(role_arn):
    sts = boto3.Session(profile_name=aws_profile_name).client('sts')
    assrole = sts.assume_role(RoleArn=role_arn,RoleSessionName='conmon-test')

    credentials = assrole['Credentials']
    return credentials

# get IAM information and return a dictionary
def get_iam_users(creds):
	aws = boto3.Session(
		aws_access_key_id=creds['AccessKeyId'],
		aws_secret_access_key=creds['SecretAccessKey'],
		aws_session_token=creds['SessionToken']
	)
	aws_account_number = aws.client('sts').get_caller_identity().get('Account')
	aws_account_alias = aws.client('iam').list_account_aliases()['AccountAliases'][0]
	iam = aws.client('iam')
	resource_iam = aws.resource('iam')
	users = iam.list_users()
	user_dict = {}
	for key in users['Users']:
		result = {}
		group_names = []
		group_policy_names = []
		inline_policy_names = []
		policy_body = []
		console_access = []

		name = key['UserName']
		result['CreateDate'] = key['CreateDate'].strftime("%B-%d-%Y - %H:%M:%S")

		try:
		    response = iam.get_login_profile(UserName=key['UserName'])
		    console_access.append('Yes')
		    result['ConsoleAccess'] = 'Yes'
		except Exception as e:
		    if e.response['ResponseMetadata']['HTTPStatusCode'] == 404:
		        console_access.append('No')
		        result['ConsoleAccess'] = 'No'

		try:
			user_last_used = resource_iam.User(key['UserName'])
			result['LastActivity'] = user_last_used.password_last_used.strftime("%B-%d-%Y - %H:%M:%S")
		except:
			user_last_used = 'None'
			result['LastActivity'] = user_last_used

		response_mfa = iam.list_mfa_devices(UserName=key['UserName'])
		if response_mfa['MFADevices'] != [] and "mfa" in response_mfa['MFADevices'][0]['SerialNumber']:
		    result['MFAEnabled'] = 'Yes'
		else:
		    result['MFAEnabled'] = 'No'

		
		list_of_groups = iam.list_groups_for_user(UserName=key['UserName'])
		for group in list_of_groups['Groups']:
			group_names.append(group['GroupName'])
			group_policies = iam.list_attached_group_policies(GroupName=group['GroupName'])
			for group_policy in group_policies['AttachedPolicies']:
				group_policy_names.append(group_policy['PolicyName'])
				group_policy_body = resource_iam.Policy(group_policy['PolicyArn'])
				group_policy_version = group_policy_body.default_version
				policy_body.append(group_policy_version.document)

		result['Groups'] = ', '.join(group_names)
		result['GroupPolicyNames'] = ', '.join(group_policy_names)

		list_of_inline_policies = iam.list_attached_user_policies(UserName=key['UserName'])
		for inline_policy in list_of_inline_policies['AttachedPolicies']:
			inline_policy_names.append(inline_policy['PolicyName'])
			inline_policy_body = resource_iam.Policy(inline_policy['PolicyArn'])
			inline_policy_version = inline_policy_body.default_version
			policy_body.append(inline_policy_version.document)

		result['InlinePolicyName'] = ', '.join(inline_policy_names)

		result['PolicyBody'] = policy_body	

		user_dict[name] = {
			'CreateDate': result['CreateDate'],
			'Account Number': aws_account_number,
			'Account Name': aws_account_alias,
			'ConsoleAccess': result['ConsoleAccess'],
			'LastActivity': result['LastActivity'],
			'MFAEnabled': result['MFAEnabled'],
			'Groups': result['Groups'],
			'GroupPolicyNames': result['GroupPolicyNames'],
			'InlinePolicyName': result['InlinePolicyName'],
			'PolicyBody': result['PolicyBody']
		}
	return user_dict

# convert dictionary into csv
def dict_to_csv():
    fields = ['Account Name', 'Account Number', 'Name', 'CreateDate', 'ConsoleAccess', 'MFAEnabled', 'LastActivity', 'Groups', 'GroupPolicyNames', 'PolicyBody', 'InlinePolicyName']
    with open(temp_file, 'w') as f:
        w = csv.DictWriter(f, fields)
        w.writeheader()
        for role in role_arns:
            for key, val in get_iam_users(assume_role(role)).items():
                row = {'Name': key}
                row.update(val)
                w.writerow(row)

# upload csv file to Smartsheet
def ship_to_smartsheet():
    # call the create csv function
    dict_to_csv()
    with open(temp_file, 'rb') as payload:
        try:
            response = requests.post(base_url+str(folder_id)+'/sheets/import?sheetName='+str(sheet_name)+'&headerRowIndex=0&primaryColumnIndex=0', headers=headers, data=payload)
            output = response.json()
        except requests.exceptions.RequestException as e:
            raise SystemExit(e)  
    print(output)

if __name__ == "__main__":
	ship_to_smartsheet()
	try:
		os.remove(temp_file)
	except OSError as e:
		print("Error: %s - %s." % (e.filename, e.strerror))
