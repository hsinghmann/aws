'''
Author: Harsh Mann

Usage: Given a list of AWS account ID's, get all the running resources like
EC2, RDS and ECR.

Required:
 1. A list of AWS account ID's.
 2. A cross account IAM role named "some-name" in each target AWS account with appropriate
    permissions like ec2readonly, rdsreadonly, iamreadonly and ecrreadonly.

The script is run from a centralized AWS account either as lambda function or could utilize the IAM user's
creds to run from local
'''

import json
import boto3
import requests
import os
from datetime import date
import datetime
# import re
# from collections import defaultdict
import csv
import itertools

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
base_url = '' # base url to upload the results (smartsheet api)
sheet_name = 'AWS Integrated Inventory: '+str(today_date)
headers = {'Authorization': 'Bearer '+my_bearer+'', 'Content-Disposition': 'attachment', 'Content-Type': 'text/csv', }


aws_profile_name = '' # source profile name to run the code from. Ignore and modify the code, if running as lambda.

# assume target IAM role
def assume_role(role_arn):
    sts = boto3.Session(profile_name=aws_profile_name).client('sts')
    assrole = sts.assume_role(RoleArn=role_arn,RoleSessionName='conmon')
    credentials = assrole['Credentials']
    return credentials

# get EC2 information and return a dictionary
def get_ec2(creds):
    aws = boto3.Session(
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken'],
    )
    aws_account_number = aws.client('sts').get_caller_identity().get('Account')
    aws_account_alias = aws.client('iam').list_account_aliases()['AccountAliases'][0]
    ec2 = aws.client('ec2')
    ec2_info = {}
    filters = [
        {
            'Name': 'instance-state-name', 
            'Values': ['running']
        }
    ]
    response = ec2.describe_instances(Filters=filters)['Reservations']
    if not response:
        name = 'No EC2'
        ec2_info[name] = {
            'Account': aws_account_number,
            'Account Name': aws_account_alias,
            'Resource Type': 'EC2'
        }
    else:
        for instance in response:
            for tag in instance['Instances'][0]['Tags']:
                if 'Name' in tag['Key']:
                    name = tag['Value']

                    ec2_info[name] = {
                        'Account': aws_account_number,
                        'Account Name': aws_account_alias,
                        'Resource Type': 'EC2',
                        'Private IP': instance['Instances'][0]['PrivateIpAddress'],
                        'Virtual': 'Yes',
                        'Public': 'No'
                    }
    return ec2_info

# get RDS information and return a dictionary
def get_rds(creds):
    aws = boto3.Session(
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken'],
    )
    aws_account_number = aws.client('sts').get_caller_identity().get('Account')
    aws_account_alias = aws.client('iam').list_account_aliases()['AccountAliases'][0]
    rds = aws.client('rds')

    # dictionary to store the RDS details output
    rds_info = {}

    # map instance arn to all the RDS details, instance arn is used to get the Tags
    instances = {
        instance['DBInstanceArn']: instance for instance in rds.describe_db_instances()['DBInstances']
    }
    if not instances:
        name = 'No RDS'
        rds_info[name] = {
            'Account': aws_account_number,
            'Account Name': aws_account_alias,
            'Resource Type': 'RDS'
        }
    else:
    # get tag and other details
        for arn, instance in instances.items():
            instance['Tags'] = rds.list_tags_for_resource(
                ResourceName=arn).get('TagList')

            rds_info[instance['DBInstanceIdentifier']] = {
                'Account': aws_account_number,
                'Account Name': aws_account_alias,
                'Resource Type': 'RDS',
                'Database Type': instance['DBInstanceClass'],
                'Database Version': instance['Engine']+'-'+instance['EngineVersion'],
                'Virtual': 'Yes',
                'Public': 'No'
            }
    return rds_info

# get ECR information and return a dictionary
def get_ecr(creds):
    aws = boto3.Session(
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken'],
    )
    aws_account_number = aws.client('sts').get_caller_identity().get('Account')
    aws_account_alias = aws.client('iam').list_account_aliases()['AccountAliases'][0]
    ecr = aws.client('ecr')
    ecr_info = {}
    repositories = ecr.describe_repositories()['repositories']
    if not repositories:
        name = 'No ECR'
        ecr_info[name] = {
            'Account': aws_account_number,
            'Account Name': aws_account_alias,
            'Resource Type': 'ECR'
        }
    else:
        for name in repositories:
            repo_name = name['repositoryName']
            ecr_info[name] = {
                'Account': aws_account_number,
                'Account Name': aws_account_alias,
                'Resource Type': 'ECR',
                'Virtual': 'Yes',
                'Public': 'No'
            }
    return ecr_info

# convert dictionary to csv file
def dict_to_csv():
    fields = ['Account', 'Account Name', 'Resource Type', 'Name', 'Private IP', 'Virtual', 'Public', 'Database Type', 'Database Version']
    with open(temp_file, 'w') as f:
        w = csv.DictWriter(f, fields)
        w.writeheader()
        for role in role_arns:
            inventory_dict = {**get_ec2(assume_role(role)), **get_rds(assume_role(role)), **get_ecr(assume_role(role))}
            for key, val in sorted(inventory_dict.items()):
                row = {'Name': key}
                row.update(val)
                w.writerow(row)

# ship csv file to smartsheet
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
    # remove temp csv file from the system
    try:
        os.remove(temp_file)
    except OSError as e:  ## if failed, report it back to the user ##
        print ("Error: %s - %s." % (e.filename, e.strerror))
