#!/usr/bin/env python
import boto3
import argparse
import time
from tabulate import tabulate
import sys
import concurrent.futures

parser = argparse.ArgumentParser(description='Tool to scan / list Access Analyzer findings.')
subparsers = parser.add_subparsers(dest="command",help='sub-command help')
parser.add_argument('-c', dest='concurrentThreads', type=int, help='Number of threads to use.',required=False)

scan_parser = subparsers.add_parser('scan')
scan_parser.add_argument('-a', dest='allPolicies', action='store_true', help='Scan all policies.',required=False)
scan_parser.add_argument('-p', dest='policyArn', type=str, help='Policy ARN to scan.',required=False)
scan_parser.add_argument('-t', dest='policyType', type=str, help='Policy type (Identity, Resource, or ServiceControl).',required=False)
scan_parser.add_argument('-f', dest='findingTypes', type=str, help='Comma seperated list of findingTypes (e.g. error, warning, security_warning, suggestion).',required=False)
scan_parser.add_argument('-s', dest='searchString', type=str, help='findingDetails text to search for (useful for searching for specific rules).',required=False)

list_parser = subparsers.add_parser('list')
list_parser.add_argument('-t', dest='rtype', type=str, help='Resource type, comma seperated (e.g. AWS::IAM::Role | AWS::KMS::Key | AWS::Lambda::Function | AWS::Lambda::LayerVersion | AWS::S3::Bucket | AWS::SQS::Queue | AWS::SecretsManager::Secret).',required=False)
list_parser.add_argument('-r', dest='region', type=str, help='Regions to check, comma seperated (defaults to ap-southeast-2).',required=False)
list_parser.add_argument('-f', dest='fields', type=str, help='Fields to display, comma seperated (e.g. Resource, ResourceType, Principle, Condition, Action).',required=False)

args = parser.parse_args()

if not args.command:
    parser.parse_args(["-h"])
    sys.exit(0)

def createAnalyser(region):
    aa = boto3.client('accessanalyzer',region_name=region)
    try:
        response = aa.create_analyzer(analyzerName='base2-access-analyzer',type='ACCOUNT')
    except aa.exceptions.ConflictException:
        answer = input(f"Access Analyzer named 'base2-access-analyzer' exists in region {region}, delete? [y/n] ")
        if answer == 'y' or answer == 'Y':
            deleteAnalyser(region)
            response = aa.create_analyzer(analyzerName='base2-access-analyzer',type='ACCOUNT')
        else:
            sys.exit()
    except aa.exceptions.ServiceQuotaExceededException:
        print("You have reached your quota limit for access analyzers, unable to create")
        sys.exit()
    return response['arn']


def readAnalyser(region):
    aa = boto3.client('accessanalyzer',region_name=region)
    arn = aa.get_analyzer(analyzerName='base2-access-analyzer')['analyzer']['arn']
    print(f"[{region}] Waiting 15 seconds for Access Analyzer to run...")
    time.sleep(15)        

    if not rtypes:
        findings = aa.list_findings(analyzerArn=arn,maxResults=100,filter={'status':{'eq':['ACTIVE']}})
        results.append(findings['findings'])
        while 'nextToken' in findings:
            findings = aa.list_findings(analyzerArn=arn,nextToken=findings['nextToken'],filter={'status':{'eq':['ACTIVE']}},maxResults=100)
            results.append(findings['findings'])

    else:
        findings = aa.list_findings(analyzerArn=arn,filter={'resourceType':{'contains':rtypes},'status':{'eq':['ACTIVE']}},maxResults=100)
        results.append(findings['findings'])
        while 'nextToken' in findings:
            findings = aa.list_findings(analyzerArn=arn,filter={'resourceType':{'contains':rtypes},'status':{'eq':['ACTIVE']}},nextToken=findings['nextToken'],maxResults=100)
            results.append(findings['findings'])

    # Iterate through findings, printing result
    for x in results:
        if len(x) != 0:
            for y in x:
                outputline= [region]

                if "resource" in args.fields.lower().split(','):
                    outputline.append(y['resource'])
                if "resourcetype" in args.fields.lower().split(','):
                    outputline.append(y['resourceType'])
                if "principle" in args.fields.lower().split(','):
                    outputline.append(y['principal'])
                if "condition" in args.fields.lower().split(','):
                    outputline.append(y['condition'])
                if "action" in args.fields.lower().split(','):
                    outputline.append(y['action'])    

                output.append(outputline)
    
    deleteAnalyser(region)
    return output


def deleteAnalyser(region):
    aa = boto3.client('accessanalyzer',region_name=region)
    aa.delete_analyzer(analyzerName='base2-access-analyzer')


def getPolicies(iam):
    policies = []
    response = iam.list_policies(Scope='Local')
    for pol in response['Policies']:
        policies.append(pol['Arn'])
    
    while response['IsTruncated'] == True:
        marker = response['Marker']
        response = iam.list_policies(Marker=marker,Scope='Local')
        for pol in response['Policies']:
            policies.append(pol['Arn'])

    return policies

def checkPolicy(arn):
    policy = iam.get_policy(PolicyArn = arn)
    policy_version = iam.get_policy_version(PolicyArn = arn, VersionId = policy['Policy']['DefaultVersionId'])

    document = str(policy_version['PolicyVersion']['Document']).replace('\'','\"')

    if args.policyType.lower() == "identity":
        policyType = "IDENTITY_POLICY"
    elif args.policyType.lower() == "resource":
        policyType = "RESOURCE_POLICY"
    elif args.policyType.lower() == "servicecontrol":
        policyType = "SERVICE_CONTROL_POLICY"

    try:
        response = aa.validate_policy(policyDocument=f"{document}",policyType=policyType)['findings']
        for finding in response:
            if args.searchString and str(args.searchString) in finding['findingDetails']:
                if len(findingTypes) != 0:
                    if finding['findingType'] in findingTypes:
                        results = [arn,finding['findingType'],finding['findingDetails'],finding['issueCode']]
                else:
                    results = [arn,finding['findingType'],finding['findingDetails'],finding['issueCode']]
            elif args.searchString and str(args.searchString) not in finding['findingDetails']:
                continue
            else:
                if len(findingTypes) != 0:
                    if finding['findingType'] in findingTypes:
                        results = [arn,finding['findingType'],finding['findingDetails'],finding['issueCode']]
                else:
                    results = [arn,finding['findingType'],finding['findingDetails'],finding['issueCode']]
    except aa.exceptions.ValidationException:
        if len(findingTypes) == 0:
            results = [arn,"<Invalid Policy Syntax>","<Invalid Policy Syntax>","<Invalid Policy Syntax>"]

    output.append(results)

if args.command == "list":
    regions = []
    if args.region:
        for region in args.region.split(','):
            regions.append(region)
    else:
        regions.append('ap-southeast-2')

    if not args.concurrentThreads:
    	args.concurrentThreads = len(regions)

    rtypes = []
    if args.rtype:
        for rtype in args.rtype.split(','):
            rtypes.append(rtype)

    if args.fields == None:
        args.fields = ""

    results = []
    output = []
    head = ["Region"]
    if "resource" in args.fields.lower().split(','):
        head.append("Resource")
    if "resourcetype" in args.fields.lower().split(','):
        head.append("ResourceType")
    if "principal" in args.fields.lower().split(','):
        head.append("Principal")
    if "condition" in args.fields.lower().split(','):
        head.append("Condition")
    if "action" in args.fields.lower().split(','):
        head.append("Action")    

    for region in regions:
        createAnalyser(region)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrentThreads) as executor:
        executor.map(readAnalyser, regions)

    print(tabulate(output,head,tablefmt="pretty"))
    print(f"Total results: {len(output)}")



if args.command == "scan":
    results = []
    output = []
    findingTypes = []
    region='ap-southeast-2'
    head = ["ARN","Type","Details","Issue Code"]

    if args.findingTypes:
        for type in args.findingTypes.split(','):
            findingTypes.append(type.upper())

    if not args.concurrentThreads:
    	args.concurrentThreads = 1

    iam = boto3.client('iam')
    aa = boto3.client('accessanalyzer',region_name=region)
    createAnalyser(region)
    if args.allPolicies:
        policies = getPolicies(iam)
    else:
        policies = [args.policyArn]

    print(f"Found {len(policies)} policies")

    #for policy in policies:
    #    checkPolicy(policy)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrentThreads) as executor:
        executor.map(checkPolicy, policies)

    deleteAnalyser(region)

    print(tabulate(output,head,tablefmt="pretty"))
    print(f"Total results: {len(output)}")
