# access-analyzer
Used to either list all access analyzer findings, or scan a specific (or all) IAM policies for issues / recommendations.

For both scan and list functions it will create an access analyzer called `base2-access-analyzer` in either the region(s) specified (for list) or ap-southeast-2 by default (and for scan).

The `list` function isn't super useful, but the `scan` function is, you can scan every policy in the account, looking for specific findings, and even "grepping" for a string in the finding result (see examples).

## Usage
```
❯ ./main.py scan -h
usage: main.py scan [-h] [-a] [-p POLICYARN] [-t POLICYTYPE] [-f FINDINGTYPES] [-s SEARCHSTRING]

optional arguments:
  -h, --help       show this help message and exit
  -a               Scan all policies.
  -p POLICYARN     Policy ARN to scan.
  -t POLICYTYPE    Policy type (Identity, Resource, or ServiceControl).
  -f FINDINGTYPES  Comma seperated list of findingTypes (e.g. error, warning, security_warning, suggestion).
  -s SEARCHSTRING  findingDetails text to search for (useful for searching for specific rules).

❯ ./main.py list -h
usage: main.py list [-h] [-t RTYPE] [-r REGION] [-f FIELDS]

optional arguments:
  -h, --help  show this help message and exit
  -t RTYPE    Resource type, comma seperated (e.g. AWS::IAM::Role | AWS::KMS::Key | AWS::Lambda::Function | AWS::Lambda::LayerVersion | AWS::S3::Bucket | AWS::SQS::Queue | AWS::SecretsManager::Secret).
  -r REGION   Regions to check, comma seperated (defaults to ap-southeast-2).
  -f FIELDS   Fields to display, comma seperated (e.g. Resource, ResourceType, Principle, Condition, Action).

```

## Examples
### Scan a specific policy looking for only security_warning and errors
```
❯ ./main.py scan -p "arn:aws:iam::1234567890:policy/muhPolicy" -t resource -f security_warning,error
Found 1 policies
+----------------------------------------------------------+-------+--------------------------------------------------+-------------------+
|                           ARN                            | Type  |                     Details                      |    Issue Code     |
+----------------------------------------------------------+-------+--------------------------------------------------+-------------------+
| arn:aws:iam::1234567890:policy/muhPolicy | ERROR | Add a Principal element to the policy statement. | MISSING_PRINCIPAL |
+----------------------------------------------------------+-------+--------------------------------------------------+-------------------+
Total results: 1
```

### Scan all policies looking for any issues, using the policy as a resource
```
❯ ./main.py scan -a -t resource
Found 32 policies
+------------------------------------------------------------------------------------------------------------+------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+-------------------------------------+
|                                                    ARN                                                     |       Type       |                                                                               Details                                                                               |             Issue Code              |
+------------------------------------------------------------------------------------------------------------+------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+-------------------------------------+
|                      arn:aws:iam::1234567890:policy/muhPolicy                      |      ERROR       |                                                          Add a Principal element to the policy statement.                                                           |          MISSING_PRINCIPAL          |
|                       arn:aws:iam::1234567890:policy/muhPolicy                        |      ERROR       |                                                          Add a Principal element to the policy statement.                                                           |          MISSING_PRINCIPAL          |
|              arn:aws:iam::1234567890:policy/muhPolicy              |      ERROR       |                                                          Add a Principal element to the policy statement.                                                           |          MISSING_PRINCIPAL          |
|         arn:aws:iam::1234567890:policy/muhPolicy         |      ERROR       |                                                          Add a Principal element to the policy statement.                                                           |          MISSING_PRINCIPAL          |
|          arn:aws:iam::1234567890:policy/muhPolicy           |      ERROR       |                  Resource ARNs must include at least 6 fields and include the following structure: arn:partition:service:region:account:resource.                   |          MISSING_ARN_FIELD          |
|       arn:aws:iam::1234567890:policy/muhPolicy       | SECURITY_WARNING |     Using ForAllValues qualifier with the single-valued condition key ssm:resourceTag/env can be overly permissive. We recommend that you remove ForAllValues:.     | FORALLVALUES_WITH_SINGLE_VALUED_KEY |
|           arn:aws:iam::1234567890:policy/muhPolicy           |      ERROR       |                                                          Add a Principal element to the policy statement.                                                           |          MISSING_PRINCIPAL          |
|         arn:aws:iam::1234567890:policy/muhPolicy         |    SUGGESTION    |   The 2 action(s) are redundant because they provide similar permissions. Update the policy to remove the redundant action such as: cognito-idp:DescribeUserPool.   |          REDUNDANT_ACTION           |
|                                arn:aws:iam::1234567890:policy/muhPolicy                                |      ERROR       |                                                          Add a Principal element to the policy statement.                                                           |          MISSING_PRINCIPAL          |
|                            arn:aws:iam::1234567890:policy/muhPolicy                            |      ERROR       |                  Resource ARNs must include at least 6 fields and include the following structure: arn:partition:service:region:account:resource.                   |          MISSING_ARN_FIELD          |
|  arn:aws:iam::1234567890:policy/muhPolicy  | SECURITY_WARNING |     Using ForAllValues qualifier with the single-valued condition key ssm:resourceTag/env can be overly permissive. We recommend that you remove ForAllValues:.     | FORALLVALUES_WITH_SINGLE_VALUED_KEY |
|             arn:aws:iam::1234567890:policy/muhPolicy              |      ERROR       |                                                          Add a Principal element to the policy statement.                                                           |          MISSING_PRINCIPAL          |
+------------------------------------------------------------------------------------------------------------+------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+-------------------------------------+

```
### Scan all policies looking for any issues, using the policy as an identity
```
❯ ./main.py scan -a -t identity
Found 32 policies
+----------------------------------------------------------------------------------------------------------+------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-------------------------------------+
|                                                   ARN                                                    |       Type       |                                                                                                                                 Details
                                                                            |             Issue Code              |
+----------------------------------------------------------------------------------------------------------+------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-------------------------------------+
|                     arn:aws:iam::1234567890:policy/muhPolicy                     |    SUGGESTION    |                                                     The 2 action(s) are redundant because they provide similar permissions. Update the policy to remove the redundant action such as: cognito-idp:DescribeUserPool.                                                     |          REDUNDANT_ACTION           |
|                  arn:aws:iam::1234567890:policy/muhPolicy                   |      ERROR       |                                                                                                               The action athena:RunQuery does not exist.
                                                                            |           INVALID_ACTION            |
|       arn:aws:iam::1234567890:policy/muhPolicy        |    SUGGESTION    |                                                   The 2 action(s) are redundant because they provide similar permissions. Update the policy to remove the redundant action such as: cloudfront:GetDistributionConfig.                                                   |          REDUNDANT_ACTION           |
|        arn:aws:iam::1234567890:policy/muhPolicy        |    SUGGESTION    |                                                        The 2 action(s) are redundant because they provide similar permissions. Update the policy to remove the redundant action such as: cognito-idp:ListUsers.                                                         |          REDUNDANT_ACTION           |
|         arn:aws:iam::1234567890:policy/muhPolicy          |      ERROR       |                                                                    Resource ARNs must include at least 6 fields and include the following structure: arn:partition:service:region:account:resource.                                                                     |          MISSING_ARN_FIELD          |
|      arn:aws:iam::1234567890:policy/muhPolicy      | SECURITY_WARNING |                                                       Using ForAllValues qualifier with the single-valued condition key ssm:resourceTag/env can be overly permissive. We recommend that you remove ForAllValues:.                                                       | FORALLVALUES_WITH_SINGLE_VALUED_KEY |
|        arn:aws:iam::1234567890:policy/muhPolicy        | SECURITY_WARNING | Using the iam:PassRole action with wildcards (*) in the resource can be overly permissive because it allows iam:PassRole permissions on multiple resources. We recommend that you specify resource ARNs or add the iam:PassedToService condition key to your statement. |   PASS_ROLE_WITH_STAR_IN_RESOURCE   |
|                           arn:aws:iam::1234567890:policy/muhPolicy                           |      ERROR       |                                                                    Resource ARNs must include at least 6 fields and include the following structure: arn:partition:service:region:account:resource.                                                                     |          MISSING_ARN_FIELD          |
| arn:aws:iam::1234567890:policy/muhPolicy | SECURITY_WARNING |                                                       Using ForAllValues qualifier with the single-valued condition key ssm:resourceTag/env can be overly permissive. We recommend that you remove ForAllValues:.                                                       | FORALLVALUES_WITH_SINGLE_VALUED_KEY |
|         arn:aws:iam::1234567890:policy/muhPolicy          |      ERROR       |                                                                                                                  Add a Region to the ssm resource ARN.
                                                                            |         MISSING_ARN_REGION          |
+----------------------------------------------------------------------------------------------------------+------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-------------------------------------+
```

### Scan a policy looking for a specific finding string
*Note: Search strings are case sensitive, for a full list of findings, see here: [AWS](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html)*
```
❯ ./main.py -c 10 scan -a -t resource -s "Resource ARNs must include at least 6 fields and include"
Found 32 policies
+-----------------------------------------------------------------------------------------+-------+----------------------------------------------------------------------------------------------------------------------------------+-------------------+
|                                           ARN                                           | Type  |                                                             Details                                                              |    Issue Code     |
+-----------------------------------------------------------------------------------------+-------+----------------------------------------------------------------------------------------------------------------------------------+-------------------+
| arn:aws:iam::1234567890:policy/muhPolicy | ERROR | Resource ARNs must include at least 6 fields and include the following structure: arn:partition:service:region:account:resource. | MISSING_ARN_FIELD |
|                  arn:aws:iam::1234567890:policy/muhPolicy                   | ERROR | Resource ARNs must include at least 6 fields and include the following structure: arn:partition:service:region:account:resource. | MISSING_ARN_FIELD |
+-----------------------------------------------------------------------------------------+-------+----------------------------------------------------------------------------------------------------------------------------------+-------------------+
Total results: 2
```

### List all findings my access analyzer
*Note: You must specify which fields to show (Resource, ResourceType, Principle, Condition, Action)*
```
❯ ./main.py list -f resource,resourcetype,principle,condition,action
[ap-southeast-2] Waiting 15 seconds for Access Analyzer to run...
+----------------+-------------------------------------------------------------------------------------+----------------+----------------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------+-----------------------------------+
|                |                                       Region                                        |    Resource    |                                                                    ResourceType                                                                    |                                        Condition                                         |              Action               |
+----------------+-------------------------------------------------------------------------------------+----------------+----------------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------+-----------------------------------+
| ap-southeast-2 |        arn:aws:iam::1234567890:role/thisIsAroleName        | AWS::IAM::Role |                                                  {'Federated': 'cognito-identity.amazonaws.com'}                                                   | {'cognito-identity.amazonaws.com:aud': 'us-east-1:235235235-8adf-4699-9959-235235235'} | ['sts:AssumeRoleWithWebIdentity'] |
| ap-southeast-2 |                      arn:aws:iam::1234567890:role/AdminRole                       | AWS::IAM::Role |                                                              {'AWS': '1234567890'}                                                               |                                            {}                                            |        ['sts:AssumeRole']         |
| ap-southeast-2 |             arn:aws:iam::1234567890:role/thisIsAroleName             | AWS::IAM::Role |                       {'AWS': 'arn:aws:iam::1234567890:role/thisIsAroleName'}                        |                                            {}                                            |        ['sts:AssumeRole']         |
| ap-southeast-2 | arn:aws:iam::1234567890:role/thisIsAroleName | AWS::IAM::Role |                                                  {'Federated': 'cognito-identity.amazonaws.com'}                                                   | {'cognito-identity.amazonaws.com:aud': 'us-east-1:235235235-2f85-4ec9-8fe1-235235235'} | ['sts:AssumeRoleWithWebIdentity'] |
+----------------+-------------------------------------------------------------------------------------+----------------+----------------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------+-----------------------------------+
```