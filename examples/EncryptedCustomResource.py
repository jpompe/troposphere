import awacs.kms as kms
import awacs.sts as sts
import troposphere.iam as iam
import awacs.logs
from awacs.aws import Action, Allow, AWSPrincipal, Principal, Policy, Statement
from troposphere import (
    Join,
    Ref,
    Template,
    Output,
    Parameter,
    Condition,
    Not,
    Equals,
    GetAtt,
    Base64
)
from troposphere.cloudformation import AWSCustomObject
from troposphere.iam import AccessKey, Group, LoginProfile, Role, PolicyType
from troposphere.awslambda import Function, Code
from troposphere.kms import Key

class EncryptedCustomResourceObject(AWSCustomObject):
    resource_type = "AWS::CloudFormation::CustomResource"

    props = {
        'ServiceToken': (basestring, True),
        'KeyId': (basestring, True),
        'PlainText': (basestring, True)
    }

def add_encrypted_params(template, N=1, names=None):
    """ add N encrypted params to template """

    LambdaExecutionRole = t.add_resource(Role(
        "LambdaExecutionRole",
        AssumeRolePolicyDocument=Policy(
            Statement=[
                Statement(
                    Effect=Allow,
                    Action=[sts.AssumeRole],
                    Principal=Principal("Service", ["lambda.amazonaws.com"])
                )
            ]
        ),
        Path="/",
        Policies=[
            iam.Policy(
                "LambdaLogsWritePolicy",
                PolicyName='root',
                PolicyDocument=Policy(
                    Statement=[
                        Statement(
                            Effect=Allow,
                            Action=[
                                awacs.logs.PutLogEvents,
                                awacs.logs.CreateLogGroup,
                                awacs.logs.CreateLogStream
                            ],
                            Resource=['*']
                        )
                    ]
                )
            )
        ]
    ))

    # there must be a better way sorry pep8
    #     with open('handler.py', 'r') as lambda_function_file:
    #        lambda_function_string = lambda_function_file.read()
    code = [
        "import base64",
        "import uuid",
        "import httplib",
        "import urlparse",
        "import json",
        "import boto3",
        "",
        "def send_response(request, response, status=None, reason=None):",
        "    ''' Send our response to the pre-signed URL supplied by CloudFormation",
        "",
        "    If no ResponseURL is found in the request, there is no place to send a",
        "    response. This may be the case if the supplied event was for testing.",
        "    '''",
        "",
        "    if status is not None:",
        "        response['Status'] = status",
        "",
        "    if reason is not None:",
        "        response['Reason'] = reason",
        "",
        "    if 'ResponseURL' in request and request['ResponseURL']:",
        "        url = urlparse.urlparse(request['ResponseURL'])",
        "        body = json.dumps(response)",
        "        https = httplib.HTTPSConnection(url.hostname)",
        "        https.request('PUT', url.path+'?'+url.query, body)",
        "",
        "    return response",
        "",
        "def handler(event, context):",
        "",
        "    response = {",
        "        'StackId': event['StackId'],",
        "        'RequestId': event['RequestId'],",
        "        'LogicalResourceId': event['LogicalResourceId'],",
        "        'Status': 'SUCCESS'",
        "    }",
        "",
        "    # PhysicalResourceId is meaningless here, but CloudFormation requires it",
        "    if 'PhysicalResourceId' in event:",
        "        response['PhysicalResourceId'] = event['PhysicalResourceId']",
        "    else:",
        "        response['PhysicalResourceId'] = str(uuid.uuid4())",
        "",
        "    # There is nothing to do for a delete request",
        "    if event['RequestType'] == 'Delete':",
        "        return send_response(event, response)",
        "",
        "    # Encrypt the value using AWS KMS and return the response",
        "    try:",
        "",
        "        for key in ['KeyId', 'PlainText']:",
        "            if key not in event['ResourceProperties'] or not event['ResourceProperties'][key]:",
        "                return send_response(",
        "                    event, response, status='FAILED',",
        "                    reason='The properties KeyId and PlainText must not be empty'",
        "                )",
        "",
        "        client = boto3.client('kms')",
        "        encrypted = client.encrypt(",
        "            KeyId=event['ResourceProperties']['KeyId'],",
        "            Plaintext=event['ResourceProperties']['PlainText']",
        "        )",
        "",
        "        response['Data'] = {",
        "            'CipherText': base64.b64encode(encrypted['CiphertextBlob']).decode('utf-8')",
        "        }",
        "        response['Reason'] = 'The value was successfully encrypted'",
        "",
        "    except Exception as E:",
        "        response['Status'] = 'FAILED'",
        "        response['Reason'] = 'UnhandledException, check cloudwatch logs'",
        "",
        "    return send_response(event, response)"
    ]

    CloudFormationKMSResourceLambdaFunction = t.add_resource(Function(
        "CloudFormationKMSResourceLambdaFunction",
        Code=Code(
            ZipFile=Join("\n", code)
        ),
        # ZipFile=lambda_function_string
        Handler="index.handler",
        Runtime="python2.7",
        Timeout="3",
        Role=GetAtt("LambdaExecutionRole", "Arn")
    ))

    for encrypted_param_num in xrange(N):
        if names:
            if names[0] == '[' and names[-1] == ']':
                encrypted_param_name = names[1:-1].split()[encrypted_param_num]
            else:
                encrypted_param_name = '{}{}'.format(
                    names,
                    encrypted_param_num
                )
        else:
            encrypted_param_name = 'SecretParameter{}'.format(encrypted_param_num)

        SecretParameter = t.add_parameter(Parameter(
            encrypted_param_name,
            Type="String",
            NoEcho=True
        ))

        KMSKey = t.add_resource(Key(
            '{}KMSKey'.format(encrypted_param_name),
            Description="Lambda backed cloudformation KMS encryption custom "\
                "resource encryption master key",
            Enabled=True,
            EnableKeyRotation=True,
            KeyPolicy=Policy(
                Version="2012-10-17",
                Id="{}-key-default-1".format(encrypted_param_name),
                Statement=[
                    Statement(
                        Sid="Enable IAM User Permissions",
                        Effect=Allow,
                        Principal=AWSPrincipal(Join(":", [
                            "arn:aws:iam:",
                            Ref("AWS::AccountId"),
                            "root"
                        ])),
                        Action=[
                            Action("kms", "*"),
                        ],
                        Resource=["*"]
                    ),
                    Statement(
                        Sid="Allow use of the key",
                        Effect=Allow,
                        Principal=AWSPrincipal(GetAtt("LambdaExecutionRole", "Arn")),
                        Action=[
                            awacs.kms.Encrypt,
                        ],
                        Resource=["*"],
                    )
                ]
            )
        ))

        EncryptedCustomResource = t.add_resource(EncryptedCustomResourceObject(
            "Encrypted{}".format(encrypted_param_name),
            ServiceToken=GetAtt("CloudFormationKMSResourceLambdaFunction", "Arn"),
            KeyId=Ref(KMSKey),
            PlainText=(Ref(SecretParameter))
        ))

        KMSKeyArn = t.add_output(Output(
            "{}KmsKeyArn".format(encrypted_param_name),
            Value=GetAtt("{}KMSKey".format(encrypted_param_name), "Arn")
        ))

        EncryptedCustomResourceCipherText = t.add_output(Output(
            "{}CipherText".format(encrypted_param_name),
            Value=GetAtt(
                "Encrypted{}".format(encrypted_param_name),
                "CipherText"
            ),
            Description="KMS encrypted value of {} (Base64 encoded)".format(
                encrypted_param_name
            )
        ))


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='add N encrypted params to CFN template'
    )

    parser.add_argument(
        '--num_sercret_params',
        '-N',
        default=1,
        type=int,
        choices=xrange(1, 51)
    )

    parser.add_argument(
        '--param_names',
        '-n',
        default=None,
        help='either a string basename to apply to N encrypted params, or a '
            'string list "[a, b, c]" of parameter names'
    )

    args = parser.parse_args()

    t = Template()

    t.add_description(
        "Example template showing Demonstration of encryption using KMS in a "
        "CloudFormation Template. "
        "For information on AWS Lambda-backed Custom Resources see:"
        "http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/"
        "template-custom-resources-lambda.html "
        "Inspired by https://github.com/RealSalmon/lambda-backed-cloud-"
        "formation-kms-encryption"
    )

    add_encrypted_params(t, args.num_sercret_params, args.param_names)

    print(t.to_json())
