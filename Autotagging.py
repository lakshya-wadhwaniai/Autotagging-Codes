"""
This module is used for autotagging ec2 instances,RDS,S3,EFS with UUID and IAM USER Tag.
"""
import json
import uuid
import requests
import logging
from datetime import datetime
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TAG1 = 'Iam_User'
TAG2= 'Uuid'
uud = uuid.uuid4()
UID=str(uud)

def get_secret(secret_name, region_name):
    ''' Function to get the access credentials given the secretname. '''
    session = boto3.session.Session()
    secret_client = session.client(service_name='secretsmanager', region_name=region_name)
    get_secret_value_response = secret_client.get_secret_value(SecretId=secret_name)
    return get_secret_value_response['SecretString']
def check_for_tag(my_list,tag):
    """ This function checks whether resource has  passed tag or not
    tag->string, tag to check in list
    my_list->List containing all tags of particular resource
    returns True if it has tags and false otherwise
    """
    print('Looking for tag [' + tag + '] in list ' + json.dumps(my_list))
    for i in my_list:
        if i['Key'] == tag:
            return True
    return None

def check_and_get_email(my_list,tag):
    """ This function checks whether resource has Email tag or not and hence return email tag value
    my_list->List containing all tags of particular resource
    tag->string, tag to check in list
    returns email id if it has tags and false otherwise
    """
    print('Looking for tag [' + tag + '] in list ' + json.dumps(my_list))
    for i in my_list:
        if i['Key'] == tag:
            evalue=i['Value']
            return evalue
    return False
def send_mail(url, file_path, sender_email_id, recipient_email_id, email_subject, body_text, body_html,
            attachment_name, TOKEN):
    """
    Send email to recipients. Sends one mail to all recipients.
    url: The email service url
    sender_email_id: Email address of the sender
    recipient_email_id: List of email addresses to which the email is to be sent
    email_subject: Title of the email or Subject of the email
    body_text: Email content in text format
    body_html: Email content in HTML format
    file_path: Attachment path
    attachment_name: List of attachements name to the mail.
    The elements of the list are paths to the files that are to be attached.
    Return A dictionary with Source, Destination and RawMessage
    """
    if file_path:
        files = {"email_attachment": open(file_path, 'rb')}
    headers = {"TOKEN": TOKEN}
    data = {"sender_email_id": sender_email_id, "recipient_email_id": recipient_email_id,
            "email_subject": email_subject,
            "body_text": body_text,
            "body_html": body_html,
            "attachment_name": attachment_name,
            "persist_email": False}
    r = requests.post(url, data=data, files=files if file_path else None, headers=headers)
    return json.loads(r.text)["email_status"]
def tag_bucket(bucket, user,aws_region,email="Email",evalue=None):
    """ This function add tags to s3 buckets
    bucket->string, the name of s3 bucket
    user-> string, Name of Iam User creating resource
    aws_region->string, Region where the resource is being created,
    evalue ->string, the email id of user
    """
    s3_client = boto3.client('s3' ,region_name=aws_region)
    if evalue is not None:
        s3_client.put_bucket_tagging(
        Bucket=bucket,
        Tagging={
            'TagSet': [
                {
                    'Key': TAG1,
                    'Value': user
                },
                {
                    'Key': TAG2,
                    'Value': UID
                },
                {
                    'Key':email,
                    'Value':evalue
                }
            ]
        }
    )
    else:
        s3_client.put_bucket_tagging(
            Bucket=bucket,
            Tagging={
                'TagSet': [
                    {
                        'Key': TAG1,
                        'Value': user
                    },
                    {
                        'Key': TAG2,
                        'Value': UID
                    }
                ]
            }
        )

def tag_rds_instance(rds_instance, user,aws_region,email="Email",evalue=None):
    """ This function add tags to RDS
    rds_instance->string, the instance id of the RDS DATABASE
    user-> string, Name of Iam User creating resource
    aws_region->string, Region where the resource is being created,
    evalue ->string, the email id of user
    """
    rds_client = boto3.client('rds' ,region_name=aws_region)
    if evalue is not None:
        rds_client.add_tags_to_resource(
        ResourceName=rds_instance,
        Tags=[
            {
                'Key': TAG1,
                'Value': user
            },
                {
                    'Key': TAG2,
                    'Value': UID
                },
                {
                    'Key': email,
                    'Value': evalue
                }
        ]
    )
    else:
        rds_client.add_tags_to_resource(
            ResourceName=rds_instance,
            Tags=[
                {
                    'Key': TAG1,
                    'Value': user
                },
                    {
                        'Key': TAG2,
                        'Value': UID
                    }
            ]
        )

def tag_efs_instance(request_id, user,aws_region,email="Email",evalue=None):
    """ This function add tags to EFS
    request_id->string, the FileSystemId of the EFS
    user-> string, Name of Iam User creating resource
    aws_region->string, Region where the resource is being created,
    evalue ->string, the email id of user
    """
    efs_client = boto3.client('efs' ,region_name=aws_region)
    if evalue is not None:
        efs_client.create_tags(
        FileSystemId=request_id,
        Tags=[
            {
                'Key': TAG1,
                'Value': user
            },
                {
                    'Key': TAG2,
                    'Value': UID
                },
                {
                    'Key': email,
                    'Value': evalue
                }
        ]
    )
    else:
        efs_client.create_tags(
            FileSystemId=request_id,
            Tags=[
                {
                    'Key': TAG1,
                    'Value': user
                },
                    {
                        'Key': TAG2,
                        'Value': UID
                    }
            ]
        )
def aws_create_tag(_aws_region, _instance_id: str, _key_name: str, _tag_value: str):
    """
    This function is used for tagging ec2 instances with passed values as key value
    _aws_region->string, Region where the resource is being created,
    _instance_id->string, the instance id of the ec2 instance
    _key_name->string, the key for the tags
    _tag_value->string, the value for the tags
    returns true in case successfully tags and false otherwise
    """
    try:
        client = boto3.client('ec2', region_name=_aws_region)
        client.create_tags(Resources=[_instance_id, ], \
            Tags=[{'Key': _key_name, 'Value': _tag_value}, ])
        logging.info('successfuly created tag %s for instance %s', _key_name,_instance_id)
    except ClientError:
        logging.info(str(ClientError))
        return False
    return True

def find_username(event):
    """thie method find IAM Username
    event->dictionary, the event passsed via cloudtrial
    returns rhe username
    """
    user_name=' '
    try:
        if 'userIdentity' in event['detail']:
            if event['detail']['userIdentity']['type'] == 'AssumedRole':
                user_name = str('UserName: ' + event['detail']['userIdentity']['principalId']\
                    .split(':')[1] + ', Role: ' + event['detail']['userIdentity']\
                        ['sessionContext']['sessionIssuer']['userName'] + ' (role)')
            elif event['detail']['userIdentity']['type'] == 'IAMUser':
                user_name = event['detail']['userIdentity']['userName']
            elif event['detail']['userIdentity']['type'] == 'Root':
                user_name = 'root'
            else:
                logging.info('Could not determine username (unknown iam userIdentity) ')
                user_name = ''
        else:
            logging.info('Could not determine username (no userIdentity data in cloudtrail')
            user_name = ''
    except KeyError as ex_cep:
        logging.info('could not find username, exception: %s' , str(ex_cep))
        user_name = ''
    return user_name

def ebs_volume(instance_volumes,aws_region,user_name,instance_name,instance):
    """Helper function for ebs autotagging
    instance_volumes->list, the ebs volume,
    aws_region->string, Region where the resource is being created,
    user_name-> string, Name of Iam User creating resource,
    instance_name-> string, the ec2 instance name
    """
    client = boto3.client('ec2', region_name=aws_region)
    for volume in instance_volumes:
        response = client.describe_volumes(VolumeIds=[volume])
        volume_tags = [x['Tags'] for x in response['Volumes'] if 'Tags' in x]
        if volume_tags:
            if any(keys.get('Key') == 'Iam_User' and keys.get('Key')\
                == 'AttachedInstance' for keys in
                    volume_tags[0]):
                logging.info(
                    'Nothing to tag for volume %s of instance:\
                        %s, is already tagged', volume,instance)
                continue
            if not any(keys.get('Key') == 'Iam_User' for keys in volume_tags[0]):
                logging.info('Tag "Owner" doesn\'t exist, creating...')
                aws_create_tag(aws_region, volume, 'Iam_User', user_name)
                aws_create_tag(aws_region, volume, 'Uuid', UID)
            if not any(keys.get('Key') == 'AttachedInstance'\
                for keys in volume_tags[0]):
                logging.info('Tag "AttachedInstance" doesn\'t exist, creating...')
                aws_create_tag(aws_region, volume, 'AttachedInstance', \
                    instance + ' - ' + str(instance_name))
        else:
            logging.info('volume %s is not tagged, adding \
                Owner and AttachedInstance tags',volume)
            aws_create_tag(aws_region, volume, 'AttachedInstance',\
                instance + ' - ' + str(instance_name))
            aws_create_tag(aws_region, volume, 'Iam_User', user_name)
            aws_create_tag(aws_region, volume, 'Uuid', UID)

def inform(user_name,URL,TOKEN,infra_mail_id,email_sender,account_Id,aws_region):
    file_path = ""
    sender_email_id = email_sender
    recipient_email_id = infra_mail_id
    email_subject = 'Non-compliant IAM tag for user: ' + user_name
    body_text = ""
    body_html = '<html> <head></head> <body> Hi Admins, <p>You are receiving this notification as the IAM User: '+ user_name + ' in account : ' +account_Id + ' and region: ' +aws_region + ' is missing the Email tag. Due to tagging non-compliance, their newly created instance has been shut down. To resolve this issue, please add the Email tag to the user IAM user id.</p><p> Thanks,</p><p>Your AWS Admin</p> </body> </html>'
    attachment_name = "No attachment"
    logging.info(send_mail(URL, file_path, sender_email_id, recipient_email_id, email_subject, body_text, body_html,
                    attachment_name, TOKEN))
def ec2_tag(event,aws_region,user_name,value,infra_mail_id,email_sender,account_Id):
    """Helper function for ec2 autotagging
    event->dictionary, the event passsed via cloudtrial,
    aws_region->string, Region where the resource is being created,
    user_name-> string, Name of Iam User creating resource
    """
    try:
        instance_id = [x['instanceId'] for x in event['detail']\
            ['responseElements']['instancesSet']['items']]
    except KeyError:
        instance_id = []
    client = boto3.client('ec2', region_name=aws_region)
    today_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if instance_id:
        URL=value['URL']
        TOKEN=value['TOKEN']
        for instance in instance_id:
            # Let's tag the instance
            instance_api = client.describe_instances(InstanceIds=[instance])
            # Get all ec2 instance tags
            if 'Tags' in instance_api['Reservations'][0]['Instances'][0]:
                instance_tags = instance_api['Reservations'][0]['Instances'][0]['Tags']
            else:
                instance_tags = []
            # Check if 'Name' tag is exist for ec2 instance
            if instance_tags:
                instance_name = [x['Value'] for x in \
                    instance_tags if x['Key'] and x['Key'] == 'Name']
                if instance_name:
                    instance_name = instance_name[0]
            else:
                instance_name = user_name + " Instance"
            # Check if 'Iam user' tag exist in instance tags
            iam_client = boto3.client('iam')
            tags = iam_client.list_user_tags(UserName =user_name)
            email="Email"
            if instance_tags:
                if not check_for_tag(instance_tags,"Name"):
                    aws_create_tag(aws_region, instance, 'Name', user_name+ "_"+today_date)
                if not check_for_tag(instance_tags,email):
                    logging.info('Tag "Email" doesn\'t exist for instance \
                        %s, creating...',instance)
                    evalue=check_and_get_email(tags['Tags'],'Email')
                    if evalue is not None and evalue is not False:
                        aws_create_tag(aws_region, instance, 'Email',evalue)
                    else:
                        inform(user_name,URL,TOKEN,infra_mail_id,email_sender,account_Id,aws_region)
                aws_create_tag(aws_region, instance, 'Iam_User', user_name)
                aws_create_tag(aws_region, instance, 'Uuid', UID)
            else:
                logging.info('Instance %s has no tags, \
                    let\'s tag it with Iam_user and UUID tag' ,instance)
                evalue=check_and_get_email(tags['Tags'],'Email')
                if evalue is not None and evalue is not False:
                    aws_create_tag(aws_region, instance, 'Email',evalue)
                else:
                    inform(user_name,URL,TOKEN,infra_mail_id,email_sender,account_Id,aws_region)
                aws_create_tag(aws_region, instance, 'Iam_User', user_name)
                aws_create_tag(aws_region, instance, 'Uuid', UID)
                aws_create_tag(aws_region, instance, 'Name', user_name+ "_"+today_date)
            # Let's tag the instance volumes
            instance_volumes = [x['Ebs']['VolumeId'] for x in instance_api['Reservations']\
                [0]['Instances'][0]['BlockDeviceMappings']]
            # Check if volume already has tags
            ebs_volume(instance_volumes,aws_region,user_name,instance_name,instance)

def s3_tag(event,aws_region,user_name,value,infra_mail_id,email_sender,account_Id):
    """Helper function for s3 autotagging
    event->dictionary, the event passsed via cloudtrial,
    aws_region->string, Region where the resource is being created,
    user_name-> string, Name of Iam User creating resource
    """
    bucket = event['detail']['requestParameters']['bucketName']
    s3_client = boto3.client('s3' ,region_name=aws_region)
    iam_client = boto3.client('iam')
    tags = iam_client.list_user_tags(UserName =user_name)
    # check for existing tags
    try:
        bucket_tags = s3_client.get_bucket_tagging(Bucket=bucket)
        if check_for_tag(bucket_tags['TagSet'],"Email"):
            logging.info('Tag "Email"  exist for bucket %s',bucket)
            for i in bucket_tags['TagSet']:
                if i['Key'] == 'Email':
                    evalue=i['Value']
                    tag_bucket(bucket, user_name,aws_region,'Email',evalue)
        else:
            evalue=check_and_get_email(tags['Tags'],'Email')
            if evalue is not None and evalue is not False:
                tag_bucket(bucket, user_name,aws_region,'Email',evalue)
            else:
                tag_bucket(bucket, user_name,aws_region)
                inform(user_name,URL,TOKEN,infra_mail_id,email_sender,account_Id,aws_region)
    except ClientError:
        # if an exception is raised, the bucket is not tagged
        logging.info('No tags found on bucket %s',bucket)
        evalue=check_and_get_email(tags['Tags'],'Email')
        if evalue is not None and evalue is not False:
            tag_bucket(bucket, user_name,aws_region,'Email',evalue)
        else:
            tag_bucket(bucket, user_name,aws_region)
            inform(user_name,URL,TOKEN,infra_mail_id,email_sender,account_Id,aws_region)
        return

def rds_tag(event,aws_region,user_name,value,infra_mail_id,email_sender,account_Id):
    """Helper function for rds autotagging
    event->dictionary, the event passsed via cloudtrial,
    aws_region->string, Region where the resource is being created,
    user_name-> string, Name of Iam User creating resource
    """
    rds_client = boto3.client('rds' ,region_name=aws_region)
    rds_instance = event['detail']['responseElements']['dBInstanceArn']
    rds_tags = rds_client.list_tags_for_resource(ResourceName=rds_instance)
    iam_client = boto3.client('iam')
    tags = iam_client.list_user_tags(UserName =user_name)
    try:
        if check_for_tag(rds_tags['TagList'],"Email"):
            logging.info('Tag "Email"  exist for RDS Instance %s',rds_instance)
            tag_rds_instance(rds_instance, user_name,aws_region)
        else:
            evalue=check_and_get_email(tags['Tags'],'Email')
            if evalue is not None and evalue is not False:
                tag_rds_instance(rds_instance, user_name,aws_region,'Email',evalue)
            else:
                tag_rds_instance(rds_instance, user_name,aws_region)
                inform(user_name,URL,TOKEN,infra_mail_id,email_sender,account_Id,aws_region)
        return
    except KeyError:
        # if an exception is raised, the instance is not tagged
        logging.info('No tags found on RDS Instance %s',rds_instance)
        evalue=check_and_get_email(tags['Tags'],'Email')
        if evalue is not None and evalue is not False:
            tag_rds_instance(rds_instance, user_name,aws_region,'Email',evalue)
        else:
            tag_rds_instance(rds_instance, user_name,aws_region)
            inform(user_name,URL,TOKEN,infra_mail_id,email_sender,account_Id,aws_region)
        return

def efs_tag(event,aws_region,user_name,value,infra_mail_id,email_sender,account_Id):
    """Helper function for efs autotagging
    event->dictionary, the event passsed via cloudtrial,
    aws_region->string, Region where the resource is being created,
    user_name-> string, Name of Iam User creating resource
    """
    efs_client = boto3.client('efs' ,region_name=aws_region)
    request_id = event['detail']['requestParameters']['fileSystemId']
    efs_tags = efs_client.list_tags_for_resource(ResourceId=request_id)
    iam_client = boto3.client('iam')
    tags = iam_client.list_user_tags(UserName =user_name)
    try:
        if check_for_tag(efs_tags['TagList'],"Email"):
            logging.info('Tag "Email"  exist for EFS Instance %s',request_id)
            tag_efs_instance(request_id, user_name,aws_region)
        else:
            evalue=check_and_get_email(tags['Tags'],'Email')
            if evalue is not None and evalue is not False:
                tag_efs_instance(request_id, user_name,aws_region,'Email',evalue)
            else:
                tag_efs_instance(request_id, user_name,aws_region)
                inform(user_name,URL,TOKEN,infra_mail_id,email_sender,account_Id,aws_region)
        return
    except KeyError:
        # if an exception is raised, the instance is not tagged
        logging.info('No tags found on EFS instance %s',request_id)
        evalue=check_and_get_email(tags['Tags'],'Email')
        if evalue is not None and evalue is not False:
            tag_efs_instance(request_id, user_name,aws_region,'Email',evalue)
        else:
            tag_efs_instance(request_id, user_name,aws_region)
            inform(user_name,URL,TOKEN,infra_mail_id,email_sender,account_Id,aws_region)
        return

def lambda_handler(event, _context):
    """
    This method autotags 4 resources s3,ec2,rds,efs with email,Iam_User,UUID
    """
    if 'detail' in event:
        user_name=find_username(event)
        aws_region = event['detail']['awsRegion']
        account_Id = event['detail']['userIdentity']['accountId']
        with open('config.json') as file:
            data = json.load(file)
        email_sender=data['email_sender']
        secret_name=data['secret_name']
        secret_region=data['secret_region']
        infra_mail_id=data['infra_mail_id']
        aws_region = event['detail']['awsRegion']
        value=json.loads(get_secret(secret_name,secret_region))
        if event['source'] == "aws.ec2":
            ec2_tag(event,aws_region,user_name,value,infra_mail_id,email_sender,account_Id)
        elif event['source'] == "aws.s3":
            s3_tag(event,aws_region,user_name,value,infra_mail_id,email_sender,account_Id)
        elif event['source'] == "aws.rds":
            rds_tag(event,aws_region,user_name,value,infra_mail_id,email_sender,account_Id)
        elif event['source'] == "aws.elasticfilesystem":
            efs_tag(event,aws_region,user_name,value,infra_mail_id,email_sender,account_Id)