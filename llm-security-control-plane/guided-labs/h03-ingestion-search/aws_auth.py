"""Provided authentication loader: read-only credentials and server-owned resource IDs."""
import boto3


def load_aws_session(aws):
    connection = aws.authenticate()
    credentials = connection['credentials']
    session = boto3.Session(region_name=connection['region'],
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'])
    return session, dict(connection['binding'])
