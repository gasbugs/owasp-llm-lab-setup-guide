import os

import boto3


def handler(event, context):
    course_id = os.environ["COURSE_ID"]
    region = os.environ["AWS_REGION"]
    dry_run = os.environ.get("DRY_RUN", "false").lower() == "true"

    ec2 = boto3.client("ec2", region_name=region)
    response = ec2.describe_instances(
        Filters=[
            {"Name": "tag:Course", "Values": [course_id]},
            {"Name": "instance-state-name", "Values": ["running"]},
        ]
    )

    instance_ids = [
        instance["InstanceId"]
        for reservation in response["Reservations"]
        for instance in reservation["Instances"]
    ]

    if instance_ids and not dry_run:
        ec2.stop_instances(InstanceIds=instance_ids)

    print(
        {
            "course_id": course_id,
            "region": region,
            "dry_run": dry_run,
            "stopped_instance_ids": instance_ids,
            "count": len(instance_ids),
        }
    )

    return {
        "course_id": course_id,
        "dry_run": dry_run,
        "stopped_instance_ids": instance_ids,
        "count": len(instance_ids),
    }
