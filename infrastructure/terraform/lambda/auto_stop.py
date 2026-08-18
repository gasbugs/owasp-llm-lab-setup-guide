import os

import boto3


def handler(event, context):
    course_id = os.environ["COURSE_ID"]
    region = os.environ["AWS_REGION"]
    dry_run = os.environ.get("DRY_RUN", "false").lower() == "true"

    autoscaling = boto3.client("autoscaling", region_name=region)
    paginator = autoscaling.get_paginator("describe_auto_scaling_groups")
    groups = [
        group
        for page in paginator.paginate()
        for group in page["AutoScalingGroups"]
        if any(
            tag["Key"] == "Course" and tag["Value"] == course_id
            for tag in group.get("Tags", [])
        )
    ]
    group_names = [group["AutoScalingGroupName"] for group in groups]

    if not dry_run:
        for group_name in group_names:
            autoscaling.update_auto_scaling_group(
                AutoScalingGroupName=group_name,
                MinSize=0,
                MaxSize=1,
                DesiredCapacity=0,
            )

    result = {
        "course_id": course_id,
        "region": region,
        "dry_run": dry_run,
        "scaled_to_zero_groups": group_names,
        "count": len(group_names),
    }
    print(result)
    return result
