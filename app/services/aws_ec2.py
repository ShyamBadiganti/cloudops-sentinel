import boto3
def get_ec2_instances():
    ec2 = boto3.client("ec2")
    response = ec2.describe_instances()
    instances = []
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            instances.append({
                "instance_id": instance["InstanceId"],
                "state": instance["State"]["Name"],
                "instance_type": instance["InstanceType"],
                "availability_zone": instance["Placement"]["AvailabilityZone"],
                "private_ip": instance.get("PrivateIpAddress", "N/A")
            })
    return instances
