import boto3
from datetime import datetime, timezone


def check_iam_mfa():
    iam = boto3.client("iam")

    findings = []

    users = iam.list_users().get("Users", [])

    for user in users:
        username = user["UserName"]

        mfa_devices = iam.list_mfa_devices(
            UserName=username
        ).get("MFADevices", [])

        if not mfa_devices:
            findings.append({
                "service": "IAM",
                "resource": username,
                "check": "MFA",
                "severity": "HIGH",
                "status": "FAIL",
                "message": "MFA is not enabled",
                "recommendation": "Enable MFA for this IAM user"
            })
        else:
            findings.append({
                "service": "IAM",
                "resource": username,
                "check": "MFA",
                "severity": "LOW",
                "status": "PASS",
                "message": "MFA is enabled",
                "recommendation": "No action required"
            })

    return findings


def check_iam_access_keys():
    iam = boto3.client("iam")

    findings = []

    users = iam.list_users().get("Users", [])

    for user in users:
        username = user["UserName"]

        access_keys = iam.list_access_keys(
            UserName=username
        ).get("AccessKeyMetadata", [])

        for key in access_keys:
            access_key_id = key["AccessKeyId"]
            status = key["Status"]
            created = key["CreateDate"]

            age_days = (
                datetime.now(timezone.utc) - created
            ).days

            if status == "Active" and age_days >= 90:
                findings.append({
                    "service": "IAM",
                    "resource": username,
                    "check": "Access Key Age",
                    "severity": "HIGH",
                    "status": "FAIL",
                    "message": (
                        f"Active access key {access_key_id} "
                        f"is {age_days} days old"
                    ),
                    "recommendation": (
                        "Rotate or review this access key"
                    )
                })

            elif status == "Active":
                findings.append({
                    "service": "IAM",
                    "resource": username,
                    "check": "Access Key",
                    "severity": "MEDIUM",
                    "status": "WARN",
                    "message": (
                        f"Active access key {access_key_id} "
                        f"is {age_days} days old"
                    ),
                    "recommendation": (
                        "Monitor and rotate access keys regularly"
                    )
                })

            else:
                findings.append({
                    "service": "IAM",
                    "resource": username,
                    "check": "Access Key",
                    "severity": "LOW",
                    "status": "PASS",
                    "message": (
                        f"Access key {access_key_id} is inactive"
                    ),
                    "recommendation": (
                        "No immediate action required"
                    )
                })

    return findings


def run_security_scan():
    findings = []

    findings.extend(check_iam_mfa())
    findings.extend(check_iam_access_keys())
    findings.extend(check_s3_public_access())
    findings.extend(check_s3_encryption())

    return findings
def check_s3_public_access():
    s3 = boto3.client("s3")

    findings = []

    buckets = s3.list_buckets().get("Buckets", [])

    for bucket in buckets:
        bucket_name = bucket["Name"]

        try:
            public_access = s3.get_public_access_block(
                Bucket=bucket_name
            ).get("PublicAccessBlockConfiguration", {})

            block_public_acls = public_access.get(
                "BlockPublicAcls", False
            )

            ignore_public_acls = public_access.get(
                "IgnorePublicAcls", False
            )

            block_public_policy = public_access.get(
                "BlockPublicPolicy", False
            )

            restrict_public_buckets = public_access.get(
                "RestrictPublicBuckets", False
            )

            all_blocked = all([
                block_public_acls,
                ignore_public_acls,
                block_public_policy,
                restrict_public_buckets
            ])

            if all_blocked:
                findings.append({
                    "service": "S3",
                    "resource": bucket_name,
                    "check": "Public Access",
                    "severity": "LOW",
                    "status": "PASS",
                    "message": "S3 public access is blocked",
                    "recommendation": "No action required"
                })
            else:
                findings.append({
                    "service": "S3",
                    "resource": bucket_name,
                    "check": "Public Access",
                    "severity": "HIGH",
                    "status": "FAIL",
                    "message": "S3 public access is not fully blocked",
                    "recommendation": (
                        "Enable all S3 Block Public Access settings"
                    )
                })

        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            findings.append({
                "service": "S3",
                "resource": bucket_name,
                "check": "Public Access",
                "severity": "HIGH",
                "status": "FAIL",
                "message": "S3 Block Public Access configuration is missing",
                "recommendation": (
                    "Enable S3 Block Public Access"
                )
            })

    return findings

def check_s3_encryption():
    s3 = boto3.client("s3")
    findings = []
    buckets = s3.list_buckets().get("Buckets", [])
    for bucket in buckets:
        bucket_name = bucket["Name"]
        try:
            encryption = s3.get_bucket_encryption(
                Bucket=bucket_name
            )
            rules = encryption.get(
                "ServerSideEncryptionConfiguration", {}
            ).get("Rules", [])
            if rules:
                findings.append({
                    "service": "S3",
                    "resource": bucket_name,
                    "check": "Encryption",
                    "severity": "LOW",
                    "status": "PASS",
                    "message": "S3 bucket encryption is enabled",
                    "recommendation": "No action required"
                })
            else:
                findings.append({
                    "service": "S3",
                    "resource": bucket_name,
                    "check": "Encryption",
                    "severity": "HIGH",
                    "status": "FAIL",
                    "message": "S3 bucket encryption is not configured",
                    "recommendation": "Enable server-side encryption for this S3 bucket"
                })
        except s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
            findings.append({
                "service": "S3",
                "resource": bucket_name,
                "check": "Encryption",
                "severity": "HIGH",
                "status": "FAIL",
                "message": "S3 bucket encryption is not configured",
                "recommendation": "Enable server-side encryption for this S3 bucket"
            })
    return findings

