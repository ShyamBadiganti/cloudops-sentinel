from flask import Blueprint, render_template
from app.services.aws_ec2 import get_ec2_instances
from app.services.aws_s3 import get_s3_buckets
from app.services.aws_iam import get_iam_users
from app.services.aws_cloudwatch import get_cloudwatch_metrics
from app.services.aws_security import run_security_scan
main_bp = Blueprint("main", __name__)
@main_bp.route("/")
def index():
    ec2_instances = get_ec2_instances()
    s3_buckets = get_s3_buckets()
    iam_users = get_iam_users()
    cloudwatch_metrics = get_cloudwatch_metrics()
    findings = run_security_scan()
    security_issues = len([
        finding
        for finding in findings
        if finding.get("status", "").upper() in ["FAIL", "WARN"]
    ])
    security_score = 100
    for finding in findings:
        severity = finding.get("severity", "").upper()
        status = finding.get("status", "").upper()
        if status == "FAIL" and severity == "HIGH":
            security_score -= 30
        elif status == "WARN" and severity == "MEDIUM":
            security_score -= 15
        elif status == "WARN" and severity == "LOW":
            security_score -= 5
    security_score = max(0, security_score)
    aws_resources = (
        len(ec2_instances)
        + len(s3_buckets)
        + len(iam_users)
    )
    return render_template(
        "index.html",
        findings=findings,
        security_issues=security_issues,
        security_score=security_score,
        aws_resources=aws_resources,
        cloudwatch_metrics=cloudwatch_metrics
    )
