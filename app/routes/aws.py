from flask import Blueprint, render_template
from app.services.aws_ec2 import get_ec2_instances
from app.services.aws_s3 import get_s3_buckets
from app.services.aws_iam import get_iam_users
from app.services.aws_cloudwatch import get_cloudwatch_metrics
from app.services.aws_security import run_security_scan
aws_bp = Blueprint("aws", __name__, url_prefix="/aws")
@aws_bp.route("/dashboard")
def dashboard():
    ec2_instances = get_ec2_instances()
    s3_buckets = get_s3_buckets()
    iam_users = get_iam_users()
    cloudwatch_metrics = get_cloudwatch_metrics()
    security_findings = run_security_scan()
    security_score = 100
    high_count = 0
    medium_count = 0
    low_count = 0
    fail_count = 0
    warn_count = 0
    pass_count = 0
    for finding in security_findings:
        severity = str(finding.get("severity", "")).upper()
        status = str(finding.get("status", "")).upper()
        if severity == "HIGH":
            high_count += 1
        elif severity == "MEDIUM":
            medium_count += 1
        elif severity == "LOW":
            low_count += 1
        if status == "FAIL":
            fail_count += 1
        elif status == "WARN":
            warn_count += 1
        elif status == "PASS":
            pass_count += 1
        if status == "FAIL" and severity == "HIGH":
            security_score -= 30
        elif status == "WARN" and severity == "MEDIUM":
            security_score -= 15
        elif status == "WARN" and severity == "LOW":
            security_score -= 5
    security_score = max(0, security_score)
    security_summary = {
        "total": len(security_findings),
        "high": high_count,
        "medium": medium_count,
        "low": low_count,
        "fail": fail_count,
        "warn": warn_count,
        "pass": pass_count
    }
    return render_template(
        "aws_dashboard.html",
        ec2_instances=ec2_instances,
        s3_buckets=s3_buckets,
        iam_users=iam_users,
        cloudwatch_metrics=cloudwatch_metrics,
        security_findings=security_findings,
        security_score=security_score,
        security_summary=security_summary
    )
@aws_bp.route("/security")
def security_scan():
    findings = run_security_scan()
    return {
        "findings": findings,
        "total_findings": len(findings)
    }
