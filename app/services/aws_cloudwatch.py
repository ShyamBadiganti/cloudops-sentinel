import boto3
from datetime import datetime, timedelta, timezone
def get_cloudwatch_metrics():
    cloudwatch = boto3.client("cloudwatch")
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=1)
    metrics = []
    response = cloudwatch.list_metrics(
        Namespace="AWS/Usage"
    )
    for metric in response.get("Metrics", []):
        metric_name = metric["MetricName"]
        namespace = metric["Namespace"]
        dimensions = metric.get("Dimensions", [])
        datapoints = []
        try:
            statistics = cloudwatch.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=dimensions,
                StartTime=start_time,
                EndTime=end_time,
                Period=300,
                Statistics=["Sum"]
            )
            datapoints = statistics.get("Datapoints", [])
        except Exception:
            datapoints = []
        latest_value = 0
        if datapoints:
            latest = max(
                datapoints,
                key=lambda point: point["Timestamp"]
            )
            latest_value = latest.get("Sum", 0)
        metrics.append({
            "metric_name": metric_name,
            "namespace": namespace,
            "dimensions": dimensions,
            "latest_value": latest_value
        })
    return metrics
