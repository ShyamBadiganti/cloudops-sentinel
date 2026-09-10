import boto3
def get_iam_users():
    iam = boto3.client("iam")
    response = iam.list_users()
    users = []
    for user in response.get("Users", []):
        users.append({
            "username": user["UserName"],
            "user_id": user["UserId"],
            "arn": user["Arn"],
            "created": user["CreateDate"].isoformat(),
        })
    return users
