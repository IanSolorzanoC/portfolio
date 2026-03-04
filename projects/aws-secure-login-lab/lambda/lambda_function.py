import json
import boto3
import hashlib
import time
import os
import base64
import hmac

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('cs-lab-users')

MAX_ATTEMPTS = 5
LOCK_TIME_SECONDS = 300

JWT_SECRET = os.environ.get("JWT_SECRET", "")
JWT_ISSUER = os.environ.get("JWT_ISSUER", "cs-lab")
JWT_TTL_SECONDS = int(os.environ.get("JWT_TTL_SECONDS", "900"))


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def jwt_sign_hs256(payload: dict) -> str:
    if not JWT_SECRET:
        raise RuntimeError("JWT_SECRET is not set")

    header = {"alg": "HS256", "typ": "JWT"}

    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    signing_input = f"{header_b64}.{payload_b64}".encode()

    signature = hmac.new(
        JWT_SECRET.encode(),
        signing_input,
        hashlib.sha256
    ).digest()

    signature_b64 = b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{signature_b64}"


def verify_jwt(token: str):
    try:
        header_b64, payload_b64, signature = token.split(".")

        signing_input = f"{header_b64}.{payload_b64}".encode()

        expected_sig = hmac.new(
            JWT_SECRET.encode(),
            signing_input,
            hashlib.sha256
        ).digest()

        if b64url_encode(expected_sig) != signature:
            return None

        payload = json.loads(b64url_decode(payload_b64))

        if payload["exp"] < int(time.time()):
            return None

        return payload

    except Exception:
        return None


def get_source_ip(event):
    try:
        return event.get("requestContext", {}).get("identity", {}).get("sourceIp", "unknown")
    except Exception:
        return "unknown"


def get_auth_header(event):
    headers = event.get("headers") or {}

    # buscar Authorization sin importar mayúsculas
    for key in headers:
        if key.lower() == "authorization":
            return headers[key]

    # fallback: multiValueHeaders
    mvh = event.get("multiValueHeaders") or {}
    for key in mvh:
        if key.lower() == "authorization":
            return mvh[key][0]

    return None


def safe_json_body(event):
    body_raw = event.get("body")

    if not body_raw:
        return {}

    if isinstance(body_raw, str):
        return json.loads(body_raw)

    return body_raw


def lambda_handler(event, context):

    path = event.get("resource", "")
    method = event.get("httpMethod", "")

    now = int(time.time())
    src_ip = get_source_ip(event)

    # -----------------------------
    # Protected endpoint
    # -----------------------------

    if path.endswith("/me") and method == "GET":

        auth_header = get_auth_header(event)

        if not auth_header or not auth_header.startswith("Bearer "):
            return {
                "statusCode": 401,
                "body": json.dumps({"message": "Missing token"})
            }

        token = auth_header.split(" ")[1]

        payload = verify_jwt(token)

        if not payload:
            return {
                "statusCode": 401,
                "body": json.dumps({"message": "Invalid token"})
            }

        return {
            "statusCode": 200,
            "body": json.dumps({
                "username": payload["sub"],
                "role": payload["role"]
            })
        }

    # -----------------------------
    # Login endpoint
    # -----------------------------

    try:
        body = safe_json_body(event)
    except Exception:
        return {
            "statusCode": 400,
            "body": json.dumps({"message": "Invalid request"})
        }

    username = body.get("username")
    password = body.get("password")

    if not username or not password:
        return {
            "statusCode": 400,
            "body": json.dumps({"message": "Invalid request"})
        }

    response = table.get_item(Key={"username": username})

    if "Item" not in response:
        return {
            "statusCode": 401,
            "body": json.dumps({"message": "Invalid username or password"})
        }

    user = response["Item"]

    if user.get("lock_until", 0) > now:
        return {
            "statusCode": 403,
            "body": json.dumps({"message": "Account temporarily locked"})
        }

    hashed_input = hash_password(password)

    if user.get("password") == hashed_input:

        table.update_item(
            Key={"username": username},
            UpdateExpression="SET failed_attempts = :z, lock_until = :lu",
            ExpressionAttributeValues={":z": 0, ":lu": 0},
        )

        role = user.get("role", "user")

        payload = {
            "iss": JWT_ISSUER,
            "sub": username,
            "role": role,
            "iat": now,
            "exp": now + JWT_TTL_SECONDS
        }

        token = jwt_sign_hs256(payload)

        return {
            "statusCode": 200,
            "body": json.dumps({
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": JWT_TTL_SECONDS
            }),
        }

    failed_attempts = int(user.get("failed_attempts", 0)) + 1

    update_expression = "SET failed_attempts = :fa"
    expression_values = {":fa": failed_attempts}

    if failed_attempts >= MAX_ATTEMPTS:
        lock_until = now + LOCK_TIME_SECONDS
        update_expression += ", lock_until = :lu"
        expression_values[":lu"] = lock_until

    table.update_item(
        Key={"username": username},
        UpdateExpression=update_expression,
        ExpressionAttributeValues=expression_values,
    )

    return {
        "statusCode": 401,
        "body": json.dumps({"message": "Invalid username or password"})
    }
