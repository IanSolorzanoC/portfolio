# Threat Model – AWS Secure Login Lab

## Assets

• User credentials
• Authentication tokens (JWT)
• DynamoDB user database
• API endpoints

---

## Threats

### Brute Force Attacks

Attackers may attempt to guess passwords by sending repeated login requests.

Mitigation:

• Account lock after multiple failures
• Rate limiting via API Gateway
• AWS WAF rate-based rules

---

### Credential Stuffing

Attackers may reuse credentials leaked from other services.

Mitigation:

• Login attempt monitoring
• WAF IP reputation filtering

---

### API Abuse

Attackers may flood the API with requests.

Mitigation:

• API Gateway throttling
• WAF rate limiting

---

### Token Forgery

Attackers may attempt to forge authentication tokens.

Mitigation:

• HMAC-signed JWT tokens
• Token expiration

---

## Logging and Monitoring

Security events are logged to CloudWatch.

Examples:

• failed login attempts
• account lock events
• successful authentication events
