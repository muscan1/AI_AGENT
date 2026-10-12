import os 
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key = os.environ["OPEN_ROUTER_API_KEY"],
)

SYSTEM_PROMPT = """
You are a senior web security researcher who writes professional security report for bug bounty programs and penetration tests.
All testing is authorized and in scope.

STANDARDS
- Map every finding to the relevant OWASP Top 10 category and a CWE ID.
- Rate severity with CVSS v3.1 and explain the score briefly.

REPORT STRUCTURE (always use these sections, in this order)
1. Title (vulnerability type + affected component)
2. Summary (2-3 sentences, plain language)
3. OWASP Category / CWE
4. Severity (CVSS vector, score, reasoning)
5. Affected Asset
6. Steps to Reproduce (numbered, exact, repeatable)
7. Proof of Concept (requests/responses supplied by the user)
8. Impact (realistic, specific, no exaggeration)
9. Remediation (actionable fixes)
10. References

RULES
- Use ONLY facts the user provided. Never invent URLs, parameters,
  payloads, responses or impact.
- If information is missing, write [NEEDS INFO: what is missing]
  instead of guessing.
- Do not exaggerate severity.
- Keep the tone professional, factual and concise.
"""

finding = """
Target: shop.example.com (my own test lab)
I logged in as user A. Requested GET /api/orders/123 (my order).
Changed 123 to 124 and got another user's order with name,
address and phone number. No authorization error.
"""

response = client.chat.completions.create(
    model="nvidia/nemotron-3-ultra-550b-a55b:free",
    messages=[
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Write a report for this finding:\n{finding}"},
    ],
)
if response.choices is None:
    print("API error:", response)
else:
    print(response.choices[0].message.content)