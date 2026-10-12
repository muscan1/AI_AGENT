import json
import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key= os.environ["OPEN_ROUTER_API_KEY"]
)

MODEL = "nvidia/nemotron-3-ultra-550b-a55b:free"

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


# The tool
def save_report(filename, content):
    os.makedirs("reports", exist_ok=True)
    safe_name = os.path.basename(filename)  # blocks paths like ../../x
    if not safe_name.endswith(".md"):
        safe_name += ".md"
    path = os.path.join("reports", safe_name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return f"Report saved to {path}"

#Tool description which the model sees
tools = [
    {
        "type": "function",
        "function": {
            "name":"save_report",
            "description":"Saves the report to a file",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "The path to the file where the report will be saved"
                    },
                    "content": {
                        "type": "string",
                        "description": "The content of the report to be saved"
                    }
                },
                "required": ["filename", "content"]
            }
        }
    }
]

finding = """
Target: shop.example.com (my own test lab)
I logged in as user A. Requested GET /api/orders/123 (my order).
Changed 123 to 124 and got another user's order with name,
address and phone number. No authorization error.
"""
messages = [
    {"role": "system", "content": SYSTEM_PROMPT},
    {"role": "user", "content": f"Write a report for this finding:\n{finding}"},
]
response = client.chat.completions.create(
    model=MODEL,
    messages= messages,
    tools=tools
)
if response.choices is None:
    print("API error:", response)
    raise SystemExit # used to intentionally trigger an exception
msg = response.choices[0].message

if msg.tool_calls:
    messages.append(msg)  # keep the model's request in the history
    for call in msg.tool_calls:
        args = json.loads(call.function.arguments)
        result = save_report(**args)  # YOUR code does the work
        print("TOOL RAN:", result)
        messages.append({
            "role": "tool",
            "tool_call_id": call.id,
            "content": result,
        })
    final = client.chat.completions.create(model=MODEL, messages=messages, tools=tools)
    print(final.choices[0].message.content)
else:
    print("The model did not call the tool:\n", msg.content)