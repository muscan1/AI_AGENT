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
REQUIRED_SECTIONS = [
    "Summary", "OWASP", "Severity", "Affected Asset",
    "Steps to Reproduce", "Proof of Concept",
    "Impact", "Remediation", "References",
]

# ---------- Tools ----------
def save_report(filename, content):
    os.makedirs("reports", exist_ok=True)
    safe_name = os.path.basename(filename)
    if not safe_name.endswith(".md"):
        safe_name += ".md"
    path = os.path.join("reports", safe_name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return f"Report saved to {path}"

def check_report(content):
    lower = content.lower()
    missing = [s for s in REQUIRED_SECTIONS if s.lower() not in lower]
    open_items = content.count("[NEEDS INFO")
    if missing:
        return f"FAIL. Missing sections: {', '.join(missing)}"
    return f"PASS. All sections present. Open [NEEDS INFO] items: {open_items}"

TOOL_FUNCTIONS = {"save_report": save_report, "check_report": check_report}

tools = [
    {"type": "function", "function": {
        "name": "check_report",
        "description": "Check that a draft report contains every required section. Call this before saving.",
        "parameters": {"type": "object",
            "properties": {"content": {"type": "string", "description": "The full draft report in Markdown"}},
            "required": ["content"]},
    }},
    {"type": "function", "function": {
        "name": "save_report",
        "description": "Save the final report as a Markdown file. Only call after check_report passes.",
        "parameters": {"type": "object",
            "properties": {
                "filename": {"type": "string", "description": "Short file name, e.g. idor-orders-api.md"},
                "content": {"type": "string", "description": "The full report in Markdown"}},
            "required": ["filename", "content"]},
    }},
]

# ---------- The loop ----------
def run_agent(task, max_steps=8):
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": task},
    ]

    for step in range(1, max_steps + 1):
        response = client.chat.completions.create(
            model=MODEL, messages=messages, tools=tools
        )
        if response.choices is None:
            print("API error:", response)
            return

        msg = response.choices[0].message
        messages.append(msg)

        if not msg.tool_calls:          # no tool requested = agent is done
            print("\nFINAL ANSWER:\n", msg.content)
            return

        for call in msg.tool_calls:
            name = call.function.name
            print(f"[step {step}] tool requested: {name}")
            try:
                args = json.loads(call.function.arguments)
                result = TOOL_FUNCTIONS[name](**args)
            except Exception as e:
                result = f"Tool error: {e}"
            print(f"           result: {result}")
            messages.append({
                "role": "tool",
                "tool_call_id": call.id,
                "content": result,
            })

    print("Stopped: reached max_steps without finishing.")

finding = """
Target: shop.example.com (my own test lab)
I logged in as user A. Requested GET /api/orders/123 (my order).
Changed 123 to 124 and got another user's order with name,
address and phone number. No authorization error.
"""

run_agent(f"Write a report for this finding:\n{finding}")