import os
from dotenv import load_dotenv
from openai import OpenAI
load_dotenv()

client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.environ["OPEN_ROUTER_API_KEY"]
)

response = client.chat.completions.create(
    model = "nvidia/nemotron-3-ultra-550b-a55b:free",
    messages = [
        {"role": "system", "content": "You are a professional web security report writer."},
        {"role": "user", "content":"In just two sentences what is an IDOR vulnerability?"},
                ],
)
print(response.choices[0].message.content)