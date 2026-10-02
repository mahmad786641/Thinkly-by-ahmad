import os
import requests
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("GROQ_API_KEY")

url = "https://api.groq.com/openai/v1/models"
headers = {
    "Authorization": f"Bearer {api_key}",
    "Content-Type": "application/json"
}

response = requests.get(url, headers=headers)
if response.status_code == 200:
    print("✅ Successfully retrieved available models:")
    print(response.json())
else:
    print(f"❌ Failed to retrieve models. Status code: {response.status_code}")
    print(response.text)