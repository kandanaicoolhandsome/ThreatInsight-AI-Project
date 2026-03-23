import os
from google import genai
from dotenv import load_dotenv

load_dotenv()

client = genai.Client(
    api_key=os.environ.get("GEMINI_API_KEY"),
    http_options={'api_version': 'v1'}
)

print("--- LISTING MODELS ACCESSIBLE WITH YOUR API KEY ---")
try:
    for model in client.models.list():
        print(f"Model ID: {model.name}")
        print(f"Supported methods: {model.supported_generation_methods}")
        print("-" * 20)
except Exception as e:
    print(f"Error listing models: {str(e)}")
