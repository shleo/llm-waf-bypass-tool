import json
import requests

with open('../llm_config.json', 'r', encoding='utf-8') as f:
    config = json.load(f)

headers = {
    'Authorization': f"Bearer {config['api_key']}",
    'Content-Type': 'application/json'
}

payload = {
    'model': config['model'],
    'messages': [
        {'role': 'system', 'content': 'You are a helpful assistant.'},
        {'role': 'user', 'content': 'Say hello'}
    ],
    'temperature': 0.7
}

endpoint = f"{config['base_url'].rstrip('/')}/chat/completions"

print(f'Testing model: {config["model"]}')
print(f'Endpoint: {endpoint}')
print(f'API Key: {config["api_key"][:20]}...')

try:
    response = requests.post(endpoint, headers=headers, json=payload, timeout=30)
    print(f'\\nStatus Code: {response.status_code}')
    print(f'Response: {response.text[:500]}')
    
    if response.status_code == 200:
        result = response.json()
        if 'error' in result:
            print(f'\\nAPI Error: {result["error"]}')
    else:
        print(f'\\nHTTP Error Response')
except Exception as e:
    print(f'\\nException: {type(e).__name__}: {e}')