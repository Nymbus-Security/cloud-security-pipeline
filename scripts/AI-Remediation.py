import json
import os
import openai

def load_json(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def generate_fix(vulnerability):
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",  # Cheaper than GPT-4
            messages=[
                {"role": "system", "content": "You are a cloud security engineer. Provide a step-by-step fix in plain English."},
                {"role": "user", "content": f"Explain how to fix: {vulnerability}"}
            ],
            temperature=0.3  # Keep responses technical
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error generating fix: {str(e)}"

# Load scan results
trivy_results = load_json('trivy-results.json')
checkov_results = load_json('checkov-results.json')

openai.api_key = os.getenv('OPENAI_API_KEY')

# Process Trivy results
for result in trivy_results.get('Results', []):
    for vuln in result.get('Vulnerabilities', []):
        vuln['AI_Fix'] = generate_fix(vuln['Description'])

# Process Checkov results
for check in checkov_results.get('results', {}).get('failed_checks', []):
    check['AI_Fix'] = generate_fix(check['check_name'])

# Save enhanced results
with open('combined-results.json', 'w') as f:
    json.dump({'trivy': trivy_results, 'checkov': checkov_results}, f)