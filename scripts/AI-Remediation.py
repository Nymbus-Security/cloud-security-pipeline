import json
import os
import openai
import logging
import time

# Configure logging
logging.basicConfig(filename='pipeline.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_json(file_path):
    """Load JSON data from a file."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Failed to load {file_path}: {str(e)}")
        return {}

def generate_fix(vulnerability):
    """Generate a fix using OpenAI's GPT-3.5-turbo."""
    retries = 3
    for i in range(retries):
        try:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a cloud security engineer. Provide a step-by-step fix in plain English."},
                    {"role": "user", "content": f"Explain how to fix: {vulnerability}"}
                ],
                temperature=0.3  # Keep responses technical
            )
            return response.choices[0].message.content
        except Exception as e:
            logging.warning(f"Attempt {i + 1} failed: {str(e)}")
            time.sleep(2)  # Wait before retrying
    return "Failed to generate fix after retries."

def main():
    # Load scan results
    trivy_results = load_json('trivy-results.json')
    checkov_results = load_json('checkov-results.json')

    # Set OpenAI API key
    openai.api_key = os.getenv('OPENAI_API_KEY')
    if not openai.api_key:
        logging.error("OpenAI API key not found in environment variables.")
        return

    # Process Trivy results
    for result in trivy_results.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            vuln['AI_Fix'] = generate_fix(vuln['Description'])

    # Process Checkov results
    for check in checkov_results.get('results', {}).get('failed_checks', []):
        check['AI_Fix'] = generate_fix(check['check_name'])

    # Save enhanced results
    with open('combined-results.json', 'w') as f:
        json.dump({'trivy': trivy_results, 'checkov': checkov_results}, f, indent=2)
    logging.info("AI remediation completed successfully.")

if __name__ == "__main__":
    main()