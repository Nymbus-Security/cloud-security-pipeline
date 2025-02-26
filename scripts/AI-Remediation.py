import json
import os
import argparse
import openai
import logging
import time
import glob

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
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Generate AI remediation for security findings')
    parser.add_argument('--trivy', required=True, help='Path to Trivy results file(s)')
    parser.add_argument('--checkov', required=True, help='Path to Checkov results file')
    args = parser.parse_args()

    # Load scan results
    trivy_files = glob.glob(args.trivy)
    trivy_results = []
    for trivy_file in trivy_files:
        trivy_data = load_json(trivy_file)
        if trivy_data:
            trivy_results.append(trivy_data)
    
    checkov_results = load_json(args.checkov)

    # Set OpenAI API key
    openai.api_key = os.getenv('OPENAI_API_KEY')
    if not openai.api_key:
        logging.error("OpenAI API key not found in environment variables.")
        return

    # Process Trivy results
    for result_set in trivy_results:
        for result in result_set.get('Results', []):
            for vuln in result.get('Vulnerabilities', []):
                vuln['AI_Fix'] = generate_fix(vuln['Description'])

    # Process Checkov results
    for check in checkov_results.get('results', {}).get('failed_checks', []):
        check['AI_Fix'] = generate_fix(check['check_name'])

    # Save enhanced results
    with open('ai-remediation-results.json', 'w') as f:
        json.dump({
            'trivy': trivy_results, 
            'checkov': checkov_results
        }, f, indent=2)
    logging.info("AI remediation completed successfully.")

if __name__ == "__main__":
    main()