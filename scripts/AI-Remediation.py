import json
import os
import argparse
import openai
import logging
import time
import glob

# Configure logging
logging.basicConfig(filename='pipeline.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# -----------------------------------------------
# Helper Functions
# -----------------------------------------------

def load_json(file_path):
    """Load JSON data from a file."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Failed to load {file_path}: {str(e)}")
        return {}

def generate_ai_response(prompt):
    """Generate an AI-based response using OpenAI's GPT."""
    retries = 3
    for i in range(retries):
        try:
            response = openai.ChatCompletion.create(
                model="gpt-4",  # You can switch to gpt-3.5-turbo if needed
                messages=[
                    {"role": "system", "content": "You are a cloud security and compliance expert."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3
            )
            return response.choices[0].message.content
        except Exception as e:
            logging.warning(f"Attempt {i + 1} failed: {str(e)}")
            time.sleep(2)
    return "Failed to generate AI response after retries."

# -----------------------------------------------
# AI-Driven Functions for Fixes & Compliance
# -----------------------------------------------

def generate_remediation(vuln_description):
    prompt = f"""
    You are a cybersecurity expert. Provide a step-by-step, actionable remediation plan for the following vulnerability or misconfiguration. Be clear and concise.

    Finding: {vuln_description}
    """
    return generate_ai_response(prompt)

def generate_compliance_mapping(vuln_description):
    prompt = f"""
    You are a cybersecurity compliance expert. Map the following finding to NIST 800-53, CIS Benchmarks, PCI DSS, ISO 27001, SOC 2, and HIPAA.
    For each framework, list the specific control IDs violated and explain why this finding violates them.
    Also provide a one-sentence recommendation for remediation in each framework.

    Finding: {vuln_description}
    """
    return generate_ai_response(prompt)

def generate_devsecops_recommendations(findings_summary):
    prompt = f"""
    You are a DevSecOps and security engineering expert. Given the following summary of security findings, recommend at least 3 actionable improvements to the DevSecOps pipeline or process that would help prevent or catch these issues earlier.

    Findings Summary: {findings_summary}
    """
    return generate_ai_response(prompt)

# -----------------------------------------------
# Main Function
# -----------------------------------------------

def main():
    parser = argparse.ArgumentParser(description='Generate AI remediation and compliance mapping for security findings.')
    parser.add_argument('--trivy', required=True, help='Path to Trivy results file(s)')
    parser.add_argument('--checkov', required=True, help='Path to Checkov results file')
    parser.add_argument('--client', required=True, help='Client name')
    parser.add_argument('--resource-group', required=True, help='Resource Group or Project name')
    args = parser.parse_args()

    # Load Trivy and Checkov results
    trivy_files = glob.glob(args.trivy)
    trivy_results = []
    checkov_results = load_json(args.checkov)

    # Load OpenAI API Key
    openai.api_key = os.getenv('OPENAI_API_KEY')
    if not openai.api_key:
        logging.error("OpenAI API key not found. Please set it in environment variables.")
        return

    # Process Trivy Results
    for trivy_file in trivy_files:
        data = load_json(trivy_file)
        if data:
            for result in data.get('Results', []):
                for vuln in result.get('Vulnerabilities', []):
                    description = vuln['Description']
                    vuln['AI_Fix'] = generate_remediation(description)
                    vuln['Compliance_Explanation'] = generate_compliance_mapping(description)
            trivy_results.append(data)

    # Process Checkov Results
    for check in checkov_results.get('results', {}).get('failed_checks', []):
        description = check['check_name'] + " - " + check.get('check_details', '')
        check['AI_Fix'] = generate_remediation(description)
        check['Compliance_Explanation'] = generate_compliance_mapping(description)

    # Summarize findings for DevSecOps Recommendations
    trivy_findings_count = sum(len(result.get('Vulnerabilities', [])) for trivy in trivy_results for result in trivy.get('Results', []))
    checkov_findings_count = len(checkov_results.get('results', {}).get('failed_checks', []))
    findings_summary = f"Trivy Findings: {trivy_findings_count}, Checkov Findings: {checkov_findings_count}"

    devsecops_recommendations = generate_devsecops_recommendations(findings_summary)

    # Save combined results
    output_file = f"ai-remediation-results-{args.client}.json"
    with open(output_file, 'w') as f:
        json.dump({
            "client": args.client,
            "resource_group": args.resource_group,
            "trivy": trivy_results,
            "checkov": checkov_results,
            "devsecops_recommendations": devsecops_recommendations
        }, f, indent=2)

    logging.info(f"AI remediation completed for {args.client}. Output saved to {output_file}")

if __name__ == "__main__":
    main()


