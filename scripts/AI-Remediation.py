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

def generate_ai_response(prompt):
    """Generate an AI-based response using OpenAI's GPT."""
    retries = 3
    for i in range(retries):
        try:
            response = openai.ChatCompletion.create(
                model="gpt-4",  # You can change this to "gpt-3.5-turbo" if desired
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

def generate_compliance_explanation(vuln, frameworks):
    prompt = f"Explain how the following finding violates these compliance frameworks ({frameworks}): {vuln}. Provide recommendations to address this issue."
    return generate_ai_response(prompt)

def generate_devsecops_recommendation(findings_summary):
    prompt = f"Given these security findings: {findings_summary}, recommend actionable DevSecOps pipeline improvements that can prevent such issues in the future."
    return generate_ai_response(prompt)

def main():
    parser = argparse.ArgumentParser(description='Generate AI remediation for security findings with compliance mapping.')
    parser.add_argument('--trivy', required=True, help='Path to Trivy results file(s)')
    parser.add_argument('--checkov', required=True, help='Path to Checkov results file')
    parser.add_argument('--client', required=True, help='Client name')
    parser.add_argument('--resource-group', required=True, help='Resource Group or Project name')
    parser.add_argument('--compliance-map', required=True, help='Path to compliance mapping JSON file')
    args = parser.parse_args()

    # Load data
    trivy_files = glob.glob(args.trivy)
    trivy_results, checkov_results = [], load_json(args.checkov)
    compliance_map = load_json(args.compliance_map)

    # Load API Key
    openai.api_key = os.getenv('OPENAI_API_KEY')
    if not openai.api_key:
        logging.error("OpenAI API key not found in environment variables.")
        return

    # Process Trivy Results
    for trivy_file in trivy_files:
        data = load_json(trivy_file)
        if data:
            for result in data.get('Results', []):
                for vuln in result.get('Vulnerabilities', []):
                    finding_desc = vuln['Description']
                    vuln['AI_Fix'] = generate_ai_response(f"Explain how to fix: {finding_desc}")
                    vuln['Compliance_Explanation'] = generate_compliance_explanation(finding_desc, compliance_map.get(vuln['VulnerabilityID'], 'NIST, CIS, PCI DSS, ISO 27001, SOC 2, HIPAA'))

            trivy_results.append(data)

    # Process Checkov Results
    for check in checkov_results.get('results', {}).get('failed_checks', []):
        finding_desc = check['check_name']
        check['AI_Fix'] = generate_ai_response(f"Explain how to fix: {finding_desc}")
        check['Compliance_Explanation'] = generate_compliance_explanation(finding_desc, compliance_map.get(check['check_id'], 'NIST, CIS, PCI DSS, ISO 27001, SOC 2, HIPAA'))

    # Generate DevSecOps Recommendations
    findings_summary = f"Trivy: {len(trivy_results)} sets of results, Checkov: {len(checkov_results.get('results', {}).get('failed_checks', []))} failed checks"
    devsecops_recommendations = generate_devsecops_recommendation(findings_summary)

    # Save results
    result_file = f"ai-remediation-results-{args.client}.json"
    with open(result_file, 'w') as f:
        json.dump({
            'client': args.client,
            'resource_group': args.resource_group,
            'trivy': trivy_results,
            'checkov': checkov_results,
            'devsecops_recommendations': devsecops_recommendations
        }, f, indent=2)

    logging.info(f"AI remediation completed for {args.client}. Output saved to {result_file}")

if __name__ == "__main__":
    main()

