import json
import os
import argparse
import openai

def load_findings(file_path):
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Failed to load {file_path}: {e}")
        return {}

def generate_rego_policy(vulnerability_description):
    prompt = (
        "You are a cloud security engineer specializing in Kubernetes and Terraform Policy as Code (OPA Rego/Conftest).\n"
        "Based on the following security finding, write an OPA Rego policy that will prevent this issue in future deployments.\n\n"
        f"Finding: {vulnerability_description}\n\n"
        "Only output the Rego code, do not explain anything else."
    )
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",  # Use GPT-4 or GPT-3.5
            messages=[
                {"role": "system", "content": "You write enterprise-ready security policies using OPA/Conftest."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3
        )
        return response['choices'][0]['message']['content']
    except Exception as e:
        print(f"Failed to generate policy: {e}")
        return "## Failed to generate policy."

def main():
    parser = argparse.ArgumentParser(description='Generate AI-based Rego/Conftest policies from scan results.')
    parser.add_argument('--ai', required=True, help='Path to AI remediation results file')
    parser.add_argument('--client', required=True, help='Client name for output directory')
    args = parser.parse_args()

    os.makedirs(f"generated-policies/{args.client}", exist_ok=True)

    ai_findings = load_findings(args.ai)

    all_findings = ai_findings.get('trivy', []) + [ai_findings.get('checkov', {})]
    policy_counter = 1

    for finding_set in all_findings:
        if isinstance(finding_set, list):  # Trivy findings
            for result in finding_set:
                for res in result.get('Results', []):
                    for vuln in res.get('Vulnerabilities', []):
                        description = vuln.get('Description', '')
                        if description:
                            policy_code = generate_rego_policy(description)
                            file_path = f"generated-policies/{args.client}/policy-{policy_counter}.rego"
                            with open(file_path, 'w') as f:
                                f.write(policy_code)
                            print(f"Generated policy saved to: {file_path}")
                            policy_counter += 1
        else:  # Checkov findings
            for check in finding_set.get('results', {}).get('failed_checks', []):
                description = check.get('check_name', '')
                if description:
                    policy_code = generate_rego_policy(description)
                    file_path = f"generated-policies/{args.client}/policy-{policy_counter}.rego"
                    with open(file_path, 'w') as f:
                        f.write(policy_code)
                    print(f"Generated policy saved to: {file_path}")
                    policy_counter += 1

    print(f"Total policies generated: {policy_counter - 1}")

if __name__ == "__main__":
    main()
