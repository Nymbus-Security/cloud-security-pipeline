import json
import argparse
from jinja2 import Environment, FileSystemLoader
from datetime import datetime
from weasyprint import HTML

def load_json(file_path):
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {file_path}: {str(e)}")
        return {}

def main():
    parser = argparse.ArgumentParser(description='Generate security assessment report.')
    parser.add_argument('--trivy', required=True, help='Path to Trivy results file(s)')
    parser.add_argument('--checkov', required=True, help='Path to Checkov results file')
    parser.add_argument('--opa', required=False, help='Path to OPA results file')
    parser.add_argument('--conftest', required=False, help='Path to Conftest results file')
    parser.add_argument('--ai', required=True, help='Path to AI remediation file')
    parser.add_argument('--client', required=True, help='Client name')
    parser.add_argument('--resource-group', required=True, help='Resource Group or Project name')
    args = parser.parse_args()

    # Load data
    trivy_results = load_json(args.trivy)
    checkov_results = load_json(args.checkov)
    opa_results = load_json(args.opa) if args.opa else {}
    conftest_results = load_json(args.conftest) if args.conftest else {}
    ai_results = load_json(args.ai)

    # Extract AI recommendations and findings
    devsecops_recommendations = ai_results.get('devsecops_recommendations', 'No recommendations provided.')
    trivy_findings = []
    for trivy in ai_results.get('trivy', []):
        for result in trivy.get('Results', []):
            trivy_findings.extend(result.get('Vulnerabilities', []))

    checkov_findings = ai_results.get('checkov', {}).get('results', {}).get('failed_checks', [])

    all_findings = trivy_findings + checkov_findings

    # Count findings
    trivy_findings_count = len(trivy_findings)
    checkov_findings_count = len(checkov_findings)

    # Collect OPA and Conftest policy violations
    opa_conftest_results = []
    for opa in opa_results.get('results', []):
        opa_conftest_results.append(opa.get('message', 'OPA violation found.'))

    for conftest in conftest_results.get('results', []):
        opa_conftest_results.append(conftest.get('msg', 'Conftest violation found.'))

    # Prepare Jinja2 template rendering
    env = Environment(loader=FileSystemLoader('report_template'))
    template = env.get_template('security-report-template.html')

    html_content = template.render(
        client=args.client,
        resource_group=args.resource_group,
        date=datetime.now().strftime("%Y-%m-%d"),
        trivy_findings_count=trivy_findings_count,
        checkov_findings_count=checkov_findings_count,
        devsecops_recommendations=devsecops_recommendations,
        all_findings=all_findings,
        opa_conftest_results=opa_conftest_results
    )

    # Output HTML file (optional for preview)
    with open('report/report.html', 'w') as f:
        f.write(html_content)

    # Generate PDF from HTML
    pdf_file = f"report/report-{args.client}.pdf"
    HTML(string=html_content).write_pdf(pdf_file)

    print(f"Report generated successfully: {pdf_file}")

if __name__ == "__main__":
    main()
