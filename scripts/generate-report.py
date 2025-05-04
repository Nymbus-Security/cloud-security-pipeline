#!/usr/bin/env python3
import os
import glob
import json
import argparse
import sys
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, TemplateNotFound
from weasyprint import HTML

def load_json(file_path):
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[WARN] File not found: {file_path}")
    except IsADirectoryError:
        print(f"[WARN] Path is a directory, not a file: {file_path}")
    except json.JSONDecodeError as e:
        print(f"[WARN] Malformed JSON in {file_path}: {e}")
    except Exception as e:
        print(f"[WARN] Unexpected error loading {file_path}: {e}")
    return {}

def load_json_glob(pattern):
    docs = []
    paths = glob.glob(pattern)
    if not paths:
        print(f"[WARN] No files matched pattern: {pattern}")
    for path in paths:
        if os.path.isdir(path):
            print(f"[WARN] Skipping directory match: {path}")
            continue
        doc = load_json(path)
        if isinstance(doc, list):
            docs.extend(doc)
        elif isinstance(doc, dict):
            docs.append(doc)
        else:
            print(f"[WARN] Unexpected JSON structure in {path}, skipping.")
    return docs

def main():
    parser = argparse.ArgumentParser(description='Generate security assessment report.')
    parser.add_argument('--trivy',   required=True, help='Glob pattern or path to Trivy JSON file(s)')
    parser.add_argument('--checkov', required=True, help='Path to Checkov JSON file')
    parser.add_argument('--opa',      help='Path to OPA JSON file (optional)')
    parser.add_argument('--conftest', help='Path to Conftest JSON file (optional)')
    parser.add_argument('--ai',       required=True, help='Path to AI remediation JSON file')
    parser.add_argument('--client',   required=True, help='Client name')
    parser.add_argument('--resource-group', required=True, help='Resource Group or Project name')
    args = parser.parse_args()

    client = args.client
    resource_group = args.resource_group
    generated_on = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Load Trivy findings from one or more files
    trivy_docs = load_json_glob(args.trivy)
    trivy_findings = []
    for doc in trivy_docs:
        results = doc.get('Results', []) or doc.get('results', [])
        for entry in results:
            vulns = entry.get('Vulnerabilities', []) or entry.get('vulnerabilities', [])
            trivy_findings.extend(vulns)

    # Load Checkov failed_checks
    checkov_doc = load_json(args.checkov)
    checkov_findings = []
    if isinstance(checkov_doc, dict):
        checkov_findings = checkov_doc.get('results', {}).get('failed_checks', [])

    # Load OPA results
    opa_findings = []
    if args.opa:
        opa_doc = load_json(args.opa)
        if isinstance(opa_doc, dict):
            opa_findings = [item.get('message', 'OPA violation') for item in opa_doc.get('results', [])]

    # Load Conftest results
    conftest_findings = []
    if args.conftest:
        conftest_doc = load_json(args.conftest)
        if isinstance(conftest_doc, dict):
            conftest_findings = [item.get('msg', 'Conftest violation') for item in conftest_doc.get('results', [])]

    # Load AI remediation recommendations
    ai_doc = load_json(args.ai)
    ai_recommendations = []
    if isinstance(ai_doc, dict):
        ai_recommendations = ai_doc.get('devsecops_recommendations') or ai_doc.get('recommendations') or []

    # Render the Jinja2 template
    try:
        env = Environment(loader=FileSystemLoader('report_template'))
        template = env.get_template('security-report-template.html')
    except TemplateNotFound:
        print("[ERROR] Template not found at report_template/security-report-template.html")
        sys.exit(1)

    html_content = template.render(
        client=client,
        resource_group=resource_group,
        generated_on=generated_on,
        trivy=trivy_findings,
        checkov=checkov_findings,
        opa_conftest=opa_findings + conftest_findings,
        ai_remediation=ai_recommendations
    )

    # Write HTML
    os.makedirs('report', exist_ok=True)
    html_path = f'report/report-{client}.html'
    with open(html_path, 'w') as f:
        f.write(html_content)
    print(f"[INFO] HTML report written to {html_path}")

    # Write PDF
    pdf_path = f'report/report-{client}.pdf'
    HTML(string=html_content).write_pdf(pdf_path)
    print(f"[INFO] PDF report written to {pdf_path}")

if __name__ == "__main__":
    main()
