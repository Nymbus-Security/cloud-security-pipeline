import argparse
import glob
import json
import os
from jinja2 import Template

def load_results(pattern):
    """Load results with error handling and support for multiple files."""
    results = []
    for file in glob.glob(pattern):
        try:
            with open(file, "r") as f:
                data = json.load(f)
                # Process Trivy format
                if isinstance(data, list) and all("Results" in item for item in data):
                    for item in data:
                        results.extend(item.get("Results", []))
                elif "Results" in data:  # Single Trivy result
                    results.extend(data.get("Results", []))
                # Process Checkov format
                elif "failed_checks" in data.get("results", {}):
                    results.extend(data.get("results", {}).get("failed_checks", []))
                # Process AI remediation format
                elif "trivy" in data and "checkov" in data:
                    # Handle combined AI remediation results
                    for trivy_result in data.get("trivy", []):
                        results.extend(trivy_result.get("Results", []))
                    results.extend(data.get("checkov", {}).get("results", {}).get("failed_checks", []))
        except Exception as e:
            print(f"Error loading {file}: {str(e)}")
    return results

def categorize_findings(findings):
    """Categorize findings by severity."""
    categorized = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for finding in findings:
        severity = finding.get("severity", "").upper() or finding.get("Severity", "").upper() or "MEDIUM"
        if severity not in categorized:
            severity = "MEDIUM"  # Default if not recognized
        categorized[severity].append(finding)
    return categorized

def transform_findings(results):
    """Transform raw results into standardized finding format."""
    findings = []
    for result in results:
        # Handle Trivy vulnerabilities
        if "Vulnerabilities" in result:
            for vuln in result.get("Vulnerabilities", []):
                findings.append({
                    "title": vuln.get("VulnerabilityID", "Unknown Vulnerability"),
                    "description": vuln.get("Description", "No description provided"),
                    "fix": vuln.get("AI_Fix", "No remediation provided"),
                    "severity": vuln.get("Severity", "MEDIUM"),
                    "tool": "Trivy"
                })
        # Handle Checkov findings
        elif "check_id" in result:
            findings.append({
                "title": result.get("check_name", "Unknown Check"),
                "description": result.get("guideline", "No description provided"),
                "fix": result.get("AI_Fix", "No remediation provided"),
                "severity": result.get("severity", "MEDIUM"),
                "tool": "Checkov"
            })
    return findings

def main():
    parser = argparse.ArgumentParser(description='Generate security report')
    parser.add_argument('--trivy', help='Path to Trivy results file(s)')
    parser.add_argument('--checkov', help='Path to Checkov results file')
    parser.add_argument('--remediation', help='Path to AI remediation results file')
    args = parser.parse_args()

    # Load results from provided paths or fallback to default patterns
    all_results = []
    if args.trivy:
        all_results.extend(load_results(args.trivy))
    else:
        all_results.extend(load_results("trivy-*-results.json"))
    
    if args.checkov:
        all_results.extend(load_results(args.checkov))
    else:
        all_results.extend(load_results("checkov-results.json"))
    
    if args.remediation:
        all_results.extend(load_results(args.remediation))
    
    # Transform and categorize findings
    findings = transform_findings(all_results)
    categorized = categorize_findings(findings)

    # Report template
    report_template = """
    <html>
      <head>
        <title>Security Report - {{ client_name }}</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 20px; }
          .critical { color: #FF0000; }
          .high { color: #FF6600; }
          .medium { color: #FFCC00; }
          .low { color: #00CC00; }
          .finding { border: 1px solid #CCCCCC; padding: 10px; margin-bottom: 15px; border-radius: 5px; }
          h1 { color: #333366; }
          h2 { margin-top: 30px; }
          .fix { background-color: #F8F8F8; padding: 10px; border-left: 3px solid #333366; }
          .summary { margin-bottom: 30px; }
        </style>
      </head>
      <body>
        <h1>Security Report - {{ client_name }}</h1>
        
        <div class="summary">
          <h2>Executive Summary</h2>
          <p>This report identifies security vulnerabilities in your infrastructure and provides remediation guidance.</p>
          <ul>
            <li class="critical">Critical Issues: {{ findings['CRITICAL']|length }}</li>
            <li class="high">High Issues: {{ findings['HIGH']|length }}</li>
            <li class="medium">Medium Issues: {{ findings['MEDIUM']|length }}</li>
            <li class="low">Low Issues: {{ findings['LOW']|length }}</li>
          </ul>
        </div>
        
        {% for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] %}
          <h2 class="{{ severity|lower }}">{{ severity }} Findings ({{ findings[severity]|length }})</h2>
          {% if findings[severity]|length == 0 %}
            <p>No {{ severity|lower }} findings detected.</p>
          {% endif %}
          {% for finding in findings[severity] %}
            <div class="finding">
              <h3>{{ finding.title }}</h3>
              <p><strong>Source:</strong> {{ finding.tool }}</p>
              <p>{{ finding.description }}</p>
              <div class="fix"><strong>Remediation:</strong> {{ finding.fix }}</div>
            </div>
          {% endfor %}
        {% endfor %}
      </body>
    </html>
    """

    # Generate report
    with open("report.html", "w") as f:
        f.write(Template(report_template).render(
            client_name=os.getenv("CLIENT_NAME", "Cloud Security Assessment"),
            findings=categorized
        ))
    
    print("Report generated successfully: report.html")

if __name__ == "__main__":
    main()