from jinja2 import Template
import json
import glob
import os

# Load results with error handling
def load_results(pattern):
    results = []
    for file in glob.glob(pattern):
        try:
            with open(file, "r") as f:
                data = json.load(f)
                if "Results" in data:  # Trivy format
                    results.extend(data["Results"])
                elif "failed_checks" in data.get("results", {}):  # Checkov format
                    results.extend(data["results"]["failed_checks"])
        except Exception as e:
            print(f"Error loading {file}: {str(e)}")
    return results

# Load data
trivy_results = load_results("trivy-*-results.json")
checkov_results = load_results("checkov-results.json")
scout_results = load_results("scoutsuite-results/*.json")  # If using Scout Suite add-on

# Severity-based categorization
def categorize_findings(results):
    categorized = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for item in results:
        severity = item.get("Severity") or item.get("severity") or "MEDIUM"
        categorized[severity.upper()].append(item)
    return categorized

# Generate report
report_template = """
<html>
  <head>
    <style>
      .critical { color: red; }
      .high { color: orange; }
      .medium { color: #CCCC00; }
      .low { color: green; }
    </style>
  </head>
  <body>
    <h1>Security Report - {{ client_name }}</h1>
    
    {% for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] %}
      <h2 class="{{ severity|lower }}">{{ severity }} Findings ({{ findings[severity]|length }})</h2>
      {% for finding in findings[severity] %}
        <div class="finding">
          <h3>{{ finding.title }}</h3>
          <p><strong>Source:</strong> {{ finding.tool }}</p>
          <p>{{ finding.description }}</p>
          <p class="fix"><strong>Remediation:</strong> {{ finding.fix }}</p>
        </div>
      {% endfor %}
    {% endfor %}
  </body>
</html>
"""

# Transform data for reporting
findings = []
for result in trivy_results + checkov_results + scout_results:
    findings.append({
        "title": result.get("VulnerabilityID") or result.get("check_name"),
        "description": result.get("Description") or result.get("guideline"),
        "fix": result.get("AI_Fix", "No remediation provided"),
        "severity": result.get("Severity") or result.get("severity"),
        "tool": "Trivy" if "VulnerabilityID" in result else "Checkov"
    })

categorized = categorize_findings(findings)

with open("report.html", "w") as f:
    f.write(Template(report_template).render(
        client_name=os.getenv("CLIENT_NAME", "Unknown Client"),
        findings=categorized
    ))