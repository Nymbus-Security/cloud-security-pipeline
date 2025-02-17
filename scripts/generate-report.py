from jinja2 import Template
import json
import glob

# Load all scan results
trivy_results = []
for file in glob.glob("trivy-*-results.json"):
    with open(file, "r") as f:
        trivy_results.extend(json.load(f).get("Results", []))

with open("checkov-results.json", "r") as f:
    checkov_results = json.load(f).get("results", {}).get("failed_checks", [])

# Scout Suite results (simplified)
scout_results = []
for file in glob.glob("scoutsuite-results/scoutsuite-results*.js"):
    with open(file, "r") as f:
        scout_results.append(json.load(f))

# Generate HTML
html_template = """
<html>
  <body>
    <h1>Security Report for {{ client_name }}</h1>
    <h2>Container & IaC Vulnerabilities</h2>
    {% for result in trivy_results %}
      {% for vuln in result.Vulnerabilities %}
        <div class="{{ vuln.Severity.lower() }}">
          <h3>{{ vuln.VulnerabilityID }}</h3>
          <p>{{ vuln.Description }}</p>
          <p><strong>Fix:</strong> {{ vuln.AI_Fix }}</p>
        </div>
      {% endfor %}
    {% endfor %}
    <h2>Compliance Gaps</h2>
    {% for check in checkov_results %}
      <div class="{{ check.severity.lower() }}">
        <h3>{{ check.check_name }}</h3>
        <p>{{ check.file_path }}</p>
        <p><strong>Fix:</strong> {{ check.AI_Fix }}</p>
      </div>
    {% endfor %}
  </body>
</html>
"""

report = Template(html_template).render(
    client_name=os.getenv("CLIENT_NAME"),
    trivy_results=trivy_results,
    checkov_results=checkov_results
)

with open("report.html", "w") as f:
    f.write(report)