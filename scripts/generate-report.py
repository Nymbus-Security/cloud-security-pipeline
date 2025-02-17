import json
from jinja2 import Template

with open('combined-results.json', 'r') as f:
    data = json.load(f)

html_template = """
<html>
  <head>
    <title>Cloud Security Report</title>
    <style>
      body { font-family: Arial; }
      .critical { color: red; }
      .high { color: orange; }
    </style>
  </head>
  <body>
    <h1>Security Report</h1>
    <h2>Trivy Findings</h2>
    {% for result in data.trivy.Results %}
      {% for vuln in result.Vulnerabilities %}
        <div class="{{ vuln.Severity.lower() }}">
          <h3>{{ vuln.VulnerabilityID }} ({{ vuln.Severity }})</h3>
          <p>{{ vuln.Description }}</p>
          <p><strong>Fix:</strong> {{ vuln.AI_Fix }}</p>
        </div>
      {% endfor %}
    {% endfor %}
    <h2>Checkov Findings</h2>
    {% for check in data.checkov.results.failed_checks %}
      <div class="{{ check.severity.lower() }}">
        <h3>{{ check.check_name }} ({{ check.severity }})</h3>
        <p>File: {{ check.file_path }}</p>
        <p><strong>Fix:</strong> {{ check.AI_Fix }}</p>
      </div>
    {% endfor %}
  </body>
</html>
"""

report = Template(html_template).render(data=data)
with open('report.html', 'w') as f:
    f.write(report)