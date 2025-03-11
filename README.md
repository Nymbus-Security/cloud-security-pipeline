## 🌐 Overview

This **Cloud Security Assessment Pipeline** is a fully automated **Cloud and IaC scanning framework** that performs security and compliance assessments across multiple client environments. It leverages **AI remediation**, **custom Policy-as-Code (OPA/Conftest)** generation, and **automated PDF reporting**, making it ideal for **managed service offerings** and **enterprise security assessments**.

---

## ✅ **Key Features**

- **Multi-Client, Parallel Cloud Security Scans** (Matrix-based execution)
- **AI-Powered Remediation Recommendations** (OpenAI GPT integration)
- **AI-Generated Rego & Conftest Policy-as-Code (PaC)**
- **IaC and Compliance Scanning**:
  - **Checkov** for Terraform, Kubernetes, CloudFormation
  - **Regula** for Terraform compliance checks
  - **Prowler** for AWS Security Benchmarks & CIS
  - **Steampipe** for live compliance queries (PCI, NIST, HIPAA, ISO, SOC2)
- **Container Security Scanning** with Trivy
- **Automated Jinja2 & WeasyPrint PDF Reports**
- **Compliance Mappings** for CIS, NIST 800-53, PCI-DSS, ISO 27001, SOC 2, HIPAA
- **Customizable Branding & Reports**

---

## ⚙️ **Pipeline Setup and Usage**

### 🚀 Quick Start

```bash
git clone https://github.com/Nymbus-Security/cloud-security-pipeline.git
cd cloud-security-pipeline
```

## 🔑 **Prerequisites**
- GitHub Secrets (Required):
    - OPENAI_API_KEY – For AI remediation and policy generation.
- GitHub Actions enabled in your repository
