\# Pipeline Guardrails-as-Code: Pre-Provisioning Infrastructure Attestation



An enterprise-grade Policy-as-Code (PaC) enforcement gate that natively parses HashiCorp Terraform configuration trees and programmatically prevents the provisioning of non-compliant public cloud resources.



\## 🛠️ Core Engineering \& Tooling

\* \*\*Policy Engine:\*\* Open Policy Agent (OPA) / Rego Declarative Policy Language

\* \*\*Infrastructure-as-Code:\*\* HashiCorp Terraform (AWS Provider)

\* \*\*CI/CD Automation Flight-Path:\*\* GitHub Actions Runner Engine

\* \*\*Workstation Workstream:\*\* Windows PowerShell / Git Core SCM



\## 🚀 Architectural Mechanics \& CI/CD Pipeline Flow

This project implements a proactive, shift-left defensive posture. Rather than scanning for vulnerabilities after resources are live, this pipeline captures infrastructure manifests mid-transit:



1\. \*\*`main.tf`\*\* defines a cloud storage topology with intentional security defects (unencrypted storage volumes and public S3 bucket pathways).

2\. The GitHub Actions runner handles compiling the manifest into an \*\*Abstract Syntax Tree (AST)\*\* JSON object database (`tfplan.json`).

3\. The \*\*Open Policy Agent Engine\*\* cross-references the compiled parameters against strict data-protection logic modules written in \*\*Rego\*\* (`policies/db\_encryption\_check.rego`).

4\. If a posture blocker is found, the workflow throws an alert to standard error and breaks the build with an operational `exit 1` status, blocking the deployment pipeline completely.



\## 🔬 Local Review \& Layout

\* `/terraform/main.tf` - Target state cloud definitions outlining data-tier volume profiles.

\* `/policies/db\_encryption\_check.rego` - Evaluation logic matrices tracking data-at-rest encryption requirements.

\* `/.github/workflows/main.yml` - Orchestration workflow automating binary tool setups and failure handling.

