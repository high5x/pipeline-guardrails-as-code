# Architectural Specification: Deterministic Infrastructure Attestation & Shift-Left Policy-as-Code

## 1. Executive Summary & Design Philosophy
Traditional enterprise defensive paradigms operate reactively, relying on runtime security telemetry, configuration management databases (CMDBs), and post-provisioning compliance scanners to identify misconfigured assets. This approach guarantees an operational window of vulnerability—the latency period between a resource's deployment and its subsequent automated detection or remediation.

This project implements a **Deterministic Infrastructure Attestation Engine** utilizing a "Shift-Left" methodology. By embedding programmatic policy validation gates directly inside the continuous integration/continuous deployment (CI/CD) flight path, we convert security requirements from abstract text documents into executable, compile-time assertions. No infrastructure manifest is allowed to provision unless it mathematically satisfies our explicit compliance matrices.

---

## 2. Technical Architecture & Data Transformation Pipeline
The automated security gate relies on converting declarative Infrastructure-as-Code definitions into a structured format optimized for complex logical evaluation. The transformation pipeline operates in four distinct phases:

1. **Syntax Parsing:** The HashiCorp Configuration Language (HCL) parser compiles the raw `.tf` declarations into a localized configuration block.
2. **Execution Plan Generation:** The `terraform plan` command calculates the delta between the existing cloud state and the desired target state, outputting a serialized binary execution map (`tfplan.binary`).
3. **Abstract Syntax Tree (AST) Extraction:** The binary map is deserialized and normalized into a standard JSON document (`tfplan.json`). This object models the explicit configuration parameters (`resource_changes`) representing the planned state of the cloud tenant.
4. **Declarative Logical Evaluation:** The Open Policy Agent (OPA) engine ingests the JSON payload natively, mapping the input keys against compiled **Rego mathematical relation matrices**. 

---

## 3. Structural Analysis: Policy-as-Code Rules Matrix

### A. Cryptographic Storage Enforcement (AWS EBS)
The policy mandates that all blocks assigned to `aws_ebs_volume` must explicitly pass a Boolean verification check on the `encrypted` block parameter. 

The engine scans the object array:
$$\forall x \in \text{Resources}(\text{type} = \text{"aws\_ebs\_volume"}), \, \text{config}(x).\text{encrypted} = \text{true}$$

If any resource violates this assertion, the rule evaluates to true for a violation, triggering a localized string interpolation that captures the specific offending resource block name and injects it into the standard error stream of the CI/CD pipeline.

### B. Ingress Boundary Control (AWS S3)
To eliminate public leakage vectors via accidental Object Access Control List (ACL) misconfigurations, the engine targets the public containment envelope defined within `aws_s3_bucket_public_access_block`. The policy explicitly blocks configurations that switch default boundary parameters (`block_public_acls`) to `false`. 

---

## 4. Operational Limitations of Static IaC Analysis
While pre-provisioning static analysis completely eliminates structural misconfigurations, an advanced security engineer must recognize its architectural constraints:

* **Dynamic Data Blindspots:** Static analysis cannot predict value evaluations that occur at runtime via cloud-side interpolation, such as dynamically assigned IP addresses, late-bound lookup arrays, or cross-account AWS Systems Manager (SSM) parameter paths.
* **Contextual Isolation:** The engine evaluates the infrastructure manifest *in isolation*. It cannot verify if an unencrypted resource is securely wrapped behind a non-routable private network layer unless that entire networking block is bundled within the exact same evaluation plane.
* **State Drift Divergence:** Policy-as-Code gates validate **intent**, not current reality. If an administrator manually adjusts a cloud configuration via the AWS Console after a successful pipeline run (creating out-of-band state drift), the pre-provisioning gate cannot detect the compromise path. This highlights why Shift-Left tools must always be backed by runtime configuration monitoring.