# ==============================================================================
# ENTERPRISE POLICY-AS-CODE GUARDRAIL ENGINE (OPEN POLICY AGENT)
# ==============================================================================
package terraform.security

import rego.v1

default allow := false

allow if count(violations) == 0

violations[msg] {
	resource := input.resource_changes[_]
	resource.type == "aws_ebs_volume"
	config := resource.change.after
	not config.encrypted
	msg := sprintf("CRITICAL IAAC POSTURE BLOCKER: The EBS volume '%x' is unencrypted. Data-at-rest encryption is mandatory for production workloads.", [resource.name])
}

violations[msg] {
	resource := input.resource_changes[_]
	resource.type == "aws_s3_bucket_public_access_block"
	config := resource.change.after
	config.block_public_acls == false
	msg := sprintf("CRITICAL IAC POSTURE BLOCKER: S3 Public Access Block configuration '%x' explicitly allows public ACL configuration. Ingress boundaries compromised.", [resource.name])
}