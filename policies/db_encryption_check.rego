package terraform.security
import rego.v1

default allow := false
allow if count(violations) == 0

# --- RULE 1: EBS ENCRYPTION CHECK ---
# Path A: Check live resource changes (Online/Refreshed)
violations[msg] {
resource := input.resource_changes[_]
resource.type == "aws_ebs_volume"
not resource.change.after.encrypted
msg := sprintf("CRITICAL IAC POSTURE BLOCKER: EBS volume '%v' is unencrypted.", [resource.name])
}

# Path B: Check static block configurations (Offline Matrix)
violations[msg] {
resource := input.configuration.root_module.resources[_]
resource.type == "aws_ebs_volume"
not resource.expressions.encrypted.constant_value == true
msg := sprintf("CRITICAL IAC POSTURE BLOCKER: EBS volume '%v' is missing explicit encryption.", [resource.name])
}


# --- RULE 2: S3 PUBLIC ACCESS CHECK ---
# Path A: Check live resource changes (Online/Refreshed)
violations[msg] {
resource := input.resource_changes[_]
resource.type == "aws_s3_bucket_public_access_block"
resource.change.after.block_public_acls == false
msg := sprintf("CRITICAL IAC POSTURE BLOCKER: S3 Public Access Block '%v' allows public ACLs.", [resource.name])
}

# Path B: Check static block configurations (Offline Matrix)
violations[msg] {
resource := input.configuration.root_module.resources[_]
resource.type == "aws_s3_bucket_public_access_block"
resource.expressions.block_public_acls.constant_value == false
msg := sprintf("CRITICAL IAC POSTURE BLOCKER: S3 Public Access Block '%v' breaks security boundaries.", [resource.name])
}