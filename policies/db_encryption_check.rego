package terraform.security
import rego.v1

default allow := false
allow if count(violations) == 0

# Check static configuration blocks instead of live resource changes
violations[msg] {
resource := input.configuration.root_module.resources[_]
resource.type == "aws_ebs_volume"
not resource.expressions.encrypted.constant_value == true
msg := sprintf("CRITICAL IAC POSTURE BLOCKER: EBS volume '%v' is missing explicit encryption.", [resource.name])
}

violations[msg] {
resource := input.configuration.root_module.resources[_]
resource.type == "aws_s3_bucket_public_access_block"
resource.expressions.block_public_acls.constant_value == false
msg := sprintf("CRITICAL IAC POSTURE BLOCKER: S3 Public Access Block '%v' breaks security boundaries.", [resource.name])
}