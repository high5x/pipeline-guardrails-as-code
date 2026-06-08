package terraform.security
import rego.v1
default allow := false
allow if count(violations) == 0

violations[msg] {
resource := input.resource_changes[_]
resource.type == "aws_ebs_volume"
not resource.change.after.encrypted
msg := sprintf("CRITICAL IAAC POSTURE BLOCKER: EBS volume '%x' is unencrypted.", [resource.name])
}
violations[msg] {
resource := input.resource_changes[_]
resource.type == "aws_s3_bucket_public_access_block"
resource.change.after.block_public_acls == false
msg := sprintf("CRITICAL IAC POSTURE BLOCKER: S3 Public Access Block '%x' allows public ACLs.", [resource.name])
}
