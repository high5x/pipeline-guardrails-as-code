package terraform.security
import rego.v1

# Test case ensuring compliant infrastructure yields zero violations
test_compliant_architecture if {
    mock_input := {
        "resource_changes": [
            {
                "name": "secure_ebs",
                "type": "aws_ebs_volume",
                "change": {
                    "after": {
                        "encrypted": true
                    }
                }
            },
            {
                "name": "secure_s3_ingress",
                "type": "aws_s3_bucket_public_access_block",
                "change": {
                    "after": {
                        "block_public_acls": true
                    }
                }
            }
        ]
    }
    count(violations) == 0 with input as mock_input
}