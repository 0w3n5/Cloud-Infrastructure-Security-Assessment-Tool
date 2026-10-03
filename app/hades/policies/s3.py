# Hades-Warden AWS S3 security policies
# These policies check whether s3 buckets are configured in a way that could make their cotents publicly accessible

def check_public_bucket_acl(resource_name: str, acl: str) -> list:
    """
    Check whether an S3 bucket has a public ACL.
    """

    findings = []

    public_acls = {
        "public-read",
        "public-read-write",
    }

    if acl in public_acls:
        findings.append(
            {
                "rule": "AWS-S3-001",
                "severity": "HIGH",
                "title": "S3 bucket has a public ACL",
                "resource": resource_name,
                "recommendation": (
                    "Remove the public ACL and keep the S3 bucket private."
                ),
            }
        )

    return findings


def check_public_access_block(resource_name: str, resource: dict) -> list:
    """
    Check whether an S3 bucket has disabled public access protections.
    """

    findings = []

    block_public_acls = resource.get("block_public_acls", True)
    block_public_policy = resource.get("block_public_policy", True)
    ignore_public_acls = resource.get("ignore_public_acls", True)
    restrict_public_buckets = resource.get("restrict_public_buckets", True)

    protections_disabled = (
        not block_public_acls
        or not block_public_policy
        or not ignore_public_acls
        or not restrict_public_buckets
    )

    if protections_disabled:
        findings.append(
            {
                "rule": "AWS-S3-002",
                "severity": "HIGH",
                "title": "S3 public access protections disabled",
                "resource": resource_name,
                "recommendation": (
                    "Enable all S3 Block Public Access settings."
                ),
            }
        )

    return findings
