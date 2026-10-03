from hades.policies.s3 import (
    check_public_bucket_acl,
    check_public_access_block,
)


def test_public_s3_acl_is_blocked():
    findings = check_public_bucket_acl(
        "public_bucket",
        "public-read",
    )

    assert len(findings) == 1
    assert findings[0]["rule"] == "AWS-S3-001"
    assert findings[0]["severity"] == "HIGH"


def test_private_s3_acl_is_allowed():
    findings = check_public_bucket_acl(
        "private_bucket",
        "private",
    )

    assert findings == []


def test_disabled_s3_public_access_block_is_blocked():
    resource = {
        "block_public_acls": False,
        "block_public_policy": False,
        "ignore_public_acls": False,
        "restrict_public_buckets": False,
    }

    findings = check_public_access_block(
        "bad_bucket",
        resource,
    )

    assert len(findings) == 1
    assert findings[0]["rule"] == "AWS-S3-002"
    assert findings[0]["severity"] == "HIGH"


def test_enabled_s3_public_access_block_is_allowed():
    resource = {
        "block_public_acls": True,
        "block_public_policy": True,
        "ignore_public_acls": True,
        "restrict_public_buckets": True,
    }

    findings = check_public_access_block(
        "safe_bucket",
        resource,
    )

    assert findings == []
