from hades.policies.iam import check_overly_permissive_iam_policy


def test_wildcard_iam_policy_is_blocked():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }
        ]
    }

    findings = check_overly_permissive_iam_policy(
        "dangerous_policy",
        policy,
    )

    assert len(findings) == 1
    assert findings[0]["rule"] == "AWS-IAM-001"
    assert findings[0]["severity"] == "CRITICAL"


def test_restricted_iam_policy_is_allowed():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::example/*",
            }
        ]
    }

    findings = check_overly_permissive_iam_policy(
        "safe_policy",
        policy,
    )

    assert findings == []
