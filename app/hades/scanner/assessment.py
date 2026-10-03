# Hades-Warden assessment engine.
#
# This module parses Terraform and runs the registered
# security policies against the relevant resources.

from hades.policies.security_group import (
    check_ssh_exposure,
    check_rdp_exposure,
)

from hades.policies.s3 import (
    check_public_bucket_acl,
    check_public_access_block,
)

from hades.scanner.terraform import parse_terraform

from hades.policies.iam import check_overly_permissive_iam_policy

# Security policies registered with Hades-Warden.
#
# Each policy defines:
# - an ID
# - the Terraform resource type it applies to
# - the type of data it needs
# - the function that performs the security check

POLICY_REGISTRY = [
    {
        "id": "AWS-SG-001",
        "resource_type": "aws_security_group",
        "input": "ingress",
        "check": check_ssh_exposure,
    },
    {
        "id": "AWS-SG-002",
        "resource_type": "aws_security_group",
        "input": "ingress",
        "check": check_rdp_exposure,
    },
    {
        "id": "AWS-S3-001",
        "resource_type": "aws_s3_bucket",
        "input": "acl",
        "check": check_public_bucket_acl,
    },
    {
        "id": "AWS-S3-002",
        "resource_type": "aws_s3_bucket_public_access_block",
        "input": "public_access_block",
        "check": check_public_access_block,
    },
    {
        "id": "AWS-IAM-001",
        "resource_type": "aws_iam_policy",
        "input": "policy_document",
        "check": check_overly_permissive_iam_policy,
    },
]


def assess_terraform(terraform_code: str) -> list:
    """
    Parse Terraform and run all registered security policies.
    """

    terraform = parse_terraform(terraform_code)

    findings = []

    resources = terraform.get("resource", [])

    for resource_group in resources:
        for resource_type, resource_instances in resource_group.items():

            applicable_policies = [
                policy
                for policy in POLICY_REGISTRY
                if policy["resource_type"] == resource_type
            ]

            for resource_name, resource in resource_instances.items():

                for policy in applicable_policies:

                    if policy["input"] == "ingress":
                        findings.extend(
                            policy["check"](
                                resource_name,
                                resource.get("ingress", []),
                            )
                        )
                    elif policy["input"] == "acl":
                        findings.extend(
                            policy["check"](
                                resource_name,
                                resource.get("acl"),
                            )
                        )
                    elif policy["input"] == "public_access_block":
                        findings.extend(
                            policy["check"](
                                resource_name,
                                resource,
                            )
                        )
                    elif policy["input"] == "policy_document":
                        findings.extend(
                            policy["check"](
                                resource_name,
                                resource.get("policy", {}),
                            )
                        )
    return findings


