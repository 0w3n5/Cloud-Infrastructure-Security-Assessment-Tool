# Hades-Warden AWS IAM security policies.


def check_overly_permissive_iam_policy(
    resource_name: str,
    policy_document: dict,
) -> list:
    """
    Detect IAM statements that allow every action on every resource.
    """

    findings = []

    statements = policy_document.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:

        effect = statement.get("Effect")
        action = statement.get("Action")
        resource = statement.get("Resource")

        allows_everything = (
            effect == "Allow"
            and action == "*"
            and resource == "*"
        )

        if allows_everything:
            findings.append(
                {
                    "rule": "AWS-IAM-001",
                    "severity": "CRITICAL",
                    "title": "Overly permissive IAM policy",
                    "resource": resource_name,
                    "recommendation": (
                        "Apply least privilege by restricting "
                        "actions and resources."
                    ),
                }
            )

    return findings
