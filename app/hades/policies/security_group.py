# Hades-Warden AWS Security Group policies.
#
# This file contains individual security rules.
# Each rule answers:
# "Is this infrastructure configuration safe according to policy?"


def check_ssh_exposure(resource_name: str, ingress_rules: list) -> list:
    """
    Check whether an AWS security group exposes SSH (port 22)
    to the entire internet.
    """

    findings = []

    for rule in ingress_rules:
        from_port = rule.get("from_port")
        to_port = rule.get("to_port")
        cidr_blocks = rule.get("cidr_blocks", [])

        ssh_exposed = (
            from_port is not None
            and to_port is not None
            and from_port <= 22 <= to_port
        )

        public_access = "0.0.0.0/0" in cidr_blocks

        if ssh_exposed and public_access:
            findings.append(
                {
                    "rule": "AWS-SG-001",
                    "severity": "HIGH",
                    "title": "SSH exposed to the internet",
                    "resource": resource_name,
                    "recommendation": (
                        "Restrict SSH access to a trusted IP range."
                    ),
                }
            )

    return findings


def check_rdp_exposure(resource_name: str, ingress_rules: list) -> list:
    """
    Check whether an AWS security group exposes RDP (port 3389)
    to the entire internet.
    """

    findings = []

    for rule in ingress_rules:
        from_port = rule.get("from_port")
        to_port = rule.get("to_port")
        cidr_blocks = rule.get("cidr_blocks", [])

        rdp_exposed = (
            from_port is not None
            and to_port is not None
            and from_port <= 3389 <= to_port
        )

        public_access = "0.0.0.0/0" in cidr_blocks

        if rdp_exposed and public_access:
            findings.append(
                {
                    "rule": "AWS-SG-002",
                    "severity": "HIGH",
                    "title": "RDP exposed to the internet",
                    "resource": resource_name,
                    "recommendation": (
                        "Restrict RDP access to a trusted IP range."
                    ),
                }
            )

    return findings
