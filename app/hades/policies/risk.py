# Hades-Warden risk decision logic

# This module decised what should happen after drcurity policies have produced findings

def calculate_decision(findings: list) -> str:
	"""
	Convert security findings into a Hades-Warden decision

	HIGH findings block the change.
	Lower-severity findings generate a warning.
	No findings means the change is passed.
	"""

	if any(finding["severity"] in {"CRITICAL", "HIGH"} for finding in findings):
		return "BLOCK"

	if findings:
		return "WARN"

	return "PASS"


