# Hades-Warden Terraform scanner.
#
# This module takes Terraform code and converts it into
# Python data that our security policies can inspect.

import hcl2


def parse_terraform(terraform_code: str) -> dict:
    """
    Parse Terraform/HCL code into a Python dictionary.
    """
    try:
        terraform = hcl2.loads(terraform_code)
        return _clean_values(terraform)
    except Exception as error:
        raise ValueError(f"Invalid Terraform: {error}")


def _clean_values(value):
    """
    Recursively clean and evaluate values from Terraform.
    """

    if isinstance(value, dict):
        return {
            _clean_string(key): _clean_values(item)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [_clean_values(item) for item in value]

    if isinstance(value, str):
        # Terraform represents jsonencode(...) expressions
        # as strings. Convert the inner Terraform object
        # into a normal Python dictionary.
        if value.startswith("${jsonencode(") and value.endswith(")}"):
            inner = value[len("${jsonencode("):-2]

            parsed = hcl2.loads(
                f"__value = {inner}"
            )

            return _clean_values(parsed["__value"])

        return _clean_string(value)

    return value


def _clean_string(value: str) -> str:
    """
    Remove unwanted surrounding quotation marks.
    """
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]

    return value
