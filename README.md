## Cloud Infrastructure Security Assessment Tool
A Cloud Infrastructure security assessment tool for identifying security misconfigurations in terraform code before it gets deployed.

### Overview
Terraform configurations are assessed against a set of security policies. From this it generates security findings with severity, affected 
resource and remediation guidance.

Findings are sorted into the following security decisions:
- PASS - no security findings detected
- WARN - findings detected but done are high or critical severity
- BLOCK - high or critical security findings detected

The project is designed as a light weight foundation for an automated cloud security assurance workflow.

### Current Security Checks
#### AWS Security Groups
- AWS-SG-001 - SSH exposed to the internet - Severity:HIGH
- AWS-SG-002 - RDP exposed to the internet - Severity:HIGH
- AWS-SG-003 - Common database ports exposed to the internet - Severity:CRITICAL

#### AWS S3
- AWS-S3-001 - S3 Bucket has a public ACL - Severity:HIGH
- AWS-S3-002 - S3 Block Public Access protections disabled - Severity:HIGH

#### AWS IAM
- AWS-IAM-001 - IAM policy allows all actions on all resources - Severity:CRITICAL

### Architecture

Hades-Warden takes Terraform configuration, parses it, runs security policies against the AWS resources, and returns security findings with an overall PASS, WARN or BLOCK decision.

#### Technology

- Python
- FastAPI
- Terraform / HCL
- Docker
- pytest

#### Running Locally

Run the application with Docker Compose:

docker compose up -d

API: http://localhost:8000

Swagger documentation: http://localhost:8000/docs

Run tests:

docker compose run --rm hades-api pytest

#### Example

A Terraform security group allowing SSH from 0.0.0.0/0 is detected as a HIGH severity finding and results in a BLOCK decision.

Safe configurations with no detected issues return PASS.

#### Testing

Hades-Warden currently has 13 automated tests covering IAM, S3, security groups, Terraform parsing and end-to-end assessments.

#### Project Status

Hades-Warden is a functional MVP for assessing Terraform-managed AWS infrastructure.

The project demonstrates practical experience with:

- AWS security
- Infrastructure as Code
- Security policy automation
- Python and FastAPI
- Docker
- Automated testing
