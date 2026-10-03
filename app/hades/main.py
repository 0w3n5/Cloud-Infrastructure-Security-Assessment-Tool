from fastapi import FastAPI
from pydantic import BaseModel

from hades.scanner.assessment import assess_terraform
from hades.policies.risk import calculate_decision

app = FastAPI(
    title="Hades-Warden",
    description="Cloud infrastructure security change-assurance platform",
    version="0.1.0",
)


class TerraformRequest(BaseModel):
    # Terraform configuration submitted for security assessment.
    terraform: str


@app.get("/")
def root():
    return {
        "name": "Hades-Warden",
        "status": "online",
        "version": "0.1.0",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.post("/assess")
def assess(request: TerraformRequest):
    # Send the submitted Terraform to the assessment engine.
    findings = assess_terraform(request.terraform)

    # Convert security findings into a PASS/WARN/BLOCK decision.
    decision = calculate_decision(findings)

    return {
        "decision": decision,
        "findings": findings,
    }
