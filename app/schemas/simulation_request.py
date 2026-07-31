from pydantic import BaseModel, Field


class SimulationRequest(BaseModel):

    hostname: str = Field(
        default="DESKTOP-LAB-01",
        description="Target hostname"
    )

    username: str = Field(
        default="himanshu",
        description="Logged in user"
    )

    severity: str = Field(
        default="critical",
        description="Alert severity"
    )

    dry_run: bool = Field(
        default=True,
        description="Do not perform real containment"
    )