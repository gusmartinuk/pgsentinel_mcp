from pydantic import BaseModel


class Finding(BaseModel):
    source: str
    severity: str
    message: str
