from pydantic import BaseModel


class ServiceHealth(BaseModel):
    service: str
    status: str
    mode: str


class ErrorResponse(BaseModel):
    error: str
    detail: str
