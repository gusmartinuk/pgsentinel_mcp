from pydantic import BaseModel


class ContainerStatus(BaseModel):
    name: str
    status: str
    image: str = ""
    started_at: str = ""
