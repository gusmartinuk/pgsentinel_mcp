from pydantic import BaseModel


class LogLines(BaseModel):
    log_name: str | None = None
    container: str | None = None
    lines: list[str] = []
    count: int
