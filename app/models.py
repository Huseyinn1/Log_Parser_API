from pydantic import BaseModel

class LogParseRequest(BaseModel):
    log_content: str 