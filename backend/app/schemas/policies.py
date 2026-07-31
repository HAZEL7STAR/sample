from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class PolicyCreate(BaseModel):
    device_fingerprint: Optional[str] = Field(default=None)
    rule_type: str = Field(..., pattern=r"^(whitelist|blacklist|temp_allow|temp_block|permanent_allow|permanent_block)$")
    expires_at: Optional[datetime] = None
    reason: Optional[str] = None


class PolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    device_fingerprint: Optional[str]
    rule_type: str
    expires_at: Optional[datetime]
    created_by: Optional[int]
    created_at: datetime
    reason: Optional[str]
