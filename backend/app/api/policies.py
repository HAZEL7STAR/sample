from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import models
from app.schemas.policies import PolicyCreate, PolicyResponse

router = APIRouter(prefix="/policies", tags=["policies"])


@router.get("", response_model=list[PolicyResponse])
def list_policies(db: Session = Depends(get_db)):
    rows = db.query(models.Policy).order_by(models.Policy.created_at.desc()).all()
    return rows


@router.post("", response_model=PolicyResponse)
def create_policy(payload: PolicyCreate, db: Session = Depends(get_db)):
    policy = models.Policy(
        device_fingerprint=payload.device_fingerprint,
        rule_type=payload.rule_type,
        expires_at=payload.expires_at,
        reason=payload.reason,
        created_by=None,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return policy
