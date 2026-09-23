from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional, List

from backend.db.session import get_db
from backend.models import MitreTechnique, User
from backend.schemas import MitreTechniqueResponse, PaginatedResponse
from backend.api.deps import get_current_active_user

router = APIRouter(prefix="/mitre", tags=["mitre"])


@router.get("", response_model=PaginatedResponse)
async def list_mitre_techniques(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    tactic: Optional[str] = None,
    search: Optional[str] = None,
    is_subtechnique: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    query = select(MitreTechnique)
    
    if tactic:
        query = query.where(MitreTechnique.tactic == tactic)
    if search:
        query = query.where(
            MitreTechnique.technique_id.ilike(f"%{search}%") |
            MitreTechnique.name.ilike(f"%{search}%")
        )
    if is_subtechnique is not None:
        query = query.where(MitreTechnique.is_subtechnique == is_subtechnique)
    
    query = query.order_by(MitreTechnique.technique_id)
    
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()
    
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    techniques = result.scalars().all()
    
    return PaginatedResponse(
        items=[MitreTechniqueResponse.model_validate(t) for t in techniques],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size
    )


@router.get("/tactics")
async def list_tactics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    result = await db.execute(
        select(MitreTechnique.tactic, func.count())
        .where(MitreTechnique.is_subtechnique == False)
        .group_by(MitreTechnique.tactic)
        .order_by(MitreTechnique.tactic)
    )
    return {"tactics": [{"tactic": t, "count": c} for t, c in result.all()]}


@router.get("/matrix")
async def get_mitre_matrix(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    result = await db.execute(
        select(MitreTechnique).where(MitreTechnique.is_subtechnique == False)
    )
    techniques = result.scalars().all()
    
    matrix = {}
    for t in techniques:
        if t.tactic not in matrix:
            matrix[t.tactic] = []
        matrix[t.tactic].append({
            "technique_id": t.technique_id,
            "name": t.name,
            "is_subtechnique": False,
        })
    
    result = await db.execute(
        select(MitreTechnique).where(MitreTechnique.is_subtechnique == True)
    )
    subtechniques = result.scalars().all()
    
    for t in subtechniques:
        if t.tactic not in matrix:
            matrix[t.tactic] = []
        matrix[t.tactic].append({
            "technique_id": t.technique_id,
            "name": t.name,
            "is_subtechnique": True,
            "parent_technique": t.parent_technique,
        })
    
    return {"matrix": matrix}


@router.get("/coverage")
async def get_mitre_coverage(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    from backend.models import Event
    from datetime import datetime, timezone, timedelta
    
    start_time = datetime.now(timezone.utc) - timedelta(days=30)
    
    result = await db.execute(
        select(Event.mitre_techniques)
        .where(Event.timestamp >= start_time)
        .where(Event.mitre_techniques.isnot(None))
    )
    
    detected = set()
    for (tech_str,) in result.all():
        if tech_str:
            for t in tech_str.split(","):
                detected.add(t.strip())
    
    result = await db.execute(select(MitreTechnique.technique_id))
    all_techniques = {t for (t,) in result.all()}
    
    covered = len(detected & all_techniques)
    total = len(all_techniques)
    
    return {
        "covered_techniques": covered,
        "total_techniques": total,
        "coverage_percent": round(covered / total * 100, 2) if total > 0 else 0,
        "detected": list(detected),
    }


@router.get("/{technique_id}", response_model=MitreTechniqueResponse)
async def get_mitre_technique(
    technique_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    result = await db.execute(
        select(MitreTechnique).where(MitreTechnique.technique_id == technique_id)
    )
    technique = result.scalar_one_or_none()
    if not technique:
        raise HTTPException(status_code=404, detail="Technique not found")
    return technique


from backend.models import User