"""
Admin routes for dashboard and management.
"""
import os
import logging
from typing import Dict, Optional

from fastapi import APIRouter, Depends, Request, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from config import config
from bot.security import verify_jwt_dependency

logger = logging.getLogger(__name__)

# Create APIRouter
router = APIRouter(prefix="/admin", tags=["admin"])

# Get templates directory path
templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)


async def get_admin_data(request: Request, admin_data: Dict = Depends(verify_jwt_dependency)):
    """Dependency for admin routes to get admin data."""
    admin_id = admin_data.get("admin_id")
    if not admin_id:
        raise HTTPException(status_code=401, detail="Invalid admin token")
    return {"admin_id": admin_id}


@router.get("/", response_class=HTMLResponse)
async def admin_home(request: Request, admin_data: Dict = Depends(get_admin_data)):
    """Admin dashboard homepage."""
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "admin": admin_data,
            "title": "Anti-Erotic Spam Bot - Admin Dashboard"
        }
    )


@router.get("/dashboard", response_class=HTMLResponse)
async def admin_dashboard(request: Request, admin_data: Dict = Depends(get_admin_data)):
    """Admin dashboard with statistics."""
    # Get statistics from database
    from bot.database import get_stats, get_bot_enabled_state
    stats = await get_stats(request.app.state.db)
    enabled = await get_bot_enabled_state(request.app.state.db)
    
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "stats": stats,
            "enabled": enabled,
            "admin": admin_data,
            "title": "Anti-Erotic Spam Bot - Admin Dashboard"
        }
    )


@router.post("/toggle")
async def admin_toggle(
    request: Request,
    enabled: bool = Form(...),
    admin_data: Dict = Depends(get_admin_data)
):
    """Toggle the bot enabled state."""
    # Update the bot state in database
    from bot.database import set_bot_enabled_state
    await set_bot_enabled_state(request.app.state.db, enabled)
    
    # Return to dashboard
    return RedirectResponse(url="/admin/dashboard", status_code=303)