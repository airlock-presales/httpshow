"""
HttpShow: Simple Python http server to return request details in html

Copyright 2018-2025 Urs Zurbuchen

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and 
associated documentation files (the “Software”), to deal in the Software without restriction, 
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH 
THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

#---------------------------------------------------------------------------
#   Module imports
#---------------------------------------------------------------------------
import logging
import os
from contextlib import asynccontextmanager
from typing import Optional
from pydantic import BaseModel

from fastapi import FastAPI, Request, Response, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from app import config
from app import oidc
from app import session
from app.utils import (
    parse_request_details,
    setup_logging,
)

class HealthCheck( BaseModel ):
    status: str = "OK"


setup_logging()
logger = logging.getLogger(__name__)

cfg = config.Settings()
rp = oidc.RP(cfg)
logger.setLevel(cfg.log_level)

authSessions = session.SessionStore(cfg)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize OIDC client on startup."""
    logger.info("Starting application...")
    await rp.init_client()
    logger.info("OIDC client initialized")
    yield
    logger.info("Shutting down application...")

app = FastAPI(
    title="OIDC Request Inspector",
    description="A secure request inspector with OIDC support",
    version="0.3.0",
    lifespan=lifespan,
)

# Add session middleware
app.add_middleware(
    SessionMiddleware,
    secret_key=cfg.app_secret_key,
    session_cookie=cfg.session_cookie_name,
    https_only=cfg.base_url.startswith("https://"),
    same_site="lax",
)

# Mount static files
os.makedirs("app/static", exist_ok=True)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Templates
templates = Jinja2Templates(directory="app/templates")


def add_security_headers(response: Response):
    """Add security headers to response."""
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.get("/oidc/login")
async def oidc_login(request: Request):
    """Initiate OIDC login flow."""
    logger.info(f"{request.client.host if request.client else "unknown"} - {request.method} {request.url.path}")
    return await rp.handle_login(request, sessions=authSessions)


@app.get("/oidc/callback")
async def oidc_callback(request: Request):
    """Handle OIDC callback."""
    logger.info(f"{request.client.host if request.client else "unknown"} - {request.method} {request.url.path}")
    return await rp.handle_callback(request, sessions=authSessions)


@app.api_route("/oidc/logout", methods=["GET", "POST"])
async def oidc_logout(request: Request):
    """Clear session and logout."""
    logger.info(f"{request.client.host if request.client else "unknown"} - {request.method} {request.url.path}")
    return await rp.handle_logout(request, sessions=authSessions)


@app.get("/profile", response_class=HTMLResponse)
async def profile(request: Request):
    """Show user profile with token introspection."""
    logger.info(f"{request.client.host if request.client else "unknown"} - {request.method} {request.url.path}")
    return await rp.handle_profile(request, sessions=authSessions)


@app.post("/toggle-theme")
async def toggle_theme(request: Request, theme: str = Form(...)):
    """Toggle day/night mode."""
    request.session["night_mode"] = theme == "night"
    referer = request.headers.get("referer", "/")
    return RedirectResponse(url=referer, status_code=303)


@app.get("/health", status_code=status.HTTP_200_OK, response_model=HealthCheck,)
async def health():
    """Health endpoint."""
    return HealthCheck(status="OK")


@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def home(request: Request, path_name: str):
    """Request inspector endpoint."""
    logger.info(f"{request.client.host if request.client else "unknown"} - {request.method} {request.url.path}")
    details = await parse_request_details(request, cfg)
    
    response = templates.TemplateResponse(
        "request.html",
        {
            "request": request,
            "path": path_name,
            # "user": user,
            "details": details,
            "night_mode": cfg.night_mode,
        },
    )
    return add_security_headers(response)


if __name__ == "__main__":
    import uvicorn
    print( "Starting uvicorn" )
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=cfg.port,
        reload=True,
    )

