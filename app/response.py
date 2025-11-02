"""
HttpShow: Simple HTTP server to return request details in html

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
from typing import Optional, Dict, Any

from fastapi import Request
from fastapi.templating import Jinja2Templates

from app import config
from app import session
from app.utils import parse_request_details, decode_jwt_token

templates = Jinja2Templates(directory="app/templates")

class RequestMirror( object ):
    def __init__( self, cfg: config.Settings ):
        self._cfg = cfg
        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(self._cfg.log_level)
    
    async def mirror(self, request: Request, sessions: session.SessionStore, api_details: Dict=None, auth_info: Dict=None, errors: Dict=None):
        """Return request mirroring result."""
        self._logger.debug("mirror - enter")

        # Retrieve session & user information
        session_data = self._get_session(request, sessions, init=True)
        user = self.get_current_user(request, sessions=sessions, session_data=session_data)
        self._logger.debug( f"User: {user}")
        tokens = session_data.get("tokens", {})

        # Parse request details
        details = await parse_request_details(request, self._cfg)
        
        # Add OIDC-specific details
        tokens = session_data.get("tokens", {})
        oidc_details = {
            "id_token": decode_jwt_token(tokens.get("id_token")) if tokens.get("id_token") else None,
            "access_token": decode_jwt_token(tokens.get("access_token")) if tokens.get("access_token") else None,
            "userinfo": session_data.get("userinfo", {}),
            "introspection": auth_info['introspection'] if auth_info else None,
        }
        
        # Add access token info
        if auth_info and auth_info['token']:
            auth_info_details = {
                "access_token": decode_jwt_token(auth_info['token']) if auth_info['token'] else None,
                "introspection": auth_info['introspection'],
            }
        else:
            auth_info_details = None
        data = {
                    "request": request,
                    "user": user,
                    "details": details,
                    "oidc_details": oidc_details,
                    "auth_info_details": auth_info_details,
                    "config": self._cfg,
                    "errors": errors,
                }
        if request.headers.get("accept") != "application/json":
            data["night_mode"] = self._cfg.night_mode
        if api_details:
            data["api_details"] = api_details
        
        if request.headers.get("accept") == "application/json":
            response = templates.TemplateResponse("request.json",data)
        elif api_details:
            response = templates.TemplateResponse("api.html",data)
        else:
            response = templates.TemplateResponse("request.html",data)
        self._logger.debug("mirror - exit")
        return response


    def get_current_user(self, request: Request, sessions: session.SessionStore=None, session_data: session.SessionData=None) -> Optional[Dict[str, Any]]:
        """Get current authenticated user from session."""
        if not session_data:
            session_data = self._get_session(request, sessions)
            if not session_data:
                return None
        return session_data.getUser()


    # helper functions

    def _get_session(self, request: Request, sessions: session.SessionStore, init: bool=False) -> session.SessionData:
        session_id = request.session.get("id")
        self._logger.debug(f"Session id from request: {session_id}")
        session_data = sessions.find( session_id )
        if init and not session_data:
            session_data = sessions.create()
            request.session["id"] = session_data.id
            self._logger.debug(f"Store session id")
        return session_data

