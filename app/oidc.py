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
import base64
import logging
import secrets
from typing import Optional, Dict, Any
from urllib.parse import urlencode

import httpx
from authlib.jose import jwt, JsonWebKey
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app import config
from app import session
from app.utils import parse_request_details, decode_jwt_token

templates = Jinja2Templates(directory="app/templates")

class RP( object ):
    
    """
    OIDC RP
    """

    def __init__( self, cfg: config.Settings ):
        self._cfg = cfg
        self._oidc = {}
        self._jwks_cache = {}
        self._client = None
        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(self._cfg.log_level)
    
    async def init_client(self):
        """Initialize OIDC client and fetch discovery document."""
        # Create HTTP client
        self._client = httpx.AsyncClient( verify=self._cfg.verify_provider_certificate, timeout=self._cfg.oidc_client_timeout )
        
        # Fetch discovery document
        discovery_url = f"{self._cfg.oidc_issuer}/.well-known/openid-configuration"
        self._logger.info(f"Fetching OIDC discovery from {discovery_url}")
        
        try:
            response = await self._client.get(discovery_url)
            response.raise_for_status()
            self._oidc.update(response.json())
            self._logger.info(f"OIDC discovery loaded: issuer={self._oidc.get('issuer')}")
            
            # Fetch JWKS
            jwks_uri = self._oidc.get("jwks_uri")
            if jwks_uri:
                jwks_response = await self._client.get(jwks_uri)
                jwks_response.raise_for_status()
                self._jwks_cache.update(jwks_response.json())
                self._logger.info(f"JWKS loaded from {jwks_uri}")
        except Exception as e:
            self._logger.error(f"Failed to initialize OIDC: {e}")
            raise
    
    
    async def handle_login(self, request: Request, sessions: session.SessionStore) -> RedirectResponse:
        """Handle OIDC login initiation."""
        # Generate security parameters
        state = self._generate_state()
        nonce = self._generate_nonce()
        
        # Store in session
        session_data = self._get_session(request, sessions, init=True)
        session_data.store( {"oidc_state": state, "oidc_none": nonce} )
        
        # Build authorization parameters
        params = {
            "client_id": self._cfg.oidc_client_id,
            "response_type": "code",
            "scope": self._request_scopes(),
            "redirect_uri": self._getPath("/oidc/callback"),
            "state": state,
            "nonce": nonce,
        }
        
        # Add PKCE if enabled
        if self._cfg.pkce:
            code_verifier, code_challenge = self._generate_pkce()
            session_data.set( "oidc_code_verifier", code_verifier )
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        
        # Handle PAR if enabled
        if self._cfg.par and self._oidc.get("pushed_authorization_request_endpoint"):
            try:
                par_endpoint = self._oidc["pushed_authorization_request_endpoint"]
                self._logger.info(f"Using PAR endpoint: {par_endpoint}")
                
                # Prepare PAR request
                par_data = params.copy()
                auth = None
                if self._cfg.oidc_client_secret:
                    auth = (self._cfg.oidc_client_id, self._cfg.oidc_client_secret)
                
                par_response = await self._client.post(
                    par_endpoint,
                    data=par_data,
                    auth=auth,
                )
                par_response.raise_for_status()
                par_result = par_response.json()
                
                session_data.set( "par_request", par_result )
                
                # Build authorization URL with request_uri
                auth_url = self._oidc["authorization_endpoint"]
                auth_params = {
                    "client_id": self._cfg.oidc_client_id,
                    "request_uri": par_result["request_uri"],
                }
                authorization_url = f"{auth_url}?{urlencode(auth_params)}"
            except Exception as e:
                self._logger.error(f"PAR request failed: {e}")
                # Fallback to regular authorization
                auth_url = self._oidc["authorization_endpoint"]
                authorization_url = f"{auth_url}?{urlencode(params)}"
        else:
            # Regular authorization request
            auth_url = self._oidc["authorization_endpoint"]
            authorization_url = f"{auth_url}?{urlencode(params)}"
        
        self._logger.info(f"Redirecting to authorization endpoint: {auth_url}")
        return RedirectResponse(url=authorization_url)


    async def handle_callback(self, request: Request, sessions: session.SessionStore):
        """Handle OIDC callback and token exchange."""
        # Check for errors
        error = request.query_params.get("error")
        if error:
            error_description = request.query_params.get("error_description", "Unknown error")
            self._logger.error(f"OIDC error: {error} - {error_description}")
            raise HTTPException(status_code=400, detail=f"OIDC error: {error_description}")
        
        # Verify session
        session_data = self._get_session(request, sessions)
        if session_data == None:
            self._logger.error("Invalid session")
            raise HTTPException(status_code=400, detail="Invalid session")
        
        # Verify state
        state = request.query_params.get("state")
        stored_state = session_data.get("oidc_state")
        if not state or state != stored_state:
            self._logger.error("State mismatch or missing")
            raise HTTPException(status_code=400, detail="Invalid state parameter")
        
        # Get authorization code
        code = request.query_params.get("code")
        if not code:
            raise HTTPException(status_code=400, detail="No authorization code received")
        
        # Exchange code for tokens
        code_verifier = session_data.get("oidc_code_verifier")
        
        try:
            tokens = await self._exchange_code_for_tokens(code, code_verifier)
        except Exception as e:
            self._logger.error(f"Token exchange failed: {e}")
            raise HTTPException(status_code=400, detail=f"Token exchange failed: {str(e)}")
        
        # Verify ID token
        id_token = tokens.get("id_token")
        if not id_token:
            raise HTTPException(status_code=400, detail="No ID token received")
        
        nonce = session_data.get("oidc_nonce")
        try:
            claims = self._verify_id_token(id_token, nonce)
        except Exception as e:
            self._logger.error(f"ID token verification failed: {e}")
            raise HTTPException(status_code=400, detail=f"ID token verification failed: {str(e)}")
        
        # Fetch userinfo if enabled
        userinfo = {}
        if self._cfg.userinfo and tokens.get("access_token"):
            try:
                userinfo = await self._fetch_userinfo(tokens["access_token"])
            except Exception as e:
                self._logger.warning(f"Failed to fetch userinfo: {e}")
        
        # Store session data
        session_data.store({
            "user_id": claims.get("sub"),
            "email": claims.get("email"),
            "name": claims.get("name"),
            "tokens": tokens,
            "userinfo": userinfo,
        })
        
        # Clean up temporary session data
        session_data.delete("oidc_state")
        session_data.delete("oidc_nonce")
        session_data.delete("oidc_code_verifier")
        
        self._logger.info(f"User authenticated: {claims.get('email')}")
        # self._logger.info(f"User from session: {self.get_current_user(request, session_data=session_data)}")
        
        # Redirect back to page requesting authentication
        root = self._getPath("")
        forward_location = session_data.get("forward_location")
        if forward_location:
            if forward_location.startswith( "http://" ) or forward_location.startswith( "https://" ):
                forward_location = '/'
        self._logger.info(f"Redirect back to initial page: {forward_location}")
        return RedirectResponse(url=forward_location, status_code=303)
    
        # Show callback details
        details = await parse_request_details(request, self._cfg)
        
        # Add OIDC-specific details
        oidc_details = {
            "id_token": decode_jwt_token(id_token) if id_token else None,
            "access_token": decode_jwt_token(tokens.get("access_token")) if tokens.get("access_token") else None,
            "refresh_token": tokens.get("refresh_token"),
            "userinfo": userinfo,
            "par_request": session_data.get("par_request"),
        }
        
        response = templates.TemplateResponse(
            "request.html",
            {
                "request": request,
                "user": self.get_current_user(request, sessions, session_data=session_data),
                "details": details,
                "oidc_details": oidc_details,
                "night_mode": self._cfg.night_mode,
            },
        )
        return response


    async def handle_logout(self, request: Request, sessions: session.SessionStore) -> Jinja2Templates.TemplateResponse:
        """Handle logout."""
        session_id = request.session.get("id")
        sessions.delete( session_id )
        request.session.clear()
        self._logger.info("User logged out")
        
        details = await parse_request_details(request, self._cfg)
        
        response = templates.TemplateResponse(
            "request.html",
            {
                "request": request,
                "user": None,
                "details": details,
                "night_mode": self._cfg.night_mode,
            },
        )
        return response


    async def handle_profile(self, request: Request, sessions: session.SessionStore):
        """Handle profile page with token introspection."""
        # Retrieve session
        session_data = self._get_session(request, sessions, init=True)
        
        access_token = None

        # Use bearer token passed in Authorization header
        auth_header = request.headers.get("authorization", "")
        if auth_header and auth_header.startswith("Bearer "):
            access_token = auth_header[7:]
            self._logger.info("Using access token from Authorization header")

        # Otherwise, use access token form session
        if not access_token:
            user = self.get_current_user(request, sessions=sessions, session_data=session_data)
            if user and not access_token:
                tokens = session_data.get("tokens", {})
                access_token = tokens.get( "access_token" )
                if access_token:
                    self._logger.info("Using access token from session")

        # If no access token available, redirect to login
        if not access_token:
            base = str(request.base_url).rstrip('/')
            url = str(request.url)
            forward_location = url[len(base):]
            if session_data:
                session_data.set("forward_location", forward_location)
            else:
                session_data = sessions.create( {"forward_location", forward_location} )
                request.session["id"] = session_data.id
            return RedirectResponse(url=f"/oidc/login?loc={forward_location}")
        
        # Introspect token
        try:
            introspection_result = await self._introspect_token(access_token)
        except Exception as e:
            self._logger.error(f"Token introspection failed: {e}")
            introspection_result = {"active": False, "error": str(e)}

        # Parse request details
        details = await parse_request_details(request, self._cfg)
        
        # Add OIDC-specific details
        oidc_details = {
            "id_token": decode_jwt_token(tokens.get("id_token")) if tokens.get("id_token") else None,
            "access_token": decode_jwt_token(access_token) if access_token else None,
            "introspection": introspection_result,
            "userinfo": session_data.get("userinfo", {}),
        }
        
        response = templates.TemplateResponse(
            "request.html",
            {
                "request": request,
                "user": user,
                "details": details,
                "oidc_details": oidc_details,
                "night_mode": self._cfg.night_mode,
            },
        )
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
        session_data = sessions.find( session_id )
        if init and not session_data:
            session_data = sessions.create()
            request.session["id"] = session_data.id
        return session_data

    def _generate_pkce(self) -> tuple[str, str]:
        """Generate PKCE code verifier and challenge."""
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        code_challenge = create_s256_code_challenge(code_verifier)
        return code_verifier, code_challenge


    def _generate_state(self) -> str:
        """Generate random state parameter."""
        return secrets.token_urlsafe(32)


    def _generate_nonce(self) -> str:
        """Generate random nonce parameter."""
        return secrets.token_urlsafe(32)


    async def _exchange_code_for_tokens(
        self,
        code: str,
        code_verifier: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Exchange authorization code for tokens."""
        token_endpoint = self._oidc["token_endpoint"]
        
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self._getPath("/oidc/callback"),
            "client_id": self._cfg.oidc_client_id,
        }
        
        if code_verifier:
            token_data["code_verifier"] = code_verifier
        
        # Add client secret if available
        auth = None
        if self._cfg.oidc_client_secret:
            auth = (self._cfg.oidc_client_id, self._cfg.oidc_client_secret)
        else:
            # For public clients, include client_id in body
            token_data["client_id"] = self._cfg.oidc_client_id
        
        self._logger.info(f"Exchanging code at token endpoint: {token_endpoint}")
        response = await self._client.post(
            token_endpoint,
            data=token_data,
            auth=auth,
        )
        response.raise_for_status()
        return response.json()


    def _verify_id_token(self, id_token: str, nonce: str) -> Dict[str, Any]:
        """Verify and decode ID token."""
        # Parse header to get kid
        # self._logger.info(f"Starting ID token verification: enc={id_token.encode()}")
        # header = jwt.decode(id_token.encode(), None)
        # self._logger.info(f"Verify ID token: header={header}")
        # kid = header.get("kid")
        # self._logger.info(f"Verify ID token: kid={kid}")
        
        # # Find matching key in JWKS
        # jwk = None
        # for key in self._jwks_cache.get("keys", []):
        #     if key.get("kid") == kid:
        #         jwk = JsonWebKey.import_key(key)
        #         break
        
        # if not jwk:
        #     raise ValueError(f"No matching key found for kid={kid}")
        # self._logger.info(f"Verify ID token: key={jwk}")
        
        # Verify and decode
        claims = jwt.decode(
            id_token,
            #jwk,
            key=self._jwks_cache.get("keys", []),
            claims_options={
                "iss": {"essential": True, "value": self._oidc["issuer"]},
                "aud": {"essential": True, "value": self._cfg.oidc_client_id},
                "exp": {"essential": True},
                "iat": {"essential": True},
                "nonce": {"essential": True, "value": nonce},
            },
        )
        
        self._logger.info(f"ID token verified successfully for sub={claims.get('sub')}")
        return claims


    def _request_scopes(self) -> str:
        if "openid" not in self._cfg.oidc_scope.split(" "):
            return f"openid {self._cfg.oidc_scope}"
        return self._cfg.oidc_scope
    

    def _getPath(self, location: str=None) -> str:
        if location == None:
            location = '/'
        # if self._cfg.port in [80, 443]:
        #     return f"{self._cfg.base_url}{location}"
        return f"{self._cfg.base_url}:{self._cfg.port}{location}"
    

    async def _fetch_userinfo(self, access_token: str) -> Dict[str, Any]:
        """Fetch user info from userinfo endpoint."""
        userinfo_endpoint = self._oidc.get("userinfo_endpoint")
        if not userinfo_endpoint:
            return {}
        
        self._logger.info(f"Fetching userinfo from {userinfo_endpoint}")
        response = await self._clien.get(
            userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        response.raise_for_status()
        return response.json()


    async def _introspect_token(self, token: str) -> Dict[str, Any]:
        """Introspect access token."""
        introspection_endpoint = self._oidc.get("introspection_endpoint")
        
        if not introspection_endpoint:
            # self._logger.warning("No introspection endpoint available")
            return {"active": False, "error": "introspection_not_supported"}
        
        auth = None
        if self._cfg.oidc_client_secret:
            auth = (self._cfg.oidc_client_id, self._cfg.oidc_client_secret)
        
        response = await self._client.post(
            introspection_endpoint,
            data={"token": token, "client_id": self._cfg.oidc_client_id},
            auth=auth,
        )
        response.raise_for_status()
        return response.json()
