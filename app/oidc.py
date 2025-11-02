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
import base64
import logging
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from urllib.parse import urlencode

import httpx
from authlib.jose import jwt
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from fastapi import Request, HTTPException
from fastapi.responses import RedirectResponse

from app import config, session, response
from app.utils import create_jwt_token


class RP( object ):
    
    """
    OIDC RP
    """

    def __init__( self, cfg: config.Settings ):
        self._cfg = cfg
        self._oidc = {}
        self._jwks_cache = {}
        self._expires = datetime.now() - timedelta(seconds=86400)
        self._errors = []
        self._client = None
        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(self._cfg.log_level)
    
    async def init_client(self):
        """Initialize OIDC client and fetch discovery document."""
        if not self._cfg.oidc_issuer:
            self._logger.error(f"OIDC RP not configured")
            return
        
        # Create HTTP client
        self._client = httpx.AsyncClient( verify=self._cfg.verify_backend_certificate, timeout=self._cfg.client_timeout )
        
        # Fetch discovery document
        discovery_url = f"{self._cfg.oidc_issuer}/.well-known/openid-configuration"
        self._logger.info(f"Fetching OIDC discovery from {discovery_url}")
        
        try:
            api_response = await self._client.get(discovery_url)
            api_response.raise_for_status()
            self._oidc.update(api_response.json())
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
    
    
    async def handle_login(self, request: Request, sessions: session.SessionStore, output: response.RequestMirror) -> RedirectResponse:
        """Handle OIDC login initiation."""
        func = "handle_callback"
        if not self._client:
            self._errors.append( {"id": 100, "msg": f"OIDC: client not initialised"} )
            return await self._return_response(func, request, sessions, output)
        self._logger.debug(f"{func} - enter")

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
                self._errors.append( {"id": 1103, "msg": f"OIDC: PAR request failed: {str(e)}"} )
                self._errors.append( {"id": 1001, "msg": "Trying standard authorization code flow"} )
                # Fallback to regular authorization
                auth_url = self._oidc["authorization_endpoint"]
                authorization_url = f"{auth_url}?{urlencode(params)}"
        else:
            # Regular authorization request
            auth_url = self._oidc["authorization_endpoint"]
            authorization_url = f"{auth_url}?{urlencode(params)}"
        
        self._logger.info(f"Redirecting to authorization endpoint: {auth_url}")
        self._logger.debug("handle_login - exit")
        return RedirectResponse(url=authorization_url)


    async def handle_callback(self, request: Request, sessions: session.SessionStore, output: response.RequestMirror):
        """Handle OIDC callback and token exchange."""
        func = "handle_callback"
        if not self._client:
            self._errors.append( {"id": 100, "msg": f"OIDC: client not initialised"} )
            return await self._return_response(func, request, sessions, output)
        self._logger.debug(f"{func} - enter")

        # Check for request errors
        error = request.query_params.get("error")
        if error:
            error_description = request.query_params.get("error_description", "Unknown error")
            self._logger.error(f"OIDC: {error} - {error_description}")
            self._errors.append( {"id": 102, "msg": f"OIDC: {error} - {error_description}"} )
            return await self._return_response(func, request, sessions, output)
        
        # Verify session
        session_data = self._get_session(request, sessions)
        self._logger.debug(f"callback: {session_data}")
        if session_data == None:
            self._logger.error("Invalid session")
            self._errors.append( {"id": 201, "msg": f"Session: unknown"} )
            return await self._return_response(func, request, sessions, output)
        
        # Verify state
        state = request.query_params.get("state")
        stored_state = session_data.get("oidc_state")
        if not state or state != stored_state:
            self._logger.error("State mismatch or missing")
            self._errors.append( {"id": 103, "msg": f"OIDC: state mismatch or missing"} )
            return await self._return_response(func, request, sessions, output)
        
        # Get authorization code
        code = request.query_params.get("code")
        if not code:
            self._errors.append( {"id": 104, "msg": f"OIDC: no authorization code received"} )
            return await self._return_response(func, request, sessions, output)
        
        # Exchange code for tokens
        code_verifier = session_data.get("oidc_code_verifier")
        
        try:
            tokens = await self._exchange_code_for_tokens(code, code_verifier)
        except Exception as e:
            self._logger.error(f"Token exchange failed: {e}")
            self._errors.append( {"id": 105, "msg": f"OIDC: failed to exchange auth code into token: {str(e)}"} )
            return await self._return_response(func, request, sessions, output)
        
        # Verify ID token
        id_token = tokens.get("id_token")
        if not id_token:
            self._errors.append( {"id": 106, "msg": f"OIDC: no ID token received"} )
            return await self._return_response(func, request, sessions, output)
        
        nonce = session_data.get("oidc_nonce")
        if self._expires < datetime.now():
            try:
                # Fetch JWKS
                jwks_uri = self._oidc.get("jwks_uri")
                if jwks_uri:
                    self._jwks_cache = {}
                    jwks_response = await self._client.get(jwks_uri)
                    jwks_response.raise_for_status()
                    self._jwks_cache.update(jwks_response.json())
                    self._expires = datetime.now() + timedelta(seconds=self._cfg.jwks_refresh_interval)
                    self._logger.info(f"JWKS refreshed from {jwks_uri}")
            except Exception as e:
                self._logger.warning(f"Failed to refresh JWKS: {e}")
                self._errors.append( {"id": 1105, "msg": f"OIDC: failed to refresh JWKS ({str(e)})"} )
        try:
            claims = self._verify_id_token(id_token, nonce)
        except Exception as e:
            self._logger.error(f"ID token verification failed: {e}")
            self._errors.append( {"id": 101, "msg": f"OIDC: ID token verification failed: {str(e)}"} )
            return await self._return_response(func, request, sessions, output)
        
        # Fetch userinfo if enabled
        userinfo = {}
        if self._cfg.userinfo and tokens.get("access_token"):
            try:
                userinfo = await self._fetch_userinfo(tokens["access_token"])
            except Exception as e:
                self._logger.warning(f"Failed to fetch userinfo: {e}")
                self._errors.append( {"id": 1101, "msg": f"OIDC: failed to fetch userinfo: {str(e)}"} )
        
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
        
        # Redirect back to page requesting authentication
        root = self._getPath("")
        forward_location = session_data.get("forward_location")
        if forward_location:
            if forward_location.startswith( "http://" ) or forward_location.startswith( "https://" ):
                forward_location = '/'
        self._logger.info(f"Redirect back to initial page: {forward_location}")
        self._logger.debug(f"{func} - exit")
        return RedirectResponse(url=forward_location, status_code=303)


    async def handle_logout(self, request: Request, sessions: session.SessionStore, output: response.RequestMirror, oidc_logout: bool=False):
        """Handle logout."""
        func = "handle_logout"
        if not self._client:
            self._errors.append( {"id": 100, "msg": f"OIDC: client not initialised"} )
            return await self._return_response(func, request, sessions, output)
        self._logger.debug(f"{func} - enter")
        session_id = request.session.get("id")
        sessions.delete( session_id )
        request.session.clear()
        self._logger.info("Session cleared")
        
        self._logger.debug(f"oidc_logout: {oidc_logout}, url: {self._cfg.oidc_logout_url}")
        if oidc_logout and self._cfg.oidc_logout_url:
            param = { "post_logout_redirect_uri": self._getPath() }
            forward_location = f"{self._cfg.oidc_logout_url}?{urlencode(param)}"
            self._logger.info(f"Redirect OIDC OP logout page: {forward_location}")
            self._logger.debug(f"{func} - exit")
            return RedirectResponse(url=forward_location, status_code=303)

        return await self._return_response(func, request, sessions, output)


    async def handle_profile(self, request: Request, sessions: session.SessionStore, output: response.RequestMirror):
        """Handle profile page with token introspection."""
        func = "handle_profile"
        if not self._client:
            self._errors.append( {"id": 100, "msg": f"OIDC: client not initialised"} )
            return await self._return_response(func, request, sessions, output)
        self._logger.debug(f"{func} - enter")

        # Retrieve session & user information
        session_data = self._get_session(request, sessions, init=True)
        user = self.get_current_user(request, sessions=sessions, session_data=session_data)
        tokens = session_data.get("tokens", {})
        if user:
            access_token = tokens.get( "access_token" )
        if not access_token:
            self._logger.info("No access token - rediect to login")
            return self._redirectLogin( request, sessions )

        # Introspect token
        try:
            introspection_result = await self._introspect_token(access_token)
        except Exception as e:
            self._logger.error(f"Token introspection failed: {e}")
            self._errors.append( {"id": 1104, "msg": f"OIDC: introspection failed: {str(e)}"} )
        auth_info = {
            "token": None,
            "introspection": introspection_result
        }

        return await self._return_response(func, request, sessions, output, auth_info=auth_info)


    async def handle_api_call(self, request: Request, sessions: session.SessionStore, output: response.RequestMirror, delegation: bool=False):
        """Handle API page with callout to backend api."""
        func = "handle_api_call"
        self._logger.debug(f"{func} - enter")

        api_url = self._cfg.api_direct_url
        if not api_url:
            self._errors.append( {"id": 1, "msg": f"Config: api.oidc.url"} )
            return await self._return_response(func, request, sessions, output)
        api_host = None
        if self._cfg.api_direct_host:
            api_host = self._cfg.api_direct_host
        
        session_data = self._get_session(request, sessions, init=True)
        tokens = session_data.get("tokens", {})

        # Get bearer token, if available
        authorization_header = request.headers.get("authorization", "")
        bearer_auth = None
        if authorization_header and authorization_header.startswith("Bearer "):
            bearer_auth = authorization_header[7:]
            
        # Token Exchange for delegation token
        if delegation:
            self._logger.debug("token exchange - start")
            if not self._cfg.tokenexchange_url:
                self._errors.append( {"id": 2, "msg": f"Config: tokenExchange.url"} )
                return await self._return_response(func, request, sessions, output)
            if not self._cfg.tokenexchange_delegation_claim:
                self._errors.append( {"id": 3, "msg": f"Config: tokenExchange.delegationClaim"} )
                return await self._return_response(func, request, sessions, output)
            
            api_url = self._cfg.api_tkx_url
            if not api_url:
                self._errors.append( {"id": 4, "msg": f"Config: api.tokenexchange.url"} )
                return await self._return_response(func, request, sessions, output)
            if self._cfg.api_tkx_host:
                api_host = self._cfg.api_tkx_host
            
            # User token
            # - use bearer token passed in Authorization header
            if bearer_auth:
                user_token = bearer_auth
                self._logger.info("Set user token from Authorization header")
            # - otherwise, use id or access token
            elif self._cfg.api_auth_token == "id-token":
                user_token = tokens.get("id_token")
                self._logger.info("Set user token from id token")
            else:
                user_token = tokens.get("access_token")
                self._logger.info("Set user token from access token")
            if not user_token:
                self._logger.error("No user token available")
                self._errors.append( {"id": 201, "msg": f"Session: no user token available for token exchange"} )
                return await self._return_response(func, request, sessions, output)

            # Actor token
            actor_token = create_jwt_token(self._cfg.base_url, 100)

            # Prepare token exchange body
            body = {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                    "subject_token": user_token, "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    "actor_token": actor_token, "actor_token_type": "urn:ietf:params:oauth:token-type:access_token"}
            headers = {'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'}
            if self._cfg.tokenexchange_host:
                headers['Host'] = self._cfg.tokenexchange_host
            
            # Client authentication
            auth = None
            if self._cfg.oidc_client_secret:
                auth = (self._cfg.tokenexchange_client_id, self._cfg.tokenexchange_client_secret)
            
            # Call API backend
            self._logger.debug("Do token exchange")
            api_response = await self._client.post(
                self._cfg.tokenexchange_url,
                headers=headers,
                data=body,
                auth=auth,
            )
            try:
                api_response.raise_for_status()
            except Exception as e:
                self._errors.append( {"id": 301, "msg": f"Token Exchange: failed - {str(e)}"} )
                return await self._return_response(func, request, sessions, output)
            try:
                result = api_response.json()
            except Exception as e:
                self._logger.error(f"No JSON received in Token Exchange: {e}")
                self._logger.debug(f"Response: {api_response.text}")
                self._errors.append( {"id": 302, "msg": f"Token Exchange: invalid response - {str(e)}"} )
                return await self._return_response(func, request, sessions, output)
            self._logger.debug("token exchange - done")
            auth_token = result['access_token']
            self._logger.info("Using result from token exchange for backend auth")
        
        else:
            # If not token exchange, use bearer token passed in Authorization header
            auth_header = request.headers.get("authorization", "")
            if bearer_auth:
                auth_token = bearer_auth
                self._logger.info("Using token from Authorization header for backend auth")
            # Otherwise, use id or access token for backend auth
            elif self._cfg.api_auth_token == "id-token":
                auth_token = tokens.get("id_token")
                self._logger.info("Using id token for backend auth")
            else:
                auth_token = tokens.get("access_token")
                self._logger.info("Using access token for backend auth")

        # Call API backend
        headers = {'Accept': 'application/json'}
        if auth_token:
            if self._cfg.api_auth_header:
                headers[self._cfg.api_auth_header] = auth_token
            else:
                headers['Authorization'] = f"Bearer {auth_token}"
        if api_host:
            headers['Host'] = api_host
        self._logger.debug("headers")
        
        self._api_client = httpx.AsyncClient( verify=self._cfg.verify_backend_certificate, timeout=self._cfg.client_timeout )
        api_response = await self._api_client.get(
            api_url,
            headers=headers,
        )
        self._logger.debug("callout")
        try:
            api_response.raise_for_status()
        except Exception as e:
            self._errors.append( {"id": 303, "msg": f"API call: failed - {str(e)}"} )
            return await self._return_response(func, request, sessions, output)
        try:
            result = {"status": api_response.status_code, "json": api_response.json()}
        except Exception as e:
            self._logger.debug(f"Response: {api_response.text}")
            self._logger.error(f"No JSON received: {e}")
            self._errors.append( {"id": 304, "msg": f"API call: invalid response - {str(e)}"} )
            return await self._return_response(func, request, sessions, output)
        
        auth_info = {
            "token": auth_token,
            "introspection": {}
        }

        return await self._return_response(func, request, sessions, output, api_details=result, auth_info=auth_info)


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

    def _redirectLogin(self, request: Request, sessions: session.SessionStore):
        base = str(request.base_url).rstrip('/')
        url = str(request.url)
        forward_location = url[len(base):]
        session_data = self._get_session(request, sessions)
        if session_data:
            session_data.set("forward_location", forward_location)
        else:
            session_data = sessions.create( {"forward_location", forward_location} )
            request.session["id"] = session_data.id
        return RedirectResponse(url=f"/oidc/login?loc={forward_location}")

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
        api_response = await self._client.post(
            token_endpoint,
            data=token_data,
            auth=auth,
        )
        api_response.raise_for_status()
        return api_response.json()


    def _verify_id_token(self, id_token: str, nonce: str) -> Dict[str, Any]:
        """Verify and decode ID token."""
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
        return f"{self._cfg.base_url}{location}"
    

    async def _return_response(self, func: str, request: Request, sessions: session.SessionStore, output: response.RequestMirror, api_details: Dict=None, auth_info: Dict=None):
        my_response = await output.mirror(request, sessions, api_details=api_details, auth_info=auth_info, errors=self._errors)
        if self._errors:
            self._logger.debug(f"{func} - error")
            self._errors = []
        else:
            self._logger.debug(f"{func} - exit")
        return my_response

    async def _fetch_userinfo(self, access_token: str) -> Dict[str, Any]:
        """Fetch user info from userinfo endpoint."""
        userinfo_endpoint = self._oidc.get("userinfo_endpoint")
        if not userinfo_endpoint:
            return {}
        
        self._logger.info(f"Fetching userinfo from {userinfo_endpoint}")
        api_response = await self._clien.get(
            userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        api_response.raise_for_status()
        return api_response.json()


    async def _introspect_token(self, token: str) -> Dict[str, Any]:
        """Introspect access token."""
        introspection_endpoint = self._oidc.get("introspection_endpoint")
        
        if not introspection_endpoint:
            # self._logger.warning("No introspection endpoint available")
            return {"active": False, "error": "introspection_not_supported"}
        
        auth = None
        if self._cfg.oidc_client_secret:
            auth = (self._cfg.oidc_client_id, self._cfg.oidc_client_secret)
        
        api_response = await self._client.post(
            introspection_endpoint,
            data={"token": token, "client_id": self._cfg.oidc_client_id},
            auth=auth,
        )
        api_response.raise_for_status()
        return api_response.json()


