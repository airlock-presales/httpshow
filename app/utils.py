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
import json
import logging
import os
from dataclasses import dataclass
from typing import Dict, Any, Optional
from html import escape

from fastapi import Request

logger = logging.getLogger(__name__)


def setup_logging():
    """Configure logging."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    uvicorn_error = logging.getLogger("uvicorn.error")
    uvicorn_error.disabled = True
    uvicorn_access = logging.getLogger("uvicorn.access")
    uvicorn_access.disabled = True


def safe_html_escape(text: str, max_length: int = 10000) -> str:
    """Safely escape HTML and truncate if needed."""
    if len(text) > max_length:
        text = text[:max_length] + f"\n\n[... truncated {len(text) - max_length} characters]"
    return escape(text)


def pretty_json(data: Any, max_length: int = 50000) -> str:
    """Format JSON data with pretty printing."""
    try:
        json_str = json.dumps(data, indent=2, ensure_ascii=False)
        if len(json_str) > max_length:
            json_str = json_str[:max_length] + f"\n\n[... truncated {len(json_str) - max_length} characters]"
        return json_str
    except Exception as e:
        return f"Error formatting JSON: {e}"


def decode_basic_auth(auth_header: str) -> Optional[Dict[str, str]]:
    """Decode HTTP Basic Auth header."""
    if not auth_header.startswith("Basic "):
        return None
    
    try:
        encoded = auth_header[6:]
        decoded = base64.b64decode(encoded).decode("utf-8")
        username, password = decoded.split(":", 1)
        return {"username": username, "password": password}
    except Exception as e:
        logger.warning(f"Failed to decode Basic Auth: {e}")
        return None


def decode_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode JWT token without verification (for display purposes)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        
        # Decode header and payload
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        
        return {
            "header": header,
            "payload": payload,
            "raw": token,
        }
    except Exception as e:
        logger.warning(f"Failed to decode JWT: {e}")
        return {"raw": token, "error": str(e)}


async def parse_request_details(request: Request, cfg) -> Dict[str, Any]:
    """Parse request details for display."""
    # Request line
    request_line = f"{request.method} {request.url.path} HTTP/1.1"
    
    # Query parameters
    query_params = dict(request.query_params)
    
    # Headers
    headers = dict(request.headers)
    
    # Decode Basic Auth if present
    basic_auth = None
    auth_header = headers.get("authorization", "")
    if auth_header:
        basic_auth = decode_basic_auth(auth_header)
    
    # Cookies
    cookies = dict(request.cookies)
    
    # Body
    body_data = None
    body_preview = ""
    content_type = headers.get("content-type", "")
    
    try:
        # Read body (with size limit)
        body_bytes = await request.body()
        if len(body_bytes) > 1_000_000:  # 1 MB limit
            body_preview = f"[Body too large: {len(body_bytes)} bytes, showing first 1MB]"
            body_bytes = body_bytes[:1_000_000]
        
        if body_bytes:
            # Try to decode as text
            try:
                body_text = body_bytes.decode("utf-8")
                
                # Pretty print JSON
                if "application/json" in content_type:
                    try:
                        body_data = json.loads(body_text)
                        body_preview = pretty_json(body_data)
                    except json.JSONDecodeError:
                        body_preview = safe_html_escape(body_text)
                
                # Parse form data
                elif "application/x-www-form-urlencoded" in content_type:
                    from urllib.parse import parse_qs
                    form_data = parse_qs(body_text)
                    body_data = {k: v[0] if len(v) == 1 else v for k, v in form_data.items()}
                    body_preview = pretty_json(body_data)
                
                else:
                    body_preview = safe_html_escape(body_text)
                    
            except UnicodeDecodeError:
                # Binary content
                hex_preview = body_bytes[:256].hex()
                body_preview = f"[Binary content, {len(body_bytes)} bytes]\nHex preview: {hex_preview}"
    
    except Exception as e:
        body_preview = f"Error reading body: {e}"
    
    # Client IP
    client_ip = request.client.host if request.client else "unknown"
    
    # X-Forwarded-For (if present)
    forwarded_for = headers.get("x-forwarded-for")
    forwarded_trust = "untrusted"
    if cfg.trust_proxy_headers and client_ip in cfg.trusted_proxies:
        forwarded_trust = "trusted"
    
    return {
        "request_line": request_line,
        "method": request.method,
        "path": request.url.path,
        "query_params": query_params,
        "headers": headers,
        "basic_auth": basic_auth,
        "cookies": cookies,
        "body_preview": body_preview,
        "body_data": body_data,
        "content_type": content_type,
        "client_ip": client_ip,
        "forwarded_for": forwarded_for,
        "forwarded_trust": forwarded_trust,
    }

