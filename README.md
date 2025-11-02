# HTTPShow

A secure, production-ready Python web application that demonstrates OIDC authentication flows and provides detailed HTTP request inspection capabilities.

## Features

- **Request Inspector**: View detailed HTTP request information (method, path, query, headers, body)
- **OIDC Relying Party (RP)**: Full Authorization Code flow with PKCE and optional PAR support
- **OIDC Resource Server (RS)**: Token introspection and validation
- **REST/JSON API Client**: Backend API call to demonstrate token handling
- **OAuth2 Token Exchange Client**: 
- **Security**: State, nonce, PKCE, secure cookies, CSP headers, HTML escaping
- **Docker Support**: Debloated container image and manifests
- **Kubernetes Ready**: All manifests included to expose via a Gateway API Gateway

# Quick Start

## Clone
```bash
git clone https://github.com/airlock-presales/httpshow
cd httpshow
```

## Deploy with Docker Compose
```bash
cp samples/env.example .env
# Edit .env
docker compose up -d
```

## Deploy on Kubernetes

Manifests are in `k8s/` directory. See [Kubernetes README](k8s) for detailed instructions.

# Configuration

## Method

HTTPShow supports both a configuration file and environment variables with the latter taking precedence.
- Configfile
  ```bash
  cp samples/config.yaml .
  # Edit config.yaml
  export HTTPSHOW_CONFIG_FILE=<location-of-config.yaml>
  ```
- Environment
  ```bash
  cp samples/env.example .env
  # Edit .env

## Base Settings

| Configfile YAML key | Variable | Default | Description |
|---------------------|----------|---------|-------------|
| server.port | `HTTPSHOW_SERVER_PORT` | 8000 | Application port |
| server.baseURL | `HTTPSHOW_BASE_URL` | http://localhost:8000 | External URL as used by browsers, used for OIDC callback |
| server.trustedProxies | `HTTPSHOW_TRUSTED_PROXIES` | - | Comma-separated list of trusted proxy IPs |
| server.trustProxyHeaders | `HTTPSHOW_TRUST_PROXY_HEADERS` | false | Trust X-Forwarded-* headers |
| httpshow.appSecret | `HTTPSHOW_APP_SECRET_KEY` | *required* | Secret for signing cookies |
| httpshow.session.cookieName | `HTTPSHOW_SESSION_COOKIE_NAME` | demo_session | Cookie to use for session id |
| httpshow.session.lifetime | `HTTPSHOW_SESSION_LIFETIME` | 300 | Expiration of authenticated session |
| httpshow.cssFile | `HTTPSHOW_CSS_FILE` | - | Path to custom CSS file |
| httpshow.timeout | `HTTPSHOW_CLIENT_TIMEOUT` | - | Timeeout for connections to OIDC provider endpoints (token, userinfo, introspection) |
| httpshow.verifyBackendCertificate | `HTTPSHOW_VERIFY_BACKEND_CERTIFICATE` | true | Verify SSL certificates of backend systems (OIDC provider, API backend, Token Exchange service) |
| *n/a* | `HTTPSHOW_CONFIG_FILE` | - | Path to config file (not required if all configuration is done via environment variables) |

## OIDC RP Settings

| Configfile YAML key | Variable | Default | Description |
|---------------------|----------|---------|-------------|
| oidc.issuer | `HTTPSHOW_OIDC_ISSUER` | *required* | OIDC provider issuer URL, base for OIDC discovery |
| oidc.client.id | `HTTPSHOW_OIDC_CLIENT_ID` | *required* | OAuth2 client ID |
| oidc.client.secret | `HTTPSHOW_OIDC_CLIENT_SECRET` | - | OAuth2 client secret |
| oidc.scopes | `HTTPSHOW_OIDC_SCOPES` | openid email profile | Requested OAuth2 scopes |
| oidc.pkce | `HTTPSHOW_PKCE` | true | Use PKCE (S256) if provider supports it |
| oidc.par | `HTTPSHOW_PAR` | false | Use Pushed Authorization Requests if provider supports it |
| oidc.userInfo | `HTTPSHOW_USERINFO` | false | Fetch UserInfo when showing profile information |
| oidc.logoutUrl | `HTTPSHOW_OIDC_LOGOUT_URL` | - | Logout URL on OIDC provider |
| oidc.jwksRefresh | `HTTPSHOW_OIDC_JWKS_REFRESH` | 14400 | Refresh interval for JWKS |

## API Call Settings

HTTPShow uses bearer tokens to authenticate to the backend API service.

1. OIDC RP tokens
   
   The default is to use the Access Token but the ID Token can be used, instead.

2. Token returned from the Token Exchange service

   In this case, HTTPShow implements a Token Exchange client requesting an authentication token for delegation.

If the API service supports bearer tokens from multiple issuers, the same backend can be used. However, as most don't, HTTPShow can be configured for two different API backends.

| Configfile YAML key | Variable | Default | Description |
|---------------------|----------|---------|-------------|
| api.authHeader | `HTTPSHOW_API_AUTH_HEADER` | - | Name of HTTP header for authentication token, uses Authorization header with Bearer token if not set |
| api.authTokenType | `HTTPSHOW_API_AUTH_TOKEN` | access_token | OIDC token to use for authentication or as user token for Token Exchange (`access_token` or `id_token`) |
| api.direct.url | `HTTPSHOW_API_URL` | *myself* | URL of API service expecting OIDC token |
| api.direct.host | `HTTPSHOW_API_HOST` | - | Value of HOST header in HTTP request to API |
| api.exchanged.url | `HTTPSHOW_API_TKX_URL` | *myself*/tkx | URL of API service expecting "token-exchanged" token |
| api.exchanged.host | `HTTPSHOW_API_TKX_HOST` | - | Value of HOST header in HTTP request to API |
| tokenExchange.url | `HTTPSHOW_TOKEN_EXCHANGE_URL` | *required for token exchange* | URL of Token Exchange service token endpoint |
| tokenExchange.host | `HTTPSHOW_TOKEN_EXCHANGE_HOST` | - | Value of HOST header in HTTP request to Token Exchange service |
| tokenExchange.client.id | `HTTPSHOW_TOKEN_EXCHANGE_CLIENT_ID` | *required for token exchange* | OAuth2 client ID for Token Exchange service |
| tokenExchange.client.secret | `HTTPSHOW_TOKEN_EXCHANGE_CLIENT_SECRET` | *required for token exchange* | OAuth2 client Secret Token Exchange service|
| tokenExchange.delegationClaim | `HTTPSHOW_TOKEN_EXCHANGE_DELEGATION_CLAIM` | - | ??? |


# Local Development

1. **Clone and setup**:
```bash
git clone <repository-url>
cd HTTPShow
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

2. **Configuration**: See above

3. **Run the application**:
```bash
uvicorn app.main:app --reload --port 8000 --host 0.0.0.0
```

4. **Access the application**:
```
http://localhost:8000
```

# OIDC Provider Setup

Forthcoming

# Application details

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/*` | ALL | Request inspector (supports all HTTP methods) |
| `/profile` | GET | User profile with token introspection |
| `/api` | GET | Call API backend service |
| `/tkx` | GET | Call Token Exchange service, then call API backend with exchanged token |
| `/clear` | GET/POST | Clear user session |
| `/oidc/login` | GET | Initiate OIDC login flow |
| `/oidc/callback` | GET | OIDC callback handler |
| `/oidc/logout` | GET/POST | Clear session and logout |
| `/health` | GET | Health endpoint |

## Security Features

- ✅ **PKCE (S256)**: Protects against authorization code interception
- ✅ **State parameter**: Prevents CSRF attacks on OAuth flow
- ✅ **Nonce**: Protects against replay attacks on ID tokens
- ✅ **ID Token verification**: Full JWT validation (signature, issuer, audience, expiry)
- ✅ **Secure cookies**: HttpOnly, SameSite=Lax, Secure (when HTTPS)
- ✅ **CSP headers**: Content Security Policy to prevent XSS
- ✅ **HTML escaping**: All user input safely escaped
- ✅ **Body size limits**: Prevents memory exhaustion (1MB limit)
- ✅ **PAR support**: Optional Pushed Authorization Requests
- ✅ **Token introspection**: Validates access tokens server-side
- ✅ **Authentication to backend API**: Uses token to authenticate backend API call

# License

MIT License - See LICENSE file for details.

# Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

# Getting support

This tool is conrtibuted software and not part of the official Airlock product delivery. Airlock support will be unable to accept or answer tickets.

If you encounter an error, the author welcomes pull requests with fixes. Alternatively, an issue may be created on the [GitHub issue tracker](/issues). Please note that there is no guaranteed response time and any support is best effort.
