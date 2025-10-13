# HTTPShow

A secure, production-ready Python web application that demonstrates OIDC authentication flows and provides detailed HTTP request inspection capabilities.

## Features

- **Request Inspector**: View detailed HTTP request information (method, path, query, headers, body)
- **OIDC Relying Party (RP)**: Full Authorization Code flow with PKCE and optional PAR support
- **OIDC Resource Server (RS)**: Token introspection and validation
- **Security**: State, nonce, PKCE, secure cookies, CSP headers, HTML escaping
- **Docker Support**: Multi-stage builds with dev and production profiles
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

Manifests are in `app/k8s/` directory. See [Kubernetes README](app/k8s) for detailed instructions.

## Local Development

1. **Clone and setup**:
```bash
git clone <repository-url>
cd HTTPShow
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

2. **Configuration**:
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
  ```

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

# Configuration

All configuration via environment variables (see `.env.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| `HTTPSHOW_SERVER_PORT` | 8000 | Application port |
| `HTTPSHOW_BASE_URL` | http://localhost:8000 | External URL for callbacks |
| `HTTPSHOW_APP_SECRET_KEY` | *required* | Secret for signing cookies |
| `HTTPSHOW_OIDC_ISSUER` | *required* | OIDC provider issuer URL |
| `HTTPSHOW_OIDC_CLIENT_ID` | *required* | OAuth2 client ID |
| `HTTPSHOW_OIDC_CLIENT_SECRET` | - | OAuth2 client secret (optional for public clients) |
| `HTTPSHOW_OIDC_TIMEOUT` | - | Timeeout for connections to OIDC provider endpoints (token, userinfo, introspection) |
| `HTTPSHOW_OIDC_SCOPES` | openid email profile | OAuth2 scopes |
| `HTTPSHOW_PKCE` | true | Enable PKCE (S256) |
| `HTTPSHOW_PAR` | false | Enable Pushed Authorization Requests |
| `HTTPSHOW_USERINFO` | false | Fetch UserInfo endpoint |
| `HTTPSHOW_VERIFY_PROVIDER_CERTIFICATE` | true | Verify SSL certificates |
| `HTTPSHOW_SESSION_COOKIE_NAME` | demo_session | Cookie to use for session id |
| `HTTPSHOW_SESSION_LIFETIME` | 300 | Expiration of authenticated session |
| `HTTPSHOW_TRUST_PROXY_HEADERS` | false | Trust X-Forwarded-* headers |
| `HTTPSHOW_TRUSTED_PROXIES` | - | Comma-separated trusted proxy IPs |
| `HTTPSHOW_CSS_FILE` | - | Path to custom CSS file |
| `HTTPSHOW_NIGHT_MODE` | false | Enable dark theme |
| `HTTPSHOW_CONFIG_FILE` | - | Path to config file (not required if all configuration is done via environment variables) |

# Application details

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/*` | ALL | Request inspector (supports all HTTP methods) |
| `/profile` | GET | User profile with token introspection |
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
