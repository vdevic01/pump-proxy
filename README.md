# Pump Proxy

Pump Proxy is a reverse proxy designed to securely delegate authentication and authorization for the Kubernetes Dashboard. It replaces the default service account token-based login with modern authentication methods and fine-grained access control.
Pump Proxy is fully steteless.

## How It Works

1. **User Authentication:**
	- User visits the Pump Proxy login page.
	- Authenticates via OIDC or SAML (configurable).
2. **Authorization Mapping:**
	- Pump Proxy uses ACLs to map the user's identity (group/email) to a Kubernetes service account.
3. **Token Generation:**
	- A service account token is generated (via Kubernetes API), encrypted, and placed in a JWT.
	- The JWT is sent to the user's browser as a secure cookie.
4. **Proxying Requests:**
	- When the user accesses the dashboard, Pump Proxy validates the JWT, decrypts the token, and injects it into the request as a Bearer token.

## Prerequisites

To use Pump Proxy in a Kubernetes cluster, the deployment must be assigned a service account with permissions to generate service account tokens. This typically requires the following:

- The service account used by Pump Proxy must have the `create` permission on `serviceaccounts/token` in the target namespace.
- Example RBAC manifest:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pump-proxy-token-generator
  namespace: <target-namespace>
rules:
  - apiGroups: [""]
    resources: ["serviceaccounts/token"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: pump-proxy-token-generator-binding
  namespace: <target-namespace>
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pump-proxy-token-generator
subjects:
  - kind: ServiceAccount
    name: <pump-proxy-service-account>
    namespace: <target-namespace>
```

Replace `<target-namespace>` and `<pump-proxy-service-account>` with your actual namespace and service account name.

## Configuration

Pump Proxy uses the Viper library for configuration. You can configure Pump Proxy using either a TOML file (recommended for local/dev) or environment variables (recommended for production/secrets). When using environment variables, all keys must be prefixed with `PUMP_PROXY_APP_` (e.g., `PUMP_PROXY_APP_JWT_SECRET`).

### How Viper Loads Configuration

- By default, Pump Proxy loads configuration from `default_config.toml`. You can specify a different config file using the `--config-file` flag.
- Any environment variable with the prefix `PUMP_PROXY_APP_` will override the corresponding config file value.
- Nested config options (e.g., OIDC, SAML, Cookie) use underscores: `PUMP_PROXY_APP_OIDC_OIDC_URL`, `PUMP_PROXY_APP_SAML_ENTITY_ID`, etc.

### Main Options

| Variable                        | Type    | Description                                                      |
|----------------------------------|---------|------------------------------------------------------------------|
| `jwt_secret`                    | string  | Secret key for signing JWT tokens                                |
| `target_url`                    | string  | URL of the Kubernetes Dashboard to proxy                         |
| `encryption_key`                | string  | Key for encrypting service account tokens (16/32/64 bytes)       |
| `port`                          | int     | Port to run Pump Proxy on                                        |
| `host`                          | string  | Host to bind Pump Proxy to                                       |
| `token_duration`                | int     | Token lifetime in seconds                                        |
| `service_account_namespace`     | string  | Namespace for service accounts                                   |
| `run_in_debug`                  | bool    | Enable debug mode (prints config)                                |
| `auth_type`                     | string  | Authentication type: `oidc` or `saml`                            |

### OIDC Options *(considered if `auth_type` is `oidc`)*

| Variable                        | Type    | Description                                                      |
|----------------------------------|---------|------------------------------------------------------------------|
| `oidc.oidc_url`                 | string  | OIDC provider URL                                                |
| `oidc.oidc_client_id`           | string  | OIDC client ID                                                   |
| `oidc.oidc_client_secret`       | string  | OIDC client secret                                               |
| `oidc.oidc_redirect_url`        | string  | OIDC redirect/callback URL                                       |

### SAML Options *(considered if `auth_type` is `saml`)*

| Variable                        | Type    | Description                                                      |
|----------------------------------|---------|------------------------------------------------------------------|
| `saml.idp_metadata_url`         | string  | SAML IdP metadata URL                                            |
| `saml.entity_id`                | string  | SAML entity ID                                                   |
| `saml.user_group_attr_name`     | string  | SAML attribute for user group/role                               |
| `saml.user_id_attr_name`        | string  | SAML attribute for user ID/email                                 |
| `saml.cert_path`                | string  | Path to SAML certificate file                                    |
| `saml.key_path`                 | string  | Path to SAML key file                                            |

### Cookie Options

| Variable                        | Type    | Description                                                      |
|----------------------------------|---------|------------------------------------------------------------------|
| `cookie.secure`                 | bool    | Set cookies as secure                                            |
| `cookie.http_only`              | bool    | Set cookies as HTTP-only                                         |
| `cookie.same_site`              | string  | Cookie SameSite mode: `lax`, `strict`, or `none`. NOTE: SAML currently does not support `strict` mode.                 |

### ACL Mapping

| Variable                        | Type    | Description                                                      |
|----------------------------------|---------|------------------------------------------------------------------|
| `acl`                           | map     | Maps OIDC/SAML group IDs to Kubernetes service accounts           |

### Example TOML Configuration

```toml
jwt_secret = "your_jwt_secret"
target_url = "http://localhost:5000"
encryption_key = "your_encryption_key"
port = 8080
host = "localhost"
token_duration = 3600
service_account_namespace = "k8s-dashboard"
run_in_debug = false

auth_type = "oidc"

[oidc]
oidc_url = "https://your-oidc-provider/v2.0"
oidc_client_id = "your-client-id"
oidc_client_secret = "your-client-secret"
oidc_redirect_url = "http://localhost:8080/pumpproxy/callback"

[saml]
idp_metadata_url = "https://your-idp/metadata.xml"
entity_id = "pumpproxy"
user_group_attr_name = "group-attribute"
user_id_attr_name = "email-attribute"
cert_path = "./cert/cert.pem"
key_path = "./cert/key.pem"

[cookie]
secure = true
http_only = true
same_site = "lax"

[acl]
"group-id-1" = "dashboard-admin-service-account"
"group-id-2" = "dashboard-readonly-service-account"
```

## Endpoints

| Endpoint                        | Method | Description                                                      |
|----------------------------------|--------|------------------------------------------------------------------|
| `/pumpproxy/sign_in`             | GET    | Show sign-in page                                                |
| `/pumpproxy/sign_out`            | GET    | Sign out and clear cookies                                       |
| `/pumpproxy/auth`                | GET    | Start OIDC/SAML authentication flow                              |
| `/pumpproxy/callback`            | GET    | OIDC callback endpoint (OIDC only)                               |
| `/saml/`                         | GET    | SAML middleware endpoints (SAML only)                            |
| `/pumpproxy/static/*`            | GET    | Serve static files (CSS, images, etc.)                           |
| `/`                              | GET    | Proxies requests to the Kubernetes Dashboard                     |
| `/robots.txt`                    | GET    | Returns robots.txt                                               |

## Usage

### Running Locally

1. Build the binary:
	```powershell
	go build -o pump-proxy .
	```
2. Run the server:
	```powershell
	.\pump-proxy.exe --config-file default_config.toml
	```
3. Open your browser to `http://localhost:8080` (or configured host/port).

### Docker

Build and run using Docker:
```powershell
docker build -t pump-proxy .
docker run -p 8080:8080 --env-file .env pump-proxy
```

### Configuration Example

See `default_config.toml` for a template. All options can be set via environment variables (see Viper docs).

## License

MIT License