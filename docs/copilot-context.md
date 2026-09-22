# ArcGIS Enterprise Hardening Utility v2

## Important

app.py legacy hanya reference.

Jangan kembali ke arsitektur monolithic.

## Architecture

ConnectionRegistry
└── TargetContext[]

Bukan:

PortalResult
└── ServerResult

## Milestone 1

Focus:

- Connection
- Authentication
- Federation Discovery
- Target Registry

## Enterprise Mode

Input:

- Portal URL
- Username
- Password

Workflow:

Portal Login
→ Federation Discovery
→ Server Token Exchange
→ Target Registry

## Federated Server Connection

Priority:

1. Service URL first
2. Registered Admin URL fallback

Store:

- service_url
- registered_admin_url
- effective_admin_url

## Connection Route

Values:

- SERVICE_URL
- REGISTERED_ADMIN_URL

## TargetContext

Fields:

- target_id
- target_name
- component_type
- deployment_mode
- service_url
- registered_admin_url
- effective_admin_url
- version
- roles
- server_functions
- federation_state
- connection_state
- connection_route
- error
- metadata

## Security

- TLS verification enabled by default
- Never automatically disable TLS
- Never expose token
- Token must be redacted
- Never store password

## Partial Failure

One failed server must not stop discovery.