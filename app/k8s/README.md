# Kubernetes Deployment Guide

This directory contains Kubernetes manifests for deploying HTTPShow using Gateway API.

## Prerequisites

- Kubernetes cluster (v1.25+)
- Gateway API CRDs installed
- Gateway controller installed and configured (e.g. Airlock Microgateway)
- kubectl configured

## Quick Deploy

1. **Update secrets** in `secret.yaml`:
```bash
kubectl create secret generic httpshow \
  --from-literal=HTTPSHOW_APP_SECRET_KEY="$(openssl rand -base64 32)" \
  --from-literal=HTTPSHOW_OIDC_ISSUER="https://your-provider.com" \
  --from-literal=HTTPSHOW_OIDC_CLIENT_ID="your-client-id" \
  --from-literal=HTTPSHOW_OIDC_CLIENT_SECRET="your-client-secret" \
  -n oidc-inspector --dry-run=client -o yaml > secret.yaml
```

2. **Update ConfigMap** in `configmap.yaml`:
   - Adjust all settings according to your environment and requirements
   - Set `HTTPSHOW_BASE_URL` to your actual domain
   - Adjust `HTTPSHOW_TRUSTED_PROXIES` for your cluster CIDR

3. **Update HTTPRoute** in `httproute.yaml`:
   - Set `hostnames` to your domain
   - Adjust `gatewayClassName` for your controller

4. **Deploy**:
```bash
kubectl apply -f .
```

5. **Verify**:
```bash
kubectl get pods -n httpshow
kubectl get httproute -n oidc-inspector
```

## Configuration

### Environment Variables

All configuration is in `configmap.yaml` and `secret.yaml`. Key settings:

- **HTTPSHOW_BASE_URL**: Must match your ingress hostname
- **HTTPSHOW_TRUST_PROXY_HEADERS**: Set to "true" when behind Gateway/Ingress
- **HTTPSHOW_TRUSTED_PROXIES**: Your cluster pod/service CIDR

### Scaling

The HPA automatically scales between 2-10 replicas based on CPU/memory. Adjust in `hpa.yaml`:

```yaml
minReplicas: 2
maxReplicas: 10
```

Not that you would need it. :-)

## Troubleshooting

### Logs

```bash
# Follow logs from all pods
kubectl logs -f -l app=httpshow -n httpshow

# Logs from specific pod
kubectl logs -f <pod-name> -n httpshow
```

### OIDC callback fails

Check:
- `HTTPSHOW_BASE_URL` matches actual URL (including https://)
- Redirect URI in provider matches `${HTTPSHOW_BASE_URL}/oidc/callback`
- `HTTPSHOW_TRUST_PROXY_HEADERS=true` when behind Gateway
- Pay attention to the fact that web browser and httpshow access OIDC provider via the same DNS name.
  - Usually not an issue for external OIDC providers.
  - If OIDC provider is deployed in same cluster make sure DNS resolution works for all components.

### Session issues

Sessions are in-memory, tied to a pod, and lost on pod restart.

Service has session affinity enabled to reduce the impact.

## Cleanup

```bash
kubectl delete namespace httpshow
```
