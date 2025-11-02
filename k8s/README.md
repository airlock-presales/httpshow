# Kubernetes Deployment Guide

This directory contains Kubernetes manifests for deploying HTTPShow using Gateway API.

## Prerequisites

- Kubernetes cluster (v1.25+)
- Gateway API CRDs installed
- Gateway controller installed and configured (e.g. Airlock Microgateway)
- kubectl configured

## Quick Deploy

1. **Set configuration**:
    - Adjust all settings according to your environment and requirements
    - See the main [README](../../..) for details
     ```bash
     vi k8s/secret.yaml k8s/configmap.yaml
     ```

2. **Update HTTPRoute** in `k8s/httproute.yaml`:
   - Set `hostnames` to your domain
   - Adjust `parentRefs` for your Gateway

3. **Deploy**:
   ```bash
   kubectl apply -f k8s/
   ```

4. **Verify**:
   ```bash
   kubectl get pods -n httpshow
   kubectl get httproute -n httpshow
   ```

## Helm chart

If you prefer to use helm for deployments:

1. **Set configuration**:
    - Adjust all settings according to your environment and requirements
    - See the main [README](../../..) for details
     ```bash
     cp k8s/helm/values.yaml custom.yaml
     vi custom.yaml
     ```

2. **Install chart**:
     ```bash
     helm install httpshow k8s/helm -f custom.yaml
     ```

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
