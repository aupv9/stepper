# Deployment

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `IAM_ADDR` | `:8080` | HTTP listen address |
| `IAM_POLICY_FILE` | `config/policy.example.yaml` | Path to policy YAML |
| `IAM_REALM` | `IAM` | Realm name in WWW-Authenticate challenges |
| `IAM_UPSTREAM_URL` | _(empty)_ | Reverse proxy upstream URL. If empty, returns a placeholder response |

---

## Docker

### Build image

```bash
docker build -f deployments/Dockerfile -t common-iam:latest .
```

### Run standalone

```bash
docker run -d \
  --name iam \
  -p 8080:8080 \
  -e IAM_UPSTREAM_URL=http://your-backend:3000 \
  -e IAM_REALM=MyApp \
  -v $(pwd)/config/policy.yaml:/app/config/policy.yaml:ro \
  common-iam:latest
```

### Verify

```bash
curl http://localhost:8080/health
# {"status":"ok"}

curl http://localhost:8080/metrics
# Prometheus metrics output
```

---

## Docker Compose

The included `deployments/docker-compose.yml` provides a full stack with Redis:

```bash
# Start
docker compose -f deployments/docker-compose.yml up -d

# Check logs
docker compose -f deployments/docker-compose.yml logs -f iam-service

# Stop
docker compose -f deployments/docker-compose.yml down
```

**Customize for your environment:**

```yaml
services:
  iam-service:
    image: common-iam:latest
    environment:
      IAM_UPSTREAM_URL: "http://your-backend:3000"
      IAM_REALM: "YourAppName"
```

---

## Kubernetes

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: iam-service
spec:
  replicas: 2
  selector:
    matchLabels:
      app: iam-service
  template:
    metadata:
      labels:
        app: iam-service
    spec:
      containers:
        - name: iam-service
          image: common-iam:latest
          ports:
            - containerPort: 8080
          env:
            - name: IAM_ADDR
              value: ":8080"
            - name: IAM_REALM
              value: "MyApp"
            - name: IAM_POLICY_FILE
              value: "/config/policy.yaml"
            - name: IAM_UPSTREAM_URL
              value: "http://backend-service:3000"
          volumeMounts:
            - name: policy-config
              mountPath: /config
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 5
          readinessProbe:
            httpGet:
              path: /health
              port: 8080
      volumes:
        - name: policy-config
          configMap:
            name: iam-policy
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: iam-policy
data:
  policy.yaml: |
    version: "1"
    realm: "MyApp"
    acr_levels:
      - "urn:mace:incommon:iap:bronze"
      - "urn:mace:incommon:iap:silver"
      - "urn:mace:incommon:iap:gold"
    policies:
      - name: authenticated
        enabled: true
        resources: [/api/**]
        require_acr: "urn:mace:incommon:iap:bronze"
```

### Service + Ingress

```yaml
apiVersion: v1
kind: Service
metadata:
  name: iam-service
spec:
  selector:
    app: iam-service
  ports:
    - port: 8080
      targetPort: 8080
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-ingress
spec:
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: iam-service
                port:
                  number: 8080
```

---

## Hot-Reload Policy (No Restart)

Update policies at runtime via the Admin API:

```bash
# Reload from a local file
curl -X POST http://localhost:8080/admin/policy/reload \
  -H "Content-Type: application/json" \
  -d "{\"yaml\": $(cat config/policy.yaml | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')}"

# Check current policy summary
curl http://localhost:8080/admin/policy/summary
```

In Kubernetes, update the ConfigMap and trigger a reload:

```bash
kubectl create configmap iam-policy --from-file=policy.yaml=./new-policy.yaml \
  --dry-run=client -o yaml | kubectl apply -f -

# Then call the admin reload endpoint from within the cluster
kubectl exec deploy/iam-service -- curl -X POST localhost:8080/admin/policy/reload \
  -H "Content-Type: application/json" \
  -d "{\"yaml\": $(cat new-policy.yaml | ...)}"
```

---

## Prometheus Metrics

Scrape `/metrics` for Prometheus. Key metrics:

| Metric | Labels | Description |
|---|---|---|
| `iam_stepup_challenges_total` | `tenant`, `required_acr`, `method` | Step-up challenges issued |
| `iam_stepup_success_total` | `tenant` | Successful step-up completions |
| `iam_token_validation_duration_seconds` | `tenant`, `provider`, `cache_hit` | Introspection latency |
| `iam_token_cache_total` | `tenant`, `result` | Cache hit/miss counts |
| `iam_policy_eval_duration_seconds` | `tenant`, `matched_policy` | Policy evaluation latency |
| `iam_policy_denied_total` | `tenant`, `policy_name`, `reason` | Policy denial counts |
| `iam_active_tenants` | — | Number of registered tenants |

### Prometheus scrape config

```yaml
scrape_configs:
  - job_name: iam-service
    static_configs:
      - targets: ['iam-service:8080']
    metrics_path: /metrics
```

---

## Revocation Webhook

Point your AS's revocation notification to:

```
POST http://iam-service:8080/webhook/revoke
Content-Type: application/json

{
  "token_hash": "sha256-of-token",      // revoke specific token
  "jti": "jwt-id",                      // OR revoke by JTI
  "sub": "user-id",                     // OR revoke all tokens for user
  "revoke_all": true
}
```

This clears the token from the cache immediately, without waiting for the 30s TTL.

---

## Production Checklist

- [ ] Set `IAM_REALM` to your application name
- [ ] Mount policy YAML as a ConfigMap / volume (not baked into image)
- [ ] Configure Redis for distributed token cache (multiple replicas)
- [ ] Set up Prometheus scraping of `/metrics`
- [ ] Configure revocation webhook in your AS
- [ ] Schedule periodic `RefreshConfig` for provider discovery refresh
- [ ] Set resource limits on the container
- [ ] Enable readiness/liveness probes on `/health`
- [ ] Restrict `/admin/` routes with network policy or authentication
