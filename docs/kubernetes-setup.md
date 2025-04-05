# Kubernetes Setup Guide for IPSwamp Honeypot

## Prerequisites

- Kubernetes cluster 1.19+
- kubectl configured
- Helm 3.0+ (optional)
- IPSwamp Honeypot API Key
- IPSwamp Honeypot ID

## Important Configuration

### Honeypot ID

Each honeypot instance must have a unique identifier. This ID is used to:

- Track attacks across your honeypot network
- Distinguish between different honeypot instances
- Associate collected data with specific honeypots

**⚠️ Warning:** Never deploy multiple honeypots with the same ID!

## Deployment Methods

### Using kubectl

1. Create namespace:

```bash
kubectl create namespace ipswamp
```

2. Create secret for API key and Honeypot ID:

```bash
# Replace with your IPSwamp Honeypot credentials
kubectl create secret generic ipswamp-secret \
  --from-literal=api-key=your_honeypot_api_key \
  --from-literal=honeypot-id=your_honeypot_id \
  -n ipswamp
```

3. Apply the deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ipswamp-honeypot
  namespace: ipswamp
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ipswamp-honeypot
  template:
    metadata:
      labels:
        app: ipswamp-honeypot
    spec:
      containers:
        - name: honeypot
          image: ghcr.io/haupt-pascal/ipswamp-honeypot:latest
          env:
            - name: API_KEY
              valueFrom:
                secretKeyRef:
                  name: ipswamp-secret
                  key: api-key
            - name: HONEYPOT_ID
              valueFrom:
                secretKeyRef:
                  name: ipswamp-secret
                  key: honeypot-id
          ports:
            - containerPort: 8080
            - containerPort: 2222
            - containerPort: 21
          resources:
            limits:
              cpu: "1"
              memory: "1Gi"
            requests:
              cpu: "200m"
              memory: "256Mi"
```

4. Apply service configuration:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: ipswamp-honeypot
  namespace: ipswamp
spec:
  type: LoadBalancer
  ports:
    - port: 8080
      targetPort: 8080
      name: http
    - port: 2222
      targetPort: 2222
      name: ssh
    - port: 21
      targetPort: 21
      name: ftp
  selector:
    app: ipswamp-honeypot
```

## Configuration

### Environment Variables

Configure using ConfigMap:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ipswamp-config
  namespace: ipswamp
data:
  # HONEYPOT_ID should be set via secret, not here!
  ENABLE_HTTP: "true"
  ENABLE_HTTPS: "true"
  ENABLE_SSH: "true"
  ENABLE_FTP: "true"
  ENABLE_MAIL: "true"
  ENABLE_MYSQL: "true"
```

## Monitoring

```bash
# View logs
kubectl logs -f deployment/ipswamp-honeypot -n ipswamp

# Check pod status
kubectl get pods -n ipswamp

# Describe deployment
kubectl describe deployment ipswamp-honeypot -n ipswamp
```

## Scaling

```bash
# Scale deployment
kubectl scale deployment ipswamp-honeypot --replicas=3 -n ipswamp
```

## Updating

```bash
# Update image
kubectl set image deployment/ipswamp-honeypot \
  honeypot=ghcr.io/haupt-pascal/ipswamp-honeypot:latest -n ipswamp
```

## Troubleshooting

### Pod Startup Issues

Check pod events:

```bash
kubectl describe pod -l app=ipswamp-honeypot -n ipswamp
```

### Network Issues

Verify service configuration:

```bash
kubectl get svc ipswamp-honeypot -n ipswamp
```
