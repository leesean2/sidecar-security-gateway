# Sidecar API Security Gateway (Kubernetes Prototype)

This repository contains a complete Kubernetes-based prototype of a **Sidecar API Security Gateway** featuring:
1. **Envoy Proxy**: Sidecar interceptor routing inbound API calls.
2. **Open Policy Agent (OPA)**: Sidecar rule engine performing real-time stateless authorization (JWT validation, Rate Limit enforcement, and IP blacklist checks).
3. **Target Microservice**: FastAPI e-commerce backend mock.
4. **Log Forwarder**: Tailer sending Envoy logs asynchronously to the Control Plane.
5. **Control Plane**: FastAPI management engine checking log sequences for L7 anomalies (Workflow sequence violations) and dynamically updating OPA policy bundles.
6. **Redis**: In-memory session state store for behavior tracking.

---

## Directory Structure
```text
/sidecar-security-gateway
├── apps/
│   └── target-app/          # Target microservice app & Dockerfile
├── control-plane/           # Policy bundles, Redis registry, anomaly engine
├── envoy/                   # Envoy static proxy settings
├── opa/                     # OPA configuration settings
├── log-forwarder/           # Tail script to ship Envoy logs to Control Plane
├── k8s/                     # Kubernetes Deployment and Service manifests
│   ├── envoy-config.yaml
│   ├── opa-config.yaml
│   ├── redis.yaml
│   ├── control-plane.yaml
│   └── target-service-pod.yaml
├── verify.py                # Python test suite simulating normal & malicious clients
└── README.md                # Setup and execution guide
```

---

## Prerequisites
- Docker installed
- A local Kubernetes cluster (`minikube`, `kind`, or `Docker Desktop K8s`)
- `kubectl` CLI installed
- Python 3.x with `requests` library installed (`pip install requests`)

---

## Setup & Deployment Guide

### Step 1: Build Docker Images
We need to build our custom Docker images and make them available to your local Kubernetes cluster.

#### If using Minikube:
```bash
# Point your shell to Minikube's docker daemon
minikube docker-env | Invoke-Expression   # PowerShell
# or: eval $(minikube -p minikube docker-env) # Linux/macOS

# Build target microservice
docker build -t target-app:latest ./apps/target-app

# Build control plane
docker build -t control-plane:latest ./control-plane

# Build log forwarder
docker build -t log-forwarder:latest ./log-forwarder
```

#### If using Kind:
```bash
# Build images locally
docker build -t target-app:latest ./apps/target-app
docker build -t control-plane:latest ./control-plane
docker build -t log-forwarder:latest ./log-forwarder

# Load them into Kind
kind load docker-image target-app:latest
kind load docker-image control-plane:latest
kind load docker-image log-forwarder:latest
```

---

### Step 2: Apply ConfigMaps
Create the configurations for Envoy and OPA inside the cluster:
```bash
kubectl apply -f ./k8s/envoy-config.yaml
kubectl apply -f ./k8s/opa-config.yaml
```

---

### Step 3: Deploy Services
Deploy Redis, the Control Plane, and the Target App (which houses the Envoy, OPA, and Log Forwarder sidecars):
```bash
# Deploy Redis
kubectl apply -f ./k8s/redis.yaml

# Deploy Control Plane
kubectl apply -f ./k8s/control-plane.yaml

# Deploy Target App + Sidecars
kubectl apply -f ./k8s/target-service-pod.yaml
```

Check the status of your pods. Wait until all pods are `Running`:
```bash
kubectl get pods
```

---

### Step 4: Access the Gateway
The Envoy proxy inside the target pod is exposed through a service named `gateway-service` on port `8000`.

#### Option A: Port Forwarding (Recommended & Universal)
Run this command in a separate terminal to forward your local port `8000` directly to the gateway service:
```bash
kubectl port-forward svc/gateway-service 8000:8000
```
*(If you port-forward, access the gateway at `http://localhost:8000`)*

#### Option B: Minikube NodePort
If you are using Minikube, you can expose the NodePort service:
```bash
minikube service gateway-service --url
```
*(Note the URL returned by Minikube, e.g., `http://192.168.49.2:30080`)*

---

## Running Verification Tests

Run the test suite script to trigger various access scenarios (normal paths, token-less bypasses, rate limit flooding, and sequential workflow violations):

```bash
# If using Port Forwarding (http://localhost:8000)
python verify.py http://localhost:8000

# If using Minikube NodePort URL
python verify.py <Minikube_URL>
```

### Expected Output
The script simulates different client IPs via `X-Forwarded-For` and will show:
- Public endpoints (`/`, `/products`) accessible to everyone.
- Direct checkout without a JWT blocked immediately on Envoy (inline).
- Valid checkout with JWT and normal sequence (Home -> Products -> Cart -> Checkout) allowed.
- IP rate limit exceeded client blacklisted and blocked.
- Bot client blacklisted for executing direct checkout (skipping preceding steps) after 2 occurrences.
