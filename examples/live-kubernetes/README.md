# Live Kubernetes Example

This example demonstrates how to use the CEL Go Scanner with a **real Kubernetes cluster** to perform security compliance scanning using live API data.

## Features

- 🔗 **Real Kubernetes API**: Connects to actual clusters via kubeconfig
- 🛡️ **Security Rules**: Implements real-world security compliance checks
- 📊 **Live Data**: Fetches resources directly from the cluster API
- 🔍 **Comprehensive Scanning**: Multiple security checks across different resource types
- 📈 **Detailed Reporting**: Security assessment with recommendations

## Prerequisites

### 1. Kubernetes Cluster Access
You need access to a Kubernetes cluster with a valid kubeconfig file:

```bash
# Option 1: Default kubeconfig location
~/.kube/config

# Option 2: Custom location via environment variable
export KUBECONFIG=/path/to/your/kubeconfig

# Option 3: Verify cluster access
kubectl cluster-info
kubectl get nodes
```

### 2. Permissions
The example requires read permissions for the following resources:
- `pods` (core/v1)
- `namespaces` (core/v1)

Ensure your kubeconfig has appropriate RBAC permissions:
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cel-scanner-reader
rules:
- apiGroups: [""]
  resources: ["pods", "namespaces"]
  verbs: ["get", "list"]
```

## Security Rules Implemented

This example implements 4 real-world security compliance rules:

### 1. **Pod Security Context Check** (HIGH)
- **Rule**: All pods must have security context defined
- **CEL Expression**: `pods.items.all(pod, has(pod.spec.securityContext))`
- **Purpose**: Ensures pods run with explicit security settings

### 2. **Container Resource Limits Check** (MEDIUM)
- **Rule**: All containers must have CPU and memory limits
- **CEL Expression**: Complex expression checking `resources.limits.cpu` and `resources.limits.memory`
- **Purpose**: Prevents resource exhaustion attacks

### 3. **No Privileged Containers** (CRITICAL)
- **Rule**: No containers should run with privileged access
- **CEL Expression**: Checks for `securityContext.privileged == false`
- **Purpose**: Reduces attack surface and follows least privilege principle

### 4. **Service Account Usage** (MEDIUM)
- **Rule**: Pods should not use the default service account
- **CEL Expression**: Checks `serviceAccountName != "default"`
- **Purpose**: Ensures proper service account isolation

## Usage

### Basic Usage
```bash
cd examples/live-kubernetes
go run main.go
```

### With Debug Logging
```bash
DEBUG=true go run main.go
```

### Expected Output
```
CEL Go Scanner - Live Kubernetes Example
========================================

📝 Using kubeconfig: /home/user/.kube/config

1. Creating real-world security compliance rules:
   Created 4 security rules

2. Setting up live Kubernetes scanner:
   ✅ Scanner created with live Kubernetes connection

3. Testing connection - fetching namespaces:
   ✅ Successfully connected to Kubernetes cluster

4. Running comprehensive security scan on live cluster:

5. Security Scan Results:
========================

Rule 1: pod-security-context
  Status: FAIL
  ❌ NON-COMPLIANT

Rule 2: container-resource-limits
  Status: FAIL
  ❌ NON-COMPLIANT

Rule 3: privileged-containers
  Status: PASS
  ✅ COMPLIANT

Rule 4: service-account-check
  Status: FAIL
  ❌ NON-COMPLIANT

6. Security Assessment Summary:
==============================
  Total Rules: 4
  ✅ Compliant: 1
  ❌ Non-Compliant: 3
  🚨 Errors: 0

🔍 Recommendations:
  - Review non-compliant resources
  - Implement security contexts for all pods
  - Set resource limits on all containers
  - Avoid privileged containers
  - Use dedicated service accounts

⚠️  Security improvements needed: 1/4 rules passed

✅ Live Kubernetes security scan completed!
```

## Understanding Results

### Status Types
- **✅ PASS**: Rule is compliant - no issues found
- **❌ FAIL**: Rule is non-compliant - security issues detected
- **🚨 ERROR**: Technical error occurred during scanning

### Common Failures and Fixes

#### Pod Security Context Missing
```yaml
# ❌ Bad: No security context
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: nginx

# ✅ Good: With security context
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
  - name: app
    image: nginx
```

#### Missing Resource Limits
```yaml
# ❌ Bad: No resource limits
containers:
- name: app
  image: nginx

# ✅ Good: With resource limits
containers:
- name: app
  image: nginx
  resources:
    limits:
      cpu: 100m
      memory: 128Mi
    requests:
      cpu: 50m
      memory: 64Mi
```

#### Using Default Service Account
```yaml
# ❌ Bad: Default service account
apiVersion: v1
kind: Pod
spec:
  serviceAccountName: default  # or omitted

# ✅ Good: Dedicated service account
apiVersion: v1
kind: Pod
spec:
  serviceAccountName: my-app-sa
```

## Troubleshooting

### Connection Issues
```bash
# Check cluster connection
kubectl cluster-info

# Verify kubeconfig
kubectl config current-context
kubectl config view

# Test API access
kubectl auth can-i get pods
kubectl auth can-i list namespaces
```

### Permission Errors
```bash
# Check your permissions
kubectl auth can-i get pods --all-namespaces
kubectl auth can-i list pods --all-namespaces

# If using RBAC, apply reader role
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cel-scanner-binding
subjects:
- kind: User
  name: your-username
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
EOF
```

### No Kubeconfig Found
```bash
# Set KUBECONFIG environment variable
export KUBECONFIG=/path/to/your/kubeconfig

# Or copy to default location
mkdir -p ~/.kube
cp /path/to/your/kubeconfig ~/.kube/config
```

## Integration with CI/CD

This example can be integrated into CI/CD pipelines for automated security scanning:

```yaml
# GitHub Actions example
name: Kubernetes Security Scan
on: [push]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - uses: actions/setup-go@v3
      with:
        go-version: 1.23
    - name: Configure kubectl
      env:
        KUBECONFIG_DATA: ${{ secrets.KUBECONFIG }}
      run: |
        echo "$KUBECONFIG_DATA" | base64 -d > /tmp/kubeconfig
        export KUBECONFIG=/tmp/kubeconfig
    - name: Run Security Scan
      run: |
        cd examples/live-kubernetes
        go run main.go
```

## Extending the Example

### Adding Custom Rules
```go
customRule := celscanner.NewRuleBuilder("custom-security-check").
    WithKubernetesInput("deployments", "apps", "v1", "deployments", "", "").
    SetExpression("deployments.items.all(dep, dep.spec.replicas >= 2)").
    WithName("High Availability Check").
    WithDescription("Ensures deployments have multiple replicas").
    WithExtension("severity", "MEDIUM").
    Build()
```

### Adding Different Resource Types
```go
// Network policies
.WithKubernetesInput("netpols", "networking.k8s.io", "v1", "networkpolicies", "", "")

// Services
.WithKubernetesInput("services", "", "v1", "services", "", "")

// ConfigMaps
.WithKubernetesInput("configmaps", "", "v1", "configmaps", "", "")
```

## Next Steps

1. **Customize Rules**: Modify the security rules to match your organization's policies
2. **Add Namespaces**: Target specific namespaces for focused scanning
3. **Export Results**: Add JSON/YAML output for integration with other tools
4. **Scheduling**: Set up regular automated scans
5. **Alerting**: Integrate with monitoring systems for compliance violations

This example provides a solid foundation for building production-ready Kubernetes security scanning tools with CEL expressions. 