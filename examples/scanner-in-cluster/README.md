# In-Cluster Security Scanner Example

When the CEL scanner runs inside an OpenShift container, there are much better approaches than using `kubectl exec` to check file permissions and security configurations. This example demonstrates container-native security scanning techniques.

## Why Avoid `kubectl exec`?

Using `kubectl exec` from within a container has several drawbacks:
- **Performance**: Heavy overhead for each command execution
- **Security**: Requires elevated RBAC permissions
- **Scalability**: Doesn't scale well across many containers
- **Resource Usage**: Consumes significant cluster resources
- **Reliability**: Depends on network connectivity and target container availability

## Better Approaches

### 🎯 **Approach 1: Volume-Based Scanning**
Mount shared volumes to directly access filesystem data without exec.

```yaml
# Deployment with shared volume
volumeMounts:
  - name: shared-config
    mountPath: /shared/app-config
    readOnly: true
  - name: shared-data
    mountPath: /shared/app-data
    readOnly: true
```

**Advantages:**
- ✅ Direct filesystem access
- ✅ No network overhead
- ✅ Real-time file monitoring
- ✅ No additional RBAC permissions needed

### 🎯 **Approach 2: Kubernetes API-Based Scanning**
Use Kubernetes APIs to check pod security contexts and configurations.

```go
// Check security contexts via API
rule := celscanner.NewRuleBuilder("pod-security").
    WithKubernetesInput("pods", "", "v1", "pods", "", "").
    SetExpression(`
        pods.items.all(pod, 
            has(pod.spec.securityContext.runAsNonRoot) &&
            pod.spec.securityContext.runAsNonRoot == true
        )
    `).Build()
```

**Advantages:**
- ✅ No container access needed
- ✅ Cluster-wide visibility
- ✅ Declarative security policies
- ✅ Policy as code

### 🎯 **Approach 3: Pod Security Standards**
Leverage built-in Kubernetes Pod Security Standards.

```go
// Enforce Pod Security Standards
rule := celscanner.NewRuleBuilder("pss-baseline").
    WithKubernetesInput("pods", "", "v1", "pods", "", "").
    SetExpression(`
        pods.items.all(pod,
            pod.spec.containers.all(container,
                !has(container.securityContext.privileged) ||
                container.securityContext.privileged == false
            )
        )
    `).Build()
```

**Standards:**
- **Privileged**: Unrestricted (not recommended)
- **Baseline**: Minimally restrictive, prevents privilege escalation
- **Restricted**: Heavily restricted, follows pod hardening best practices

### 🎯 **Approach 4: Security Context Constraints (OpenShift)**
Use OpenShift's Security Context Constraints for enhanced security.

```go
// Check SCC compliance
rule := celscanner.NewRuleBuilder("scc-check").
    WithKubernetesInput("pods", "", "v1", "pods", "", "").
    SetExpression(`
        pods.items.all(pod,
            pod.metadata.annotations["openshift.io/scc"] == "restricted"
        )
    `).Build()
```

**OpenShift SCCs:**
- `restricted`: Most secure, runs as non-root
- `anyuid`: Allows any user ID
- `privileged`: Full host access (avoid in production)

### 🎯 **Approach 5: Host Filesystem Access (Privileged)**
For deep security scanning with elevated privileges.

```yaml
# Privileged scanner with host access
securityContext:
  privileged: true
volumeMounts:
  - name: host-root
    mountPath: /host
    readOnly: true
volumes:
  - name: host-root
    hostPath:
      path: /
```

**Use Cases:**
- Host security auditing
- Container runtime inspection
- Kernel security checks
- Compliance scanning

### 🎯 **Approach 6: RBAC and ServiceAccount Validation**
Validate cluster-level security configurations.

```go
// Check RBAC policies
rule := celscanner.NewRuleBuilder("rbac-check").
    WithKubernetesInput("clusterrolebindings", "rbac.authorization.k8s.io", "v1", "clusterrolebindings", "", "").
    SetExpression(`
        clusterrolebindings.items.all(binding,
            binding.roleRef.name != "cluster-admin"
        )
    `).Build()
```

## Deployment Patterns

### 1. **Sidecar Scanner**
Deploy the scanner as a sidecar container sharing volumes.

```yaml
# Pod with sidecar scanner
spec:
  containers:
  - name: app
    image: my-app:latest
    volumeMounts:
    - name: shared-data
      mountPath: /app/data
  - name: security-scanner
    image: cel-scanner:latest
    volumeMounts:
    - name: shared-data
      mountPath: /shared/data
      readOnly: true
```

### 2. **DaemonSet Scanner**
Deploy on every node for host-level scanning.

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: security-scanner
spec:
  template:
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: scanner
        image: cel-scanner:latest
        securityContext:
          privileged: true
```

### 3. **CronJob Scanner**
Periodic security audits across the cluster.

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: security-audit
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: scanner
            image: cel-scanner:latest
```

### 4. **Operator Pattern**
Custom operator for automated security scanning.

```yaml
apiVersion: security.example.com/v1
kind: SecurityScan
metadata:
  name: cluster-security-scan
spec:
  schedule: "*/15 * * * *"
  policies:
  - podSecurityStandards
  - networkPolicies
  - rbacValidation
```

## Security Configurations

### Minimal RBAC (API-based scanning)
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: security-scanner
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps", "secrets"]
  verbs: ["get", "list"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
  verbs: ["get", "list"]
```

### Privileged RBAC (Host scanning)
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: privileged-scanner
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["get", "list"]
- apiGroups: ["security.openshift.io"]
  resources: ["securitycontextconstraints"]
  verbs: ["get", "list"]
```

### OpenShift SCC for Scanner
```yaml
apiVersion: security.openshift.io/v1
kind: SecurityContextConstraints
metadata:
  name: security-scanner-scc
allowHostDirVolumePlugin: true
allowHostNetwork: true
allowHostPID: true
allowPrivilegedContainer: true
allowedCapabilities:
- '*'
runAsUser:
  type: RunAsAny
seLinuxContext:
  type: RunAsAny
```

## Integration Examples

### 1. **GitOps Integration**
```yaml
# ArgoCD Application
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: security-scanner
spec:
  source:
    path: manifests/security-scanner
    targetRevision: main
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

### 2. **Tekton Pipeline**
```yaml
apiVersion: tekton.dev/v1beta1
kind: Task
metadata:
  name: security-scan
spec:
  steps:
  - name: scan
    image: cel-scanner:latest
    script: |
      #!/bin/bash
      /app/scanner --config=/config/scan-config.yaml
```

### 3. **Prometheus Monitoring**
```go
// Export metrics for monitoring
scanner.RegisterMetrics(prometheus.DefaultRegisterer)
http.Handle("/metrics", promhttp.Handler())
```

## Performance Comparison

| Approach | CPU Usage | Memory Usage | Network I/O | Scalability |
|----------|-----------|--------------|-------------|-------------|
| `kubectl exec` | High | High | Very High | Poor |
| Volume Mount | Low | Low | None | Excellent |
| Kubernetes API | Medium | Low | Low | Good |
| Host Mount | Low | Medium | None | Good |
| Sidecar | Low | Medium | None | Excellent |

## Security Best Practices

### 1. **Principle of Least Privilege**
- Use minimal RBAC permissions
- Avoid `cluster-admin` role
- Limit volume mounts to necessary paths

### 2. **Network Policies**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: scanner-network-policy
spec:
  podSelector:
    matchLabels:
      app: security-scanner
  policyTypes:
  - Ingress
  - Egress
  egress:
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 443  # Kubernetes API only
```

### 3. **Pod Security Context**
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  fsGroup: 1000
  seccompProfile:
    type: RuntimeDefault
  capabilities:
    drop:
    - ALL
```

### 4. **Resource Limits**
```yaml
resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

## Troubleshooting

### Common Issues

1. **RBAC Permission Denied**
   ```bash
   kubectl auth can-i get pods --as=system:serviceaccount:default:scanner
   ```

2. **Volume Mount Issues**
   ```bash
   kubectl describe pod scanner-pod
   kubectl logs scanner-pod -c scanner
   ```

3. **OpenShift SCC Problems**
   ```bash
   oc describe scc restricted
   oc get pod -o yaml | grep scc
   ```

## Next Steps

- Deploy the scanner using the provided manifests
- Customize security policies for your environment
- Integrate with your CI/CD pipeline
- Set up monitoring and alerting
- Consider using security operators like Falco or OPA Gatekeeper 