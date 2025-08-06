# Create a dummy network policy for all namespaces
echo "Creating dummy network policy for all namespaces"
for namespace in $(oc get namespaces -o jsonpath='{.items[*].metadata.name}'); do
    # skip if namespace is openshift- or kube-
    if [[ $namespace == openshift-* || $namespace == kube-* ]]; then
        continue
    fi
    echo "Creating network policy for namespace: $namespace"
    oc apply -f empty-np.yaml --namespace=$namespace
done