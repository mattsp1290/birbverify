"""Static all-writer policy for the bounded bare-Pod application profile."""

import json


def admission_objects(
    *,
    namespace: str,
    namespace_uid: str,
    node_name: str,
    pod_name: str,
    configmap_name: str,
    target_username: str,
) -> list[dict]:
    q = json.dumps
    prefix = f"birbverify-{namespace}"
    inventory = (
        f"request.userInfo.username == {q(target_username)} && "
        "request.resource.group == '' && "
        "(!has(request.subResource) || request.subResource == '') && ("
        f"(request.resource.resource == 'configmaps' && request.name == {q(configmap_name)} "
        "&& request.operation == 'UPDATE') || "
        f"(request.resource.resource == 'pods' && request.name == {q(pod_name)} "
        "&& request.operation in ['CREATE', 'UPDATE', 'DELETE']))"
    )
    status = (
        f"request.userInfo.username == {q('system:node:' + node_name)} && "
        "request.resource.group == '' && request.resource.resource == 'pods' && "
        f"request.name == {q(pod_name)} && "
        "(has(request.subResource) && request.subResource == 'status') && "
        "request.operation == 'UPDATE'"
    )
    pod_shape = (
        "request.resource.resource != 'pods' || request.operation == 'DELETE' || "
        "(has(request.subResource) && request.subResource == 'status') || ("
        f"object.spec.nodeName == {q(node_name)} && "
        "object.spec.automountServiceAccountToken == false && "
        "object.spec.restartPolicy == 'Never' && "
        "(!has(object.spec.hostNetwork) || object.spec.hostNetwork == false) && "
        "(!has(object.spec.hostPID) || object.spec.hostPID == false) && "
        "(!has(object.spec.hostIPC) || object.spec.hostIPC == false) && "
        "!has(object.spec.volumes) && !has(object.spec.initContainers) && "
        "!has(object.spec.ephemeralContainers) && "
        "(!has(object.spec.securityContext) || "
        "(!has(object.spec.securityContext.sysctls) && "
        "(!has(object.spec.securityContext.seccompProfile) || "
        "object.spec.securityContext.seccompProfile.type != 'Unconfined') && "
        "(!has(object.spec.securityContext.appArmorProfile) || "
        "object.spec.securityContext.appArmorProfile.type != 'Unconfined'))) && "
        "object.spec.containers.size() == 1 && "
        "object.spec.containers.all(c, "
        "c.image.matches('^.+@sha256:[0-9a-f]{64}$') && "
        "has(c.securityContext) && c.securityContext.allowPrivilegeEscalation == false && "
        "(!has(c.securityContext.privileged) || c.securityContext.privileged == false) && "
        "c.securityContext.capabilities.drop == ['ALL'] && "
        "(!has(c.securityContext.capabilities.add) || "
        "c.securityContext.capabilities.add.size() == 0) && "
        "(!has(c.ports) || c.ports.all(p, !has(p.hostPort) || p.hostPort == 0)) && "
        "(!has(c.securityContext.procMount) || c.securityContext.procMount != 'Unmasked') && "
        "(!has(c.securityContext.seccompProfile) || "
        "c.securityContext.seccompProfile.type != 'Unconfined') && "
        "(!has(c.securityContext.appArmorProfile) || "
        "c.securityContext.appArmorProfile.type != 'Unconfined')))"
    )
    namespace_policy = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": prefix},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {
                "resourceRules": [
                    {
                        "apiGroups": ["*"],
                        "apiVersions": ["*"],
                        "operations": ["*"],
                        "resources": ["*/*"],
                        "scope": "Namespaced",
                    }
                ]
            },
            "matchConditions": [
                {"name": "owned-namespace", "expression": f"request.namespace == {q(namespace)}"}
            ],
            "validations": [
                {
                    "expression": (
                        "has(namespaceObject.metadata.annotations) && "
                        "namespaceObject.metadata.annotations['birbverify.dev/namespace-uid'] == "
                        f"{q(namespace_uid)}"
                    ),
                    "message": "birbverify namespace UID mismatch",
                },
                {
                    "expression": f"({inventory}) || ({status})",
                    "message": "birbverify writer or object outside inventory",
                },
                {"expression": pod_shape, "message": "birbverify unsafe pod shape"},
            ],
        },
    }
    namespace_guard = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": prefix + "-identity"},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {
                "resourceRules": [
                    {
                        "apiGroups": [""],
                        "apiVersions": ["v1"],
                        "operations": ["CREATE", "UPDATE", "DELETE"],
                        "resources": ["namespaces", "namespaces/*"],
                        "scope": "Cluster",
                    }
                ]
            },
            "matchConditions": [
                {"name": "owned-namespace", "expression": f"request.name == {q(namespace)}"}
            ],
            "validations": [
                {"expression": "false", "message": "birbverify namespace identity is pinned"}
            ],
        },
    }
    result = []
    for policy in (namespace_policy, namespace_guard):
        result.append(policy)
        result.append(
            {
                "apiVersion": "admissionregistration.k8s.io/v1",
                "kind": "ValidatingAdmissionPolicyBinding",
                "metadata": {"name": policy["metadata"]["name"]},
                "spec": {"policyName": policy["metadata"]["name"], "validationActions": ["Deny"]},
            }
        )
    return result


def target_role(namespace: str, pod_name: str, configmap_name: str) -> dict:
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": "birbverify-target", "namespace": namespace},
        "rules": [
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]},
            {
                "apiGroups": [""],
                "resources": ["pods"],
                "resourceNames": [pod_name],
                "verbs": ["get", "update", "delete"],
            },
            {
                "apiGroups": [""],
                "resources": ["configmaps"],
                "resourceNames": [configmap_name],
                "verbs": ["get", "update"],
            },
        ],
    }
