# Namespace and admission configuration guard

Birbhomes can install this guard on a Kubernetes v1.33.1 API server before admitting a deployment request. It freezes the target Namespace, the ownership ValidatingWebhookConfiguration and the reviewed MutatingWebhookConfigurations. A later mutating webhook must exclude the target namespace by its Kubernetes-provided name label and limit every rule to namespaced resources. Another namespace can continue creating workloads.

## Installation inputs

Use one explicit kubeconfig and context. The operator must have exclusive control of namespace and admission configuration changes throughout bootstrap. Start with an active target namespace, its reviewed ownership webhook installed, no outstanding configuration writes, and all workload writers held. Verify that the ownership webhook covers the intended writes and fails closed. The guard pins the supplied webhook configuration's UID and content.

The installer requires complete API discovery and list access. The guard refuses a served MutatingAdmissionPolicy API. Every installed mutating webhook must have a namespace selector that excludes the target's pinned labels. Every rule must explicitly use the Namespaced scope. A namespace selector alone cannot exclude cluster-scoped writes. This strict profile also rejects existing cluster-scoped mutators whose current rules happen to be disjoint.

## Install the guard

1. Run the read-only inventory command below. Review the cluster UID, namespace UID and label digest, and every webhook configuration UID and digest against the operator's installation record. Record the approved inventory digest.

   ```sh
   python -m birbverify.deployment_guard inspect \
     --kubeconfig "$config" --context "$context" \
     --namespace "$target" --validator "$ownership_configuration" > inventory.json
   ```

2. Render with the same four arguments and the reviewed digest. Apply the resulting six objects with the operator's bootstrap authority.

   ```sh
   python -m birbverify.deployment_guard render \
     --kubeconfig "$config" --context "$context" \
     --namespace "$target" --validator "$ownership_configuration" \
     --expected-sha256 "$approved_digest" > guard.json
   kubectl --kubeconfig "$config" --context "$context" create -f guard.json
   ```

3. Run `verify-install` with the same arguments and approved digest. It compares the stored policy and binding specs, waits for the installer to retry pending type checks, and rereads the complete original inventory. It sends three server-side dry-run writes to check for denials attributable to the installed policies. Retain the returned policy and binding UIDs and spec digests with the installation record. Keep the installation held on any error. The disposable proof covers one API server. A load-balanced context alone cannot establish propagation to every API server in a multi-server installation.

The namespace guard covers CREATE, UPDATE and DELETE on the namespace and its subresources, including finalize. The validator guard freezes the named ownership configuration. The mutator guard freezes existing mutator identities and permits later configurations with the explicit exclusion `kubernetes.io/metadata.name NotIn [target]` on each webhook. It checks later updates and permits deletion of a newly added disjoint configuration. The initial inventory verifier requires the exact reviewed baseline. A new disjoint mutator therefore requires a separate installation review to establish a new baseline.

## Trust and limits

Kubernetes excludes its validating and mutating admission policy and binding resources from dynamic policy evaluation. Restrict their management, RBAC escalation, impersonation, API-server configuration and backing storage to the trusted operator. Hold candidate transitions and control-plane upgrades until requalification. Keep controller identity, storage restoration and workload termination checks in the ownership lifecycle. These guards issue no release receipt. [Kubernetes v1.33 policy implementation](https://github.com/kubernetes/apiserver/blob/v0.33.1/pkg/admission/plugin/policy/generic/plugin.go)

Run `scripts/verify-deployment-guard` with kind, kubectl, uv and Docker on Linux. It creates a new single-server cluster, installs three deny policies, exercises updates, reads back the original pins and records a receipt in the cluster's private directory under `.proof`. The test admits a disjoint mutator, denies drift into the target and writes ConfigMaps inside and outside the target. It removes its own cluster.
