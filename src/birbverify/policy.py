from birbverify.contract import Request

CAPABILITIES = ("linux-docker",)


def authorize(request: Request, installation: dict):
    authority = request.authority
    if (
        not installation.get("fixture_mode")
        or len(request.plan.checks) != 1
        or authority.principal != "fixture-owner"
        or authority.workflow != "forge-fixture"
        or authority.policy_revision != installation["policy_revision"]
        or authority.environment != "fixture-local"
        or set(authority.permitted_operations) != {"fixture.apply", "fixture.reset"}
        or not set(request.resources.capabilities).issubset(CAPABILITIES)
        or request.candidate.repository != "fixture"
        or request.candidate.kind != "head"
        or request.candidate.artifact_sha256 is not None
        or request.plan_sha256 != installation["plan_sha256"]
        or request.components != ("fixture-counter",)
    ):
        raise ValueError("installation_denied")
