"""The API-Gateway-over-Function-URL rationale is stated security-first.

Issue #3475: the artifact-deploy docs argued the M2 backend shape backwards --
as if API Gateway were chosen *so that* a corporate account's automated
guardrails would not fire. The actual reason is the security property itself: a
Function URL needs a ``Principal:"*"`` resource policy, so the Lambda becomes
world-accessible, while an API Gateway HTTP API keeps the function's policy
scoped to ``apigateway.amazonaws.com``. Guardrail behaviour is a downstream
consequence of that property, not the goal.

These are prose ratchets. They fail if any surface reintroduces the
guardrail-as-goal framing, or drops the property that makes the shape correct on
its own merits.
"""

import re
from pathlib import Path

_DEPLOY = Path(__file__).parent.parent / "src" / "kiro_crew" / "deploy"
_SKILL = _DEPLOY / "skills" / "artifact-deploy"

SKILL_MD = _SKILL / "SKILL.md"
APIGW_TEMPLATE = _SKILL / "templates" / "app-apigw.yaml"
APIGW_DDB_TEMPLATE = _SKILL / "templates" / "app-apigw-ddb.yaml"
DEPLOY_BACKEND_SH = _SKILL / "scripts" / "deploy-backend.sh"
ATTACH_BACKEND_PY = _SKILL / "scripts" / "attach_backend.py"
DEPLOY_WEB_DOC = (
    Path(__file__).parent.parent / "src" / "kiro_crew" / "docs" / "deploy-web.md"
)

#: Every surface that explains why the backend sits behind API Gateway. A new
#: one must be added here, so the framing is pinned everywhere it is stated.
RATIONALE_SURFACES = (
    SKILL_MD,
    APIGW_TEMPLATE,
    APIGW_DDB_TEMPLATE,
    DEPLOY_BACKEND_SH,
    ATTACH_BACKEND_PY,
    DEPLOY_WEB_DOC,
)

#: Phrasings that make "a guardrail does not fire" the purpose of the choice.
#: "Guardrail-safe" is included because as a standalone label it names the
#: account-policy outcome as the property being claimed.
GUARDRAIL_AS_GOAL = (
    re.compile(r"guardrail[- ]safe", re.IGNORECASE),
    re.compile(r"auto[- ]mitigat", re.IGNORECASE),
    re.compile(r"(?:so|thus)\b[^.]{0,80}\bdetector\b[^.]{0,40}\bfires?\b", re.I),
    re.compile(r"\bno\b[^.]{0,40}\b(?:mitigation|detector)\b[^.]{0,20}\bfires?\b", re.I),
)


class TestRationaleIsNotGuardrailEvasion:
    """No surface presents guardrail behaviour as the reason for the design."""

    def test_no_surface_frames_guardrails_as_the_goal(self):
        offenders = []
        for path in RATIONALE_SURFACES:
            text = path.read_text(encoding="utf-8")
            for pattern in GUARDRAIL_AS_GOAL:
                match = pattern.search(text)
                if match:
                    offenders.append(f"{path.name}: {match.group(0)!r}")
        assert not offenders, (
            "guardrail-as-goal framing found (issue #3475): "
            + "; ".join(offenders)
            + " -- state the security property (Function URL needs "
            'Principal:"*"; API Gateway keeps the Lambda policy scoped) and let '
            "guardrail compatibility be the consequence."
        )


class TestRationaleStatesTheSecurityProperty:
    """The surfaces that argue the choice name the property that justifies it."""

    def test_skill_md_names_principal_star_and_the_scoped_policy(self):
        text = SKILL_MD.read_text(encoding="utf-8")
        assert 'Principal:"*"' in text or "Principal: *" in text, (
            "SKILL.md must say a Function URL requires a world-accessible "
            'Principal:"*" resource policy'
        )
        assert "apigateway.amazonaws.com" in text, (
            "SKILL.md must say the Lambda's policy is scoped to API Gateway"
        )
        assert "app-lambda.yaml" in text, (
            "SKILL.md must keep documenting the Function URL variant as the "
            "lighter option for unrestricted accounts"
        )

    def test_deploy_web_doc_names_principal_star_and_the_scoped_policy(self):
        text = DEPLOY_WEB_DOC.read_text(encoding="utf-8")
        assert 'Principal:"*"' in text or "Principal: *" in text
        assert "apigateway.amazonaws.com" in text

    def test_templates_state_the_invoke_scope(self):
        for path in (APIGW_TEMPLATE, APIGW_DDB_TEMPLATE):
            text = path.read_text(encoding="utf-8")
            assert "world-accessible" in text, (
                f"{path.name} must still say the Lambda is not world-accessible"
            )
            assert "apigateway.amazonaws.com" in text, (
                f"{path.name} must scope the invoke permission to API Gateway"
            )
