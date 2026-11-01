"""Approved Email Template Registry and Safe Rendering Engine.

Enforces strict schema validation for each template and prevents HTML/script injection
and header injection through mandatory character escaping and sanitization.
"""

import html
import re
from typing import Any, Callable, Dict, List, Tuple, Type
from pydantic import BaseModel, ValidationError
from app.integrations.email.schemas import (
    EmailTemplateId,
    EmailTemplateInfo,
    IncidentNotificationParams,
    SecurityAlertParams,
    TestDeliveryParams,
)


def _sanitize_header_value(value: str) -> str:
    """Removes CR and LF characters to prevent email header injection."""
    return re.sub(r"[\r\n]+", " ", str(value)).strip()


class ApprovedTemplate:
    """Encapsulates template metadata, schema validation, and safe HTML rendering."""

    def __init__(
        self,
        template_id: EmailTemplateId,
        name: str,
        description: str,
        param_model: Type[BaseModel],
        render_fn: Callable[[BaseModel], Tuple[str, str, str]],
    ) -> None:
        self.template_id = template_id
        self.name = name
        self.description = description
        self.param_model = param_model
        self.render_fn = render_fn

    def validate_variables(self, variables: Dict[str, Any]) -> BaseModel:
        """Validates provided variables against the template's strict Pydantic model."""
        return self.param_model.model_validate(variables)

    def render(self, validated_params: BaseModel) -> Tuple[str, str, str]:
        """Renders (subject, html_content, plain_text) safely."""
        subject, html_content, plain_text = self.render_fn(validated_params)
        return _sanitize_header_value(subject), html_content, plain_text

    def to_info(self) -> EmailTemplateInfo:
        """Serializes template specification for catalog discovery."""
        schema = self.param_model.model_json_schema()
        required = schema.get("required", [])
        return EmailTemplateInfo(
            template_id=self.template_id.value,
            name=self.name,
            description=self.description,
            required_variables=required,
            variable_schema=schema.get("properties", {}),
        )


# ==============================================================================
# Approved Render Functions with Mandatory Escaping
# ==============================================================================


def _render_security_alert(params: SecurityAlertParams) -> Tuple[str, str, str]:
    severity = html.escape(params.severity.upper())
    title = html.escape(params.alert_title)
    summary = html.escape(params.summary)
    timestamp = html.escape(params.timestamp or "N/A")

    indicators_html = "".join(f"<li><code>{html.escape(ind)}</code></li>" for ind in params.indicators)
    indicators_text = ", ".join(params.indicators) if params.indicators else "None"

    subject = f"[SECURITY ALERT - {params.severity.upper()}] {params.alert_title}"

    html_content = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><style>body{{font-family:sans-serif;line-height:1.5;color:#1e293b;}} .banner{{background:#dc2626;color:#fff;padding:12px;border-radius:6px;}} .badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-weight:bold;background:#fee2e2;color:#991b1b;}}</style></head>
<body>
<div class="banner"><h2>AegisMesh Security Alert</h2></div>
<p><span class="badge">SEVERITY: {severity}</span></p>
<h3>{title}</h3>
<p>{summary}</p>
<h4>Observed Indicators:</h4>
<ul>{indicators_html or '<li>None</li>'}</ul>
<p><small>Timestamp: {timestamp} | AegisMesh Autonomous Security Platform</small></p>
</body>
</html>"""

    plain_text = f"""[SECURITY ALERT - {params.severity.upper()}]
Title: {params.alert_title}
Summary: {params.summary}
Indicators: {indicators_text}
Timestamp: {params.timestamp or 'N/A'}
--
AegisMesh Autonomous Security Platform"""

    return subject, html_content, plain_text


def _render_incident_notification(params: IncidentNotificationParams) -> Tuple[str, str, str]:
    incident_id = html.escape(params.incident_id)
    severity = html.escape(params.severity.upper())
    title = html.escape(params.title)
    description = html.escape(params.description)

    assets_html = "".join(f"<li><code>{html.escape(asset)}</code></li>" for asset in params.affected_assets)
    assets_text = ", ".join(params.affected_assets) if params.affected_assets else "None"

    subject = f"[INCIDENT NOTIFICATION {params.incident_id}] {params.title}"

    html_content = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><style>body{{font-family:sans-serif;line-height:1.5;color:#1e293b;}} .banner{{background:#ea580c;color:#fff;padding:12px;border-radius:6px;}}</style></head>
<body>
<div class="banner"><h2>AegisMesh Incident Notification: {incident_id}</h2></div>
<p><strong>Severity:</strong> {severity}</p>
<h3>{title}</h3>
<p>{description}</p>
<h4>Affected Assets:</h4>
<ul>{assets_html or '<li>None</li>'}</ul>
<p><small>AegisMesh Autonomous Security Operations</small></p>
</body>
</html>"""

    plain_text = f"""[INCIDENT NOTIFICATION: {params.incident_id}]
Severity: {params.severity.upper()}
Title: {params.title}
Description: {params.description}
Affected Assets: {assets_text}
--
AegisMesh Autonomous Security Operations"""

    return subject, html_content, plain_text


def _render_test_delivery(params: TestDeliveryParams) -> Tuple[str, str, str]:
    test_id = html.escape(params.test_id)
    message = html.escape(params.message)
    initiated_by = html.escape(params.initiated_by)

    subject = f"[AEGISMESH VERIFICATION] Test Email Delivery ({params.test_id})"

    html_content = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><style>body{{font-family:sans-serif;line-height:1.5;color:#1e293b;}} .card{{border:1px solid #0284c7;border-radius:6px;padding:16px;}}</style></head>
<body>
<div class="card">
<h3>AegisMesh Test Email Gateway Probe</h3>
<p><strong>Test ID:</strong> <code>{test_id}</code></p>
<p><strong>Message:</strong> {message}</p>
<p><strong>Initiated By:</strong> {initiated_by}</p>
<hr>
<p><small>Environment: Test Mode | No production delivery executed.</small></p>
</div>
</body>
</html>"""

    plain_text = f"""[AEGISMESH VERIFICATION: Test Email Delivery]
Test ID: {params.test_id}
Message: {params.message}
Initiated By: {params.initiated_by}
Environment: Test Mode (Simulation Boundary)
--
AegisMesh Integration Platform"""

    return subject, html_content, plain_text


# ==============================================================================
# Template Registry Catalog
# ==============================================================================


class ApprovedTemplateRegistry:
    """Central registry of strictly approved transactional security templates."""

    def __init__(self) -> None:
        self._templates: Dict[EmailTemplateId, ApprovedTemplate] = {
            EmailTemplateId.SECURITY_ALERT: ApprovedTemplate(
                template_id=EmailTemplateId.SECURITY_ALERT,
                name="Security Alert Notification",
                description="High-priority alert notification for detected threats, suspicious activity, and policy breaches.",
                param_model=SecurityAlertParams,
                render_fn=_render_security_alert,
            ),
            EmailTemplateId.INCIDENT_NOTIFICATION: ApprovedTemplate(
                template_id=EmailTemplateId.INCIDENT_NOTIFICATION,
                name="Incident Briefing",
                description="Formal notification and scoping brief for confirmed security incidents.",
                param_model=IncidentNotificationParams,
                render_fn=_render_incident_notification,
            ),
            EmailTemplateId.TEST_DELIVERY: ApprovedTemplate(
                template_id=EmailTemplateId.TEST_DELIVERY,
                name="Gateway Test Delivery Probe",
                description="Controlled test delivery verification probe to confirm gateway connectivity.",
                param_model=TestDeliveryParams,
                render_fn=_render_test_delivery,
            ),
        }

    def get_template(self, template_id: EmailTemplateId) -> ApprovedTemplate:
        """Retrieves template by ID or raises KeyError."""
        if template_id not in self._templates:
            raise KeyError(f"Template '{template_id}' is not in approved registry")
        return self._templates[template_id]

    def list_templates(self) -> List[EmailTemplateInfo]:
        """Returns catalog of all registered template descriptions."""
        return [t.to_info() for t in self._templates.values()]


template_registry = ApprovedTemplateRegistry()
