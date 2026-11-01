package aegis

import rego.v1

# Default deny
default allow := false
default reason := "Default deny: action not permitted by policy."

# Policy metadata
policy_version := "1.0.0"

# Main decision object returned by the policy
decision := {
    "allowed": allow,
    "decision": decision_type,
    "reason": selected_reason,
    "policy_version": policy_version,
}

decision_type := "allow" if {
    allow
} else := "deny"

reasons := [r | r := deny_reasons[_]]

selected_reason := "Authorized by policy." if {
    allow
} else := reasons[0] if {
    count(reasons) > 0
} else := reason

# Collect specific deny reasons
deny_reasons contains "Authentication required." if {
    not input.subject.is_authenticated
}

deny_reasons contains "Attack execution prohibited outside sandbox environment." if {
    input.action.operation == "attack.execute"
    input.resource.environment != "sandbox"
}

deny_reasons contains "Human approval required for remediation execution." if {
    input.action.operation == "remediation.execute"
    input.context.approval_status != "approved"
}

deny_reasons contains "Admin role required for policy modifications." if {
    input.action.operation == "policy.modify"
    input.subject.role != "admin"
}

deny_reasons contains "Human approval required for policy modifications." if {
    input.action.operation == "policy.modify"
    input.context.approval_status != "approved"
}

deny_reasons contains "Admin role required for administrative operations." if {
    input.action.capability == "admin"
    input.subject.role != "admin"
}

deny_reasons contains "Unauthorized external target access prohibited." if {
    input.resource.type == "external_target"
    input.resource.environment != "sandbox"
    input.context.approval_status != "approved"
}

deny_reasons contains "Viewer role is restricted to read-only operations." if {
    input.subject.role == "viewer"
    input.action.capability != "read"
}

deny_reasons contains "Security Operator or Admin role required for scan and task execution." if {
    input.action.capability == "scan"
    not input.subject.role in ["admin", "security_operator"]
}

deny_reasons contains "Target Agent operations are strictly restricted to sandbox environment." if {
    target_agent_non_sandbox
}

deny_reasons contains "Viewer role is not authorized to access target agent infrastructure." if {
    input.subject.role == "viewer"
    is_target_operation
}

deny_reasons contains "Red Team simulation execution prohibited outside sandbox environment." if {
    is_redteam_execution
    input.resource.environment != "sandbox"
}

deny_reasons contains "Security Operator or Admin role required for Red Team simulation execution." if {
    is_redteam_execution
    not input.subject.role in ["admin", "security_operator"]
}

deny_reasons contains "Viewer role is not authorized for Red Team operations." if {
    input.subject.role == "viewer"
    is_redteam_operation
}

deny_reasons contains "Blue Guardian defensive execution prohibited outside sandbox environment." if {
    is_guardian_execution
    input.resource.environment != "sandbox"
}

deny_reasons contains "Security Operator or Admin role required for Blue Guardian execution." if {
    is_guardian_execution
    not input.subject.role in ["admin", "security_operator"]
}

deny_reasons contains "Viewer role is not authorized for Blue Guardian operations." if {
    input.subject.role == "viewer"
    is_guardian_operation
}

deny_reasons contains "AI intelligence analysis prohibited outside sandbox environment." if {
    ai_non_sandbox
}

deny_reasons contains "Viewer role is not authorized for AI intelligence operations." if {
    input.subject.role == "viewer"
    is_ai_operation
}

deny_reasons contains "Security Operator or Admin role required for AI usage metrics." if {
    is_ai_usage
    not input.subject.role in ["admin", "security_operator"]
}

# Helper identifying Target Agent operations
is_target_operation if {
    input.action.operation in [
        "target.list_assets",
        "target.inspect_asset",
        "target.get_simulated_findings",
        "mcp.target_list_assets",
        "mcp.target_inspect_asset",
        "mcp.target_get_simulated_findings"
    ]
}

# Helper for target agent environment restriction
target_agent_non_sandbox if {
    is_target_operation
    input.resource.environment != "sandbox"
}

# Helper identifying Red Team execution operations
is_redteam_execution if {
    input.action.operation in [
        "redteam.simulate",
        "redteam.execute"
    ]
}

# Helper identifying Red Team read operations
is_redteam_read if {
    input.action.operation in [
        "redteam.run_read",
        "redteam.scenario_list"
    ]
}

# Helper identifying any Red Team operation
is_redteam_operation if {
    is_redteam_execution
}

is_redteam_operation if {
    is_redteam_read
}

# Helper for Red Team non-sandbox execution restriction
redteam_non_sandbox if {
    is_redteam_execution
    input.resource.environment != "sandbox"
}

# Helper identifying Blue Guardian execution operations
is_guardian_execution if {
    input.action.operation in [
        "guardian.execute",
        "guardian.ingest",
        "guardian.correlate",
        "guardian.detect",
        "guardian.risk_analysis",
        "guardian.recommend",
        "guardian.plan",
        "guardian.report_generate",
        "guardian.approval_request",
        "guardian.approval_decide",
        "guardian.synthetic_execute",
        "orchestration.start",
        "orchestration.resume"
    ]
}

# Helper identifying Blue Guardian read operations
is_guardian_read if {
    input.action.operation in [
        "guardian.read",
        "guardian.events_read",
        "guardian.groups_read",
        "guardian.detections_read",
        "guardian.rules_read",
        "guardian.risk_read",
        "guardian.recommendation_read",
        "guardian.remediation_read",
        "guardian.report_read",
        "guardian.playbook_read",
        "guardian.approval_read",
        "guardian.verification_read",
        "guardian.approval_policy_read",
        "orchestration.read",
        "orchestration.metrics"
    ]
}

# Helper identifying any Blue Guardian operation
is_guardian_operation if {
    is_guardian_execution
}

is_guardian_operation if {
    is_guardian_read
}

# Helper for Blue Guardian non-sandbox execution restriction
guardian_non_sandbox if {
    is_guardian_execution
    input.resource.environment != "sandbox"
}

# Helpers for AI intelligence operations
is_ai_analysis if {
    input.action.operation in [
        "ai.threat_explain",
        "ai.attack_path_analyze",
        "ai.risk_explain",
        "ai.incident_summarize",
        "ai.recommendation_explain",
        "ai.executive_briefing",
        "ai.security_qa",
        "ai.analysis_read",
        "ai.agent_execute",
        "ai.graph_execute",
        "ai.graph_read",
        "ai.agent_list"
    ]
}

is_ai_usage if {
    input.action.operation in [
        "ai.usage_read"
    ]
}

is_ai_operation if {
    is_ai_analysis
}

is_ai_operation if {
    is_ai_usage
}

ai_non_sandbox if {
    is_ai_analysis
    input.resource.environment != "sandbox"
}

# Explicit allow rules (narrowly scoped)

# 1. Admin operations: Allowed for admin users (excluding unapproved policy modifications and non-sandbox target/redteam/guardian/ai operations)
allow if {
    input.subject.is_authenticated
    input.subject.role == "admin"
    input.action.operation != "policy.modify"
    input.action.operation != "attack.execute"
    input.action.operation != "remediation.execute"
    not target_agent_non_sandbox
    not redteam_non_sandbox
    not guardian_non_sandbox
    not ai_non_sandbox
}

# 2. Policy modifications: Allowed for admin with human approval
allow if {
    input.subject.is_authenticated
    input.subject.role == "admin"
    input.action.operation == "policy.modify"
    input.context.approval_status == "approved"
}

# 3. Security Operator scan & task execution: Sandbox environment only
allow if {
    input.subject.is_authenticated
    input.subject.role in ["admin", "security_operator"]
    input.action.capability == "scan"
    input.resource.environment == "sandbox"
}

# 4. Remediation execution: Allowed for operators and admins ONLY with explicit approval
allow if {
    input.subject.is_authenticated
    input.subject.role in ["admin", "security_operator"]
    input.action.operation == "remediation.execute"
    input.context.approval_status == "approved"
}

# 5. Sandbox-only attack execution: Allowed for operators and admins in sandbox
allow if {
    input.subject.is_authenticated
    input.subject.role in ["admin", "security_operator"]
    input.action.operation == "attack.execute"
    input.resource.environment == "sandbox"
}

# 6. Read and investigation operations: Allowed for analysts, operators, and admins (sandbox only for target operations)
allow if {
    input.subject.is_authenticated
    input.subject.role in ["admin", "security_operator", "security_analyst"]
    input.action.capability == "read"
    not target_agent_non_sandbox
    not redteam_non_sandbox
    not guardian_non_sandbox
}

# 7. Viewer read-only access: Non-sensitive resource types only (synthetic assets & target/redteam/guardian/ai tools excluded)
allow if {
    input.subject.is_authenticated
    input.subject.role == "viewer"
    input.action.capability == "read"
    not input.resource.type in ["secret", "policy", "admin_log", "synthetic_asset"]
    not target_agent_non_sandbox
    not is_target_operation
    not is_redteam_operation
    not is_guardian_operation
    not is_ai_operation
}

# 8. Target Agent operations: Allowed strictly for security personnel in sandbox environment
allow if {
    input.subject.is_authenticated
    input.subject.role in ["admin", "security_operator", "security_analyst"]
    is_target_operation
    input.action.capability == "read"
    input.resource.environment == "sandbox"
}

# 9. Red Team simulation execution: Allowed for operators and admins strictly in sandbox environment
allow if {
    input.subject.is_authenticated
    input.subject.role in ["admin", "security_operator"]
    is_redteam_execution
    input.resource.environment == "sandbox"
}

# 10. Red Team read and scenario listing: Allowed for analysts, operators, and admins
allow if {
    input.subject.is_authenticated
    input.subject.role in ["admin", "security_operator", "security_analyst"]
    is_redteam_read
}

# 11. Blue Guardian defensive execution: Allowed for operators and admins strictly in sandbox environment
allow if {
    input.subject.is_authenticated
    input.subject.role in ["admin", "security_operator"]
    is_guardian_execution
    input.resource.environment == "sandbox"
}

# 12. Blue Guardian read: Allowed for analysts, operators, and admins
allow if {
    input.subject.is_authenticated
    input.subject.role in ["admin", "security_operator", "security_analyst"]
    is_guardian_read
}

# 13. AI intelligence analysis: Allowed for analysts, operators, and admins strictly in sandbox environment
allow if {
    input.subject.is_authenticated
    input.subject.role in ["admin", "security_operator", "security_analyst"]
    is_ai_analysis
    input.resource.environment == "sandbox"
}

# 14. AI usage metrics: Allowed for operators and admins
allow if {
    input.subject.is_authenticated
    input.subject.role in ["admin", "security_operator"]
    is_ai_usage
}
