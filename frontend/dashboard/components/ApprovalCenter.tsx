"use client";

import React, { useEffect, useState, useCallback } from "react";
import { useAuth } from "../lib/auth-context";
import { api } from "../lib/api";
import {
  ApprovalRequestResponse,
  ApprovalStatus,
  RecommendationPriority,
  RemediationPlan,
} from "../lib/types";
import {
  ShieldAlert,
  UserCheck,
  CheckCircle2,
  XCircle,
  Clock,
  AlertTriangle,
  Play,
  RotateCcw,
  RefreshCw,
  FileText,
  User,
  Shield,
  MessageSquare,
  Lock,
} from "lucide-react";

interface ApprovalCenterProps {
  onRemediationExecuted?: (executionId: string) => void;
}

export const ApprovalCenter: React.FC<ApprovalCenterProps> = ({ onRemediationExecuted }) => {
  const { user, activeSandbox } = useAuth();
  const [requests, setRequests] = useState<ApprovalRequestResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedRequest, setSelectedRequest] = useState<ApprovalRequestResponse | null>(null);
  const [planDetail, setPlanDetail] = useState<RemediationPlan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Decision Modal state
  const [decisionModal, setDecisionModal] = useState<{
    isOpen: boolean;
    type: "approve" | "reject";
    requestId: string;
  } | null>(null);
  const [decisionComment, setDecisionComment] = useState("");
  const [isSubmittingDecision, setIsSubmittingDecision] = useState(false);

  // Execution state
  const [isExecuting, setIsExecuting] = useState(false);

  const fetchApprovals = useCallback(async (silent = false) => {
    if (!activeSandbox) {
      setLoading(false);
      return;
    }
    if (!silent) setLoading(true);
    else setRefreshing(true);
    setError(null);

    try {
      const res = await api.approval.listApprovalRequests({
        sandbox_id: activeSandbox.id,
        page_size: 50,
      });
      setRequests(res.items || []);
      if (res.items && res.items.length > 0) {
        if (!selectedRequest || !res.items.some((r) => r.id === selectedRequest.id)) {
          setSelectedRequest(res.items[0]);
        } else {
          const updated = res.items.find((r) => r.id === selectedRequest.id);
          if (updated) setSelectedRequest(updated);
        }
      } else {
        setSelectedRequest(null);
      }
    } catch (err: any) {
      console.error("Failed to fetch approval requests:", err);
      setError(err?.message || "Failed to load approval requests.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [activeSandbox, selectedRequest]);

  useEffect(() => {
    fetchApprovals();
  }, [activeSandbox]);

  // Fetch plan details when selectedRequest changes
  useEffect(() => {
    if (!selectedRequest) {
      setPlanDetail(null);
      return;
    }

    const loadPlan = async () => {
      try {
        const plan = await api.guardian.getRemediationPlan(selectedRequest.remediation_plan_id);
        setPlanDetail(plan);
      } catch (e) {
        console.warn("Could not load full plan detail:", e);
      }
    };
    loadPlan();
  }, [selectedRequest]);

  // Handle Approve / Reject submission
  const handleDecisionSubmit = async () => {
    if (!decisionModal) return;
    setIsSubmittingDecision(true);
    setError(null);
    setActionSuccess(null);

    try {
      if (decisionModal.type === "approve") {
        await api.approval.approveRequest(decisionModal.requestId, decisionComment);
        setActionSuccess("Approval vote recorded successfully.");
      } else {
        await api.approval.rejectRequest(decisionModal.requestId, decisionComment);
        setActionSuccess("Remediation plan vetoed / rejected.");
      }
      setDecisionModal(null);
      setDecisionComment("");
      await fetchApprovals(true);
    } catch (err: any) {
      console.error("Decision submission failed:", err);
      setError(err?.message || "Failed to submit decision.");
    } finally {
      setIsSubmittingDecision(false);
    }
  };

  // Handle Synthetic Remediation Execution
  const handleExecuteRemediation = async (requestId: string) => {
    setIsExecuting(true);
    setError(null);
    setActionSuccess(null);
    try {
      const execRes = await api.approval.executeRemediation(requestId);
      setActionSuccess("Synthetic remediation execution initiated in sandbox!");
      await fetchApprovals(true);
      if (onRemediationExecuted) {
        onRemediationExecuted(execRes.id);
      }
    } catch (err: any) {
      console.error("Remediation execution failed:", err);
      setError(err?.message || "Failed to trigger synthetic remediation execution.");
    } finally {
      setIsExecuting(false);
    }
  };

  // Checks for Four-Eyes constraints
  const requesterUuid = selectedRequest?.requested_by || selectedRequest?.requester_id;
  const isRequester = user && selectedRequest && String(user.id) === String(requesterUuid);
  const hasAlreadyVoted =
    user &&
    selectedRequest &&
    selectedRequest.decisions.some((d) => String(d.approver_id) === String(user.id));
  const isPending = selectedRequest?.approval_status === "pending_approval";
  const isApproved = selectedRequest?.approval_status === "approved";
  const isP0 = selectedRequest?.overall_priority === "P0";
  const canVote = isPending && !isRequester && !hasAlreadyVoted && user?.role !== "viewer";

  return (
    <div className="space-y-6">
      {/* Header and Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#1a2744] pb-4">
        <div>
          <div className="flex items-center gap-2">
            <UserCheck className="h-5 w-5 text-cyan-400" />
            <h2 className="text-base font-bold text-white tracking-wide">
              Human-in-the-Loop Approval Center
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Cryptographic four-eyes verification and multi-signature authorization for synthetic remediations.
          </p>
        </div>

        <button
          onClick={() => fetchApprovals(true)}
          disabled={refreshing}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#1a2744] bg-[#070e22] text-xs font-semibold text-slate-300 hover:bg-slate-800 transition-colors self-start sm:self-auto"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />
          <span>Refresh Requests</span>
        </button>
      </div>

      {actionSuccess && (
        <div className="flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-950/40 p-3 text-xs text-emerald-200">
          <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
          <span>{actionSuccess}</span>
        </div>
      )}

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-950/40 p-3 text-xs text-red-200">
          <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Main Layout: Requests List on Left, Selected Detail on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Requests List */}
        <div className="lg:col-span-5 space-y-3">
          <div className="flex items-center justify-between text-xs text-slate-400 font-semibold px-1">
            <span>APPROVAL REQUESTS ({requests.length})</span>
            <span>STATUS</span>
          </div>

          {loading ? (
            <div className="flex h-64 items-center justify-center rounded-xl border border-[#1a2744] bg-[#070e22]">
              <Clock className="h-6 w-6 animate-spin text-cyan-400" />
            </div>
          ) : requests.length === 0 ? (
            <div className="rounded-xl border border-[#1a2744] bg-[#070e22] p-8 text-center text-xs text-slate-400">
              <Shield className="mx-auto h-8 w-8 text-slate-600 mb-2" />
              <span>No approval requests in current sandbox.</span>
            </div>
          ) : (
            <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
              {requests.map((req) => {
                const isSelected = selectedRequest?.id === req.id;
                return (
                  <button
                    key={req.id}
                    onClick={() => setSelectedRequest(req)}
                    className={`w-full text-left p-3.5 rounded-xl border transition-all ${
                      isSelected
                        ? "border-cyan-500 bg-cyan-950/30 shadow-md shadow-cyan-950/50"
                        : "border-[#1a2744] bg-[#070e22] hover:border-slate-700"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span
                          className={`rounded px-1.5 py-0.5 text-[10px] font-bold font-mono ${
                            req.overall_priority === "P0"
                              ? "bg-red-950 text-red-300 border border-red-800"
                              : req.overall_priority === "P1"
                              ? "bg-orange-950 text-orange-300 border border-orange-800"
                              : "bg-blue-950 text-blue-300 border border-blue-800"
                          }`}
                        >
                          {req.overall_priority}
                        </span>
                        <span className="text-xs font-bold text-white font-mono">
                          {req.id.slice(0, 8)}...
                        </span>
                      </div>

                      <span
                        className={`rounded px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider border font-mono ${
                          req.approval_status === "approved"
                            ? "bg-emerald-950 text-emerald-300 border-emerald-800"
                            : req.approval_status === "pending_approval"
                            ? "bg-amber-950 text-amber-300 border-amber-800 animate-pulse"
                            : req.approval_status === "rejected"
                            ? "bg-red-950 text-red-300 border-red-800"
                            : "bg-slate-900 text-slate-400 border-slate-800"
                        }`}
                      >
                        {req.approval_status.replace(/_/g, " ")}
                      </span>
                    </div>

                    <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400">
                      <span>Signatures: {req.approvals_received ?? req.received_approvals ?? 0} / {req.required_approvals}</span>
                      <span className="text-[10px] font-mono">
                        Expires: {new Date(req.expires_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Right Column: Detailed Request & Multi-Signature Governance */}
        <div className="lg:col-span-7">
          {selectedRequest ? (
            <div className="rounded-xl border border-[#1a2744] bg-[#070e22] p-6 space-y-6">
              {/* Request Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#1a2744] pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-bold text-white">
                      Remediation Plan Signoff: {selectedRequest.id}
                    </h3>
                  </div>
                  <div className="flex items-center gap-3 text-xs text-slate-400 mt-1 font-mono">
                    <span>Requester: {selectedRequest.requester_username || (selectedRequest.requested_by || selectedRequest.requester_id || "").slice(0, 8)}</span>
                    <span>•</span>
                    <span>Plan Version: {selectedRequest.plan_version}</span>
                    <span>•</span>
                    <span>Policy: {selectedRequest.approval_policy_version}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <span
                    className={`rounded px-2.5 py-1 text-xs font-bold font-mono uppercase tracking-wider border ${
                      selectedRequest.approval_status === "approved"
                        ? "bg-emerald-950 text-emerald-300 border-emerald-800"
                        : selectedRequest.approval_status === "pending_approval"
                        ? "bg-amber-950 text-amber-300 border-amber-800"
                        : "bg-red-950 text-red-300 border-red-800"
                    }`}
                  >
                    {selectedRequest.approval_status.replace(/_/g, " ")}
                  </span>
                </div>
              </div>

              {/* Four-Eyes Governance Quorum Bar */}
              <div className="rounded-lg border border-[#1a2744] bg-[#050914] p-4 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                    <Lock className="h-3.5 w-3.5 text-cyan-400" />
                    <span>Four-Eyes Governance Quorum:</span>
                  </span>
                  <span className="font-mono text-cyan-300 font-bold">
                    {selectedRequest.approvals_received ?? selectedRequest.received_approvals ?? 0} of {selectedRequest.required_approvals} Approvals Recorded
                  </span>
                </div>

                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-300 ${
                      (selectedRequest.approvals_received ?? selectedRequest.received_approvals ?? 0) >= selectedRequest.required_approvals
                        ? "bg-emerald-500"
                        : "bg-cyan-500"
                    }`}
                    style={{
                      width: `${Math.min(
                        100,
                        ((selectedRequest.approvals_received ?? selectedRequest.received_approvals ?? 0) / selectedRequest.required_approvals) * 100
                      )}%`,
                    }}
                  />
                </div>

                {isP0 && (
                  <p className="text-[11px] text-amber-400 mt-1 flex items-center gap-1">
                    <AlertTriangle className="h-3 w-3 shrink-0" />
                    <span>P0 Incident Mandate: At least one Administrator or Senior Operator signature is strictly required.</span>
                  </p>
                )}
              </div>

              {/* Four-Eyes Policy Rules Messages */}
              {isRequester && (
                <div className="rounded-lg border border-amber-500/30 bg-amber-950/20 p-3 text-xs text-amber-300 flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
                  <span>
                    <strong>Self-Approval Forbidden:</strong> You initiated this request. AegisMesh Four-Eyes Policy mandates that another qualified operator must review and approve this plan.
                  </span>
                </div>
              )}

              {hasAlreadyVoted && (
                <div className="rounded-lg border border-cyan-500/30 bg-cyan-950/20 p-3 text-xs text-cyan-300 flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-cyan-400" />
                  <span>You have already cast an immutable decision for this approval cycle.</span>
                </div>
              )}

              {/* Remediation Plan Actions Preview */}
              {planDetail && (
                <div>
                  <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                    Actions To Be Applied in Sandbox ({planDetail.actions?.length || 0})
                  </h4>
                  <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                    {planDetail.actions?.map((act, i) => (
                      <div
                        key={act.id || i}
                        className="flex items-center justify-between rounded-lg border border-[#1a2744] bg-[#050914] p-2.5 text-xs"
                      >
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-cyan-400 text-[11px]">{act.action_code}</span>
                          <span className="text-slate-300 font-medium">{act.title}</span>
                        </div>
                        <span className="text-[10px] text-slate-500 font-mono">
                          Order: #{act.sequence_order}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Recorded Approver Decisions */}
              <div>
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                  Recorded Cryptographic Decisions
                </h4>
                {selectedRequest.decisions.length === 0 ? (
                  <p className="text-xs text-slate-500 italic">No decisions recorded yet.</p>
                ) : (
                  <div className="space-y-2">
                    {selectedRequest.decisions.map((dec) => (
                      <div
                        key={dec.id}
                        className="flex items-center justify-between rounded-lg border border-[#1a2744] bg-[#050914] p-3 text-xs"
                      >
                        <div className="flex items-center gap-2.5">
                          <User className="h-4 w-4 text-cyan-400" />
                          <div>
                            <span className="font-semibold text-white">
                              {dec.approver_username || dec.approver_id.slice(0, 8)}
                            </span>
                            <span className="text-[10px] text-slate-500 font-mono ml-2">
                              ({dec.approver_role || "operator"})
                            </span>
                            {dec.comments && (
                              <p className="text-[11px] text-slate-400 mt-0.5 italic">
                                &ldquo;{dec.comments}&rdquo;
                              </p>
                            )}
                          </div>
                        </div>

                        <div className="flex items-center gap-2 font-mono">
                          <span
                            className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase border ${
                              dec.decision === "approved"
                                ? "bg-emerald-950 text-emerald-300 border-emerald-800"
                                : "bg-red-950 text-red-300 border-red-800"
                            }`}
                          >
                            {dec.decision}
                          </span>
                          <span className="text-[10px] text-slate-500">
                            {new Date(dec.decided_at).toLocaleTimeString()}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Action Buttons */}
              <div className="flex flex-wrap items-center justify-end gap-3 pt-4 border-t border-[#1a2744]">
                {canVote && (
                  <>
                    <button
                      onClick={() =>
                        setDecisionModal({
                          isOpen: true,
                          type: "reject",
                          requestId: selectedRequest.id,
                        })
                      }
                      className="px-4 py-2 rounded-lg border border-red-500/40 bg-red-950/40 text-xs font-semibold text-red-200 hover:bg-red-900/60 transition-colors"
                    >
                      Veto / Reject Plan
                    </button>

                    <button
                      onClick={() =>
                        setDecisionModal({
                          isOpen: true,
                          type: "approve",
                          requestId: selectedRequest.id,
                        })
                      }
                      className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-emerald-600 text-xs font-semibold text-white hover:bg-emerald-500 transition-colors shadow-md shadow-emerald-950"
                    >
                      <CheckCircle2 className="h-4 w-4" />
                      <span>Sign & Approve</span>
                    </button>
                  </>
                )}

                {isApproved && (
                  <button
                    onClick={() => handleExecuteRemediation(selectedRequest.id)}
                    disabled={isExecuting}
                    className="flex items-center gap-2 px-5 py-2 rounded-lg bg-cyan-600 text-xs font-semibold text-white hover:bg-cyan-500 transition-colors shadow-md shadow-cyan-950 disabled:opacity-50"
                  >
                    {isExecuting ? (
                      <Clock className="h-4 w-4 animate-spin" />
                    ) : (
                      <Play className="h-4 w-4" />
                    )}
                    <span>Execute Synthetic Remediation</span>
                  </button>
                )}
              </div>
            </div>
          ) : (
            <div className="flex h-96 items-center justify-center rounded-xl border border-[#1a2744] bg-[#070e22] text-xs text-slate-400">
              Select an approval request to inspect governance quorum.
            </div>
          )}
        </div>
      </div>

      {/* Approve / Reject Confirmation Modal */}
      {decisionModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-md rounded-xl border border-cyan-500/30 bg-[#0b1329] p-6 space-y-4 shadow-2xl">
            <h3 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
              {decisionModal.type === "approve" ? (
                <>
                  <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                  <span>Authorize Remediation Signoff</span>
                </>
              ) : (
                <>
                  <XCircle className="h-4 w-4 text-red-400" />
                  <span>Reject Remediation Plan</span>
                </>
              )}
            </h3>

            <p className="text-xs text-slate-400">
              {decisionModal.type === "approve"
                ? "Your cryptographic signature will be recorded in the immutable SHA-256 audit ledger."
                : "Rejecting this plan halts synthetic execution. The pipeline will transition to a safe terminal state."}
            </p>

            <div>
              <label className="block text-[11px] font-semibold text-slate-300 mb-1 uppercase tracking-wider">
                Decision Notes & Operational Comments
              </label>
              <textarea
                value={decisionComment}
                onChange={(e) => setDecisionComment(e.target.value)}
                placeholder="Enter justification or signoff rationale..."
                rows={3}
                className="w-full rounded-lg border border-[#1a2744] bg-[#050914] p-2.5 text-xs text-white focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setDecisionModal(null)}
                disabled={isSubmittingDecision}
                className="px-3.5 py-1.5 rounded-lg border border-[#1a2744] text-xs font-semibold text-slate-400 hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleDecisionSubmit}
                disabled={isSubmittingDecision}
                className={`px-4 py-1.5 rounded-lg text-xs font-semibold text-white ${
                  decisionModal.type === "approve"
                    ? "bg-emerald-600 hover:bg-emerald-500"
                    : "bg-red-600 hover:bg-red-500"
                }`}
              >
                {isSubmittingDecision ? "Recording Decision..." : "Confirm Decision"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
