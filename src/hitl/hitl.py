"""
Lab 11 — Part 4: Human-in-the-Loop Design
  TODO 11: Confidence Router
  TODO 12: Design 3 HITL decision points
"""
from dataclasses import dataclass


# ============================================================
# TODO 11: Implement ConfidenceRouter
#
# Route agent responses based on confidence scores:
#   - HIGH (>= 0.9): Auto-send to user
#   - MEDIUM (0.7 - 0.9): Queue for human review
#   - LOW (< 0.7): Escalate to human immediately
#
# Special case: if the action is HIGH_RISK (e.g., money transfer,
# account deletion), ALWAYS escalate regardless of confidence.
#
# Implement the route() method.
# ============================================================

HIGH_RISK_ACTIONS = [
    "transfer_money",
    "close_account",
    "change_password",
    "delete_data",
    "update_personal_info",
]


@dataclass
class RoutingDecision:
    """Result of the confidence router."""
    action: str          # "auto_send", "queue_review", "escalate"
    confidence: float
    reason: str
    priority: str        # "low", "normal", "high"
    requires_human: bool


class ConfidenceRouter:
    """Route agent responses based on confidence and risk level.

    Thresholds:
        HIGH:   confidence >= 0.9 -> auto-send
        MEDIUM: 0.7 <= confidence < 0.9 -> queue for review
        LOW:    confidence < 0.7 -> escalate to human

    High-risk actions always escalate regardless of confidence.
    """

    HIGH_THRESHOLD = 0.9
    MEDIUM_THRESHOLD = 0.7

    def route(self, response: str, confidence: float,
              action_type: str = "general") -> RoutingDecision:
        """Route a response based on confidence score and action type.

        Args:
            response: The agent's response text
            confidence: Confidence score between 0.0 and 1.0
            action_type: Type of action (e.g., "general", "transfer_money")

        Returns:
            RoutingDecision with routing action and metadata
        """
        # 1. High-risk action check: always escalate
        if action_type in HIGH_RISK_ACTIONS:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason=f"High-risk action: {action_type}",
                priority="high",
                requires_human=True,
            )

        # 2. Confidence threshold check
        if confidence >= self.HIGH_THRESHOLD:
            return RoutingDecision(
                action="auto_send",
                confidence=confidence,
                reason="High confidence",
                priority="low",
                requires_human=False,
            )
        elif confidence >= self.MEDIUM_THRESHOLD:
            return RoutingDecision(
                action="queue_review",
                confidence=confidence,
                reason="Medium confidence — needs review",
                priority="normal",
                requires_human=True,
            )
        else:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason="Low confidence — escalating",
                priority="high",
                requires_human=True,
            )


# ============================================================
# TODO 12: Design 3 HITL decision points + a review lifecycle
# ============================================================

hitl_decision_points = [
    {
        "id": 1,
        "name": "High-Value Money Transfer Approval",
        "trigger": "User requests transfer_money action or transfer amount >= 50,000,000 VND",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Sender ID, recipient account details, transfer amount, user risk score, historical transaction pattern",
        "example": "Customer requests transferring 100,000,000 VND to an external bank account via AI Assistant.",
        "approval_path": "Approve executes transaction; Reject cancels transfer & notifies user; Timeout (10m) auto-cancels and requires 2FA OTP.",
        "audit_fields": "Correlation ID, sender_id, recipient_account, amount_vnd, risk_score, reviewer_id, review_timestamp, final_decision",
    },
    {
        "id": 2,
        "name": "Sensitive Profile & Credential Modification",
        "trigger": "User requests close_account, change_password, or update_personal_info",
        "hitl_model": "human-in-the-loop",
        "context_needed": "User identity verification status, device fingerprint, IP geolocation, proposed profile changes diff",
        "example": "User asks to update registered phone number and close savings account via chat session.",
        "approval_path": "Approve applies system changes; Reject blocks request; Timeout (15m) locks action and alerts fraud team.",
        "audit_fields": "Correlation ID, user_id, action_type, proposed_diff, ip_address, reviewer_id, approval_status",
    },
    {
        "id": 3,
        "name": "Low Confidence & Complex Inquiry Escalation",
        "trigger": "AI confidence score < 0.70 or LLM Judge marks response as potential hallucination/off-topic",
        "hitl_model": "human-on-the-loop",
        "context_needed": "User prompt, conversation history, retrieved RAG policy documents, candidate AI response draft",
        "example": "User asks complex non-standard loan policy question resulting in AI confidence 0.58.",
        "approval_path": "Approve/Edit sends response to customer; Reject replaces with custom agent response; Timeout (5m) transfers to live support queue.",
        "audit_fields": "Correlation ID, user_query, confidence_score, ai_draft_text, final_sent_text, agent_id",
    },
]


# ============================================================
# Quick tests
# ============================================================

def test_confidence_router():
    """Test ConfidenceRouter with sample scenarios."""
    router = ConfidenceRouter()

    test_cases = [
        ("Balance inquiry", 0.95, "general"),
        ("Interest rate question", 0.82, "general"),
        ("Ambiguous request", 0.55, "general"),
        ("Transfer $50,000", 0.98, "transfer_money"),
        ("Close my account", 0.91, "close_account"),
    ]

    print("Testing ConfidenceRouter:")
    print("=" * 80)
    print(f"{'Scenario':<25} {'Conf':<6} {'Action Type':<18} {'Decision':<15} {'Priority':<10} {'Human?'}")
    print("-" * 80)

    for scenario, conf, action_type in test_cases:
        decision = router.route(scenario, conf, action_type)
        print(
            f"{scenario:<25} {conf:<6.2f} {action_type:<18} "
            f"{decision.action:<15} {decision.priority:<10} "
            f"{'Yes' if decision.requires_human else 'No'}"
        )

    print("=" * 80)


def test_hitl_points():
    """Display HITL decision points."""
    print("\nHITL Decision Points:")
    print("=" * 60)
    for point in hitl_decision_points:
        print(f"\n  Decision Point #{point['id']}: {point['name']}")
        print(f"    Trigger:  {point['trigger']}")
        print(f"    Model:    {point['hitl_model']}")
        print(f"    Context:  {point['context_needed']}")
        print(f"    Example:  {point['example']}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_confidence_router()
    test_hitl_points()
