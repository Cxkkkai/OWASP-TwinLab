from __future__ import annotations

from flask import jsonify, make_response, render_template, request


RESULT_HIGHLIGHT_FIELDS = (
    ("actor", "Actor"),
    ("username", "Username"),
    ("subject", "Subject"),
    ("role", "Role"),
    ("authenticated", "Authenticated"),
    ("order_id", "Order ID"),
    ("result_count", "Results returned"),
    ("authorized", "Authorization decision"),
    ("object_owner", "Returned object owner"),
    ("sensitive_data_returned", "Sensitive data returned"),
    ("internal_details_returned", "Internal details returned"),
    ("trace_marker_returned", "Synthetic trace returned"),
    ("path_marker_returned", "Synthetic path returned"),
    ("config_marker_returned", "Synthetic config marker returned"),
    ("correlated_server_event", "Correlated server event"),
    ("request_id", "Request ID"),
    ("server_event_type", "Server event type"),
    ("server_event_details_minimised", "Server event minimised"),
    ("hidden_exposed", "Hidden data exposed"),
    ("selection_policy", "Selection policy"),
    ("selected_version", "Selected version"),
    ("contains_untrusted_marker", "Unreviewed marker selected"),
    ("algorithm", "Storage algorithm"),
    ("accepted", "Request accepted"),
    ("hashes_equal", "Equal passwords have equal records"),
    ("unique_salt_per_account", "Unique salt per account"),
    ("candidate_verified", "Candidate verified"),
    ("first_use_status", "First-use status"),
    ("replay_status", "Replay status"),
    ("replay_blocked", "Replay blocked"),
    ("redemption_number", "Redemption number"),
    ("discount_percent", "Discount percent"),
    ("server_session_active_after_logout", "Old session active after logout"),
    ("old_token_replay_status", "Old-token replay status"),
    ("fresh_token_status", "Fresh-token status"),
    ("expires_in_seconds", "Session lifetime (seconds)"),
    ("integrity_valid", "Message integrity valid"),
    ("before_price_cents", "Price before"),
    ("after_price_cents", "Price after"),
    ("state_changed", "Price state changed"),
    ("api_status", "Protected API status"),
    ("failure_event_count", "Failure events"),
    ("alert_count", "Alerts"),
    ("access_granted", "Access granted"),
    ("export_returned", "Protected export returned"),
    ("fail_open", "Failure treated as allow"),
    ("claim_supported", "Defined claim supported"),
)


def _result_highlights(data: dict) -> list[dict[str, object]]:
    return [
        {"label": label, "value": data[key]}
        for key, label in RESULT_HIGHLIGHT_FIELDS
        if key in data
    ][:6]


def lab_response(
    *,
    lab,
    variant: str,
    outcome: str,
    data: dict,
    status: int = 200,
    plane: str = "target",
):
    payload = {
        "lab": lab["owasp"],
        "name": lab["name"],
        "variant": variant,
        "plane": plane,
        "outcome": outcome,
        **data,
    }
    if request.args.get("format") == "json" or request.accept_mimetypes.best == "application/json":
        response = make_response(jsonify(payload), status)
    else:
        response = make_response(
            render_template(
                "result.html",
                title=f"{lab['owasp']} {lab['name']}",
                lab=lab,
                variant=variant,
                outcome=outcome,
                payload=payload,
                http_status=status,
                result_highlights=_result_highlights(data),
            ),
            status,
        )
    response.headers["X-TwinLab-Plane"] = plane
    return response
