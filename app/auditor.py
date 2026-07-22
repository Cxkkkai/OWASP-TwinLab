"""Counterexample-guided security-control auditor user interface."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, render_template

from .auditor_contracts import validate_auditor_contracts


bp = Blueprint("auditor", __name__, url_prefix="/auditor")


@bp.get("/")
def overview():
    return render_template(
        "auditor.html",
        title="Security Control Auditor",
        auditor_contracts=validate_auditor_contracts(),
        observer_capability=current_app.config["LAB_OBSERVER_CAPABILITY"],
    )


@bp.get("/contracts")
def contracts():
    response = jsonify(
        {
            "scope": "localhost synthetic bounded audit",
            "contracts": validate_auditor_contracts(),
        }
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-TwinLab-Plane"] = "runner"
    return response
