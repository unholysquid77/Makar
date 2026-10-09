"""API-facing models.

The forensic models in ``core.models`` are already Pydantic and already the
right shape for the wire, so they are served directly rather than duplicated
here. Request bodies live beside their routes in ``backend.api.routes``.
"""
