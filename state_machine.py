# state_machine.py

from proxy.utils.route_scope import route_phase


def update_state(state, data, direction):
    """
    Inspect raw traffic and update session state.
    No side effects outside state.
    """
    _ = data
    _ = direction

    route_name = getattr(state, "route_name", "")
    state.phase = route_phase(route_name) or getattr(state, "phase", "auth")
