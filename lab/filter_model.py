"""Pure metadata model, not a packet parser or a clone of any deployed DPI."""
from dataclasses import dataclass
from ipaddress import ip_address, ip_network


@dataclass(frozen=True)
class Flow:
    destination: str
    sni: str
    transport: str
    requested_bytes: int


@dataclass(frozen=True)
class Result:
    admitted: bool
    delivered_bytes: int
    reason: str


def evaluate(scenario: dict, flow: Flow) -> Result:
    if flow.requested_bytes < 0:
        raise ValueError('Negative byte request')
    address = ip_address(flow.destination)
    if scenario.get('total_outage'):
        return Result(False, 0, 'unavailable')
    if flow.transport.lower() in scenario.get('blocked_transports', []):
        return Result(False, 0, 'transport_rule')
    networks = scenario.get('allowed_cidrs', [])
    if networks and not any(address in ip_network(cidr) for cidr in networks):
        return Result(False, 0, 'address_rule')
    names = scenario.get('allowed_names', [])
    if names and flow.sni not in names:
        return Result(False, 0, 'name_rule')
    cap = scenario.get('max_delivered_bytes')
    delivered = min(flow.requested_bytes, cap) if cap is not None else flow.requested_bytes
    return Result(True, delivered, 'modeled_stall' if delivered < flow.requested_bytes else 'modeled_pass')
