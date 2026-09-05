import httpx

from red_alert.openclaw_client import OpenClawTarget


def test_openclaw_isolate_is_local_reset() -> None:
    client = httpx.Client(transport=httpx.MockTransport(lambda _req: httpx.Response(500)))
    target = OpenClawTarget("http://192.168.64.8:18789", "gateway-token", client)
    turn = target.isolate()
    assert turn.response is not None
    assert turn.response.status_code == 200
    assert turn.response.json()["status"] == "reset"
    assert turn.error is None


def test_openclaw_persist_is_unsupported() -> None:
    client = httpx.Client(transport=httpx.MockTransport(lambda _req: httpx.Response(200)))
    target = OpenClawTarget("http://192.168.64.8:18789", "gateway-token", client)
    turn = target.persist(principal="attacker", session_id="ra-a-test")
    assert turn.response is not None
    assert turn.response.status_code == 404
