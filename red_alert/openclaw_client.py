import httpx

from red_alert.target import TargetTurn, UserContent, isolate_error

DEFAULT_OPENCLAW_MODEL = "openclaw/default"


def _json_response(url: str, status_code: int, body: dict) -> httpx.Response:
    request = httpx.Request("POST", url)
    return httpx.Response(status_code, json=body, request=request)


class OpenClawTarget:
    def __init__(
        self,
        target: str,
        token: str,
        client: httpx.Client,
        *,
        model: str = DEFAULT_OPENCLAW_MODEL,
    ) -> None:
        self.target = target.rstrip("/")
        self.model = model
        self._client = client
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def chat_url(self) -> str:
        return f"{self.target}/v1/chat/completions"

    def persist_url(self, session_id: str) -> str:
        return f"{self.target}/v1/sessions/{session_id}/finalize"

    def isolate_url(self) -> str:
        return f"{self.target}/v1/sessions/isolate"

    def chat(self, *, principal: str, session_id: str, user_content: UserContent) -> TargetTurn:
        url = self.chat_url()
        body = {
            "model": self.model,
            "user": session_id,
            "messages": [{"role": "user", "content": user_content}],
        }
        headers = {
            **self._headers,
            "x-openclaw-session-key": session_id,
        }
        try:
            response = self._client.post(url, json=body, headers=headers)
        except httpx.RequestError as exc:
            return TargetTurn(method="POST", url=url, request_body=body, error=str(exc))
        return TargetTurn(method="POST", url=url, request_body=body, response=response)

    def persist(self, *, principal: str, session_id: str) -> TargetTurn:
        url = self.persist_url(session_id)
        response = _json_response(
            url,
            404,
            {"error": {"message": "OpenClaw target has no persist", "type": "not_found"}},
        )
        return TargetTurn(method="POST", url=url, request_body=None, response=response)

    def isolate(self) -> TargetTurn:
        url = self.isolate_url()
        response = _json_response(url, 200, {"status": "reset", "deleted": {}})
        return TargetTurn(
            method="POST",
            url=url,
            request_body=None,
            response=response,
            error=isolate_error(response),
        )
