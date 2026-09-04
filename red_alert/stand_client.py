import httpx

DEFAULT_AUTH_MODE = "vulnerable"


class StandClient:
    def __init__(
        self,
        target: str,
        api_key: str,
        client: httpx.Client,
        *,
        auth_mode: str = DEFAULT_AUTH_MODE,
    ) -> None:
        self.target = target.rstrip("/")
        self.auth_mode = auth_mode
        self._client = client
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

    def chat_url(self) -> str:
        return f"{self.target}/v1/chat/completions"

    def finalize_url(self, session_id: str) -> str:
        return f"{self.target}/v1/sessions/{session_id}/finalize"

    def chat(self, *, session_id: str, user_content: str) -> tuple[dict, httpx.Response]:
        url = self.chat_url()
        body = {
            "messages": [{"role": "user", "content": user_content}],
            "session_id": session_id,
            "auth_mode": self.auth_mode,
        }
        response = self._client.post(url, json=body, headers=self._headers)
        return body, response

    def finalize(self, session_id: str) -> tuple[dict | None, httpx.Response]:
        url = self.finalize_url(session_id)
        response = self._client.post(url, headers=self._headers)
        return None, response
