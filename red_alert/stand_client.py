import httpx

from red_alert.target import (
    PRINCIPAL_ATTACKER,
    PRINCIPAL_VICTIM,
    TargetTurn,
    isolate_error,
)

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

    def persist_url(self, session_id: str) -> str:
        return f"{self.target}/v1/sessions/{session_id}/finalize"

    def isolate_url(self) -> str:
        return f"{self.target}/v1/memory/reset"

    def chat(self, *, session_id: str, user_content: str) -> tuple[dict, httpx.Response]:
        url = self.chat_url()
        body = {
            "messages": [{"role": "user", "content": user_content}],
            "session_id": session_id,
            "auth_mode": self.auth_mode,
        }
        response = self._client.post(url, json=body, headers=self._headers)
        return body, response

    def persist(self, session_id: str) -> tuple[dict | None, httpx.Response]:
        url = self.persist_url(session_id)
        response = self._client.post(url, headers=self._headers)
        return None, response

    def isolate(self) -> tuple[dict | None, httpx.Response]:
        url = self.isolate_url()
        response = self._client.post(url, headers=self._headers)
        return None, response


class InvestStandTarget:
    def __init__(
        self,
        target: str,
        attacker_key: str,
        victim_key: str,
        client: httpx.Client,
        *,
        auth_mode: str = DEFAULT_AUTH_MODE,
    ) -> None:
        self._clients = {
            PRINCIPAL_ATTACKER: StandClient(target, attacker_key, client, auth_mode=auth_mode),
            PRINCIPAL_VICTIM: StandClient(target, victim_key, client, auth_mode=auth_mode),
        }

    def _client(self, principal: str) -> StandClient:
        return self._clients[principal]

    def chat(self, *, principal: str, session_id: str, user_content: str) -> TargetTurn:
        client = self._client(principal)
        try:
            body, response = client.chat(session_id=session_id, user_content=user_content)
        except httpx.RequestError as exc:
            return TargetTurn(
                method="POST",
                url=client.chat_url(),
                request_body={"session_id": session_id},
                error=str(exc),
            )
        return TargetTurn(
            method="POST",
            url=client.chat_url(),
            request_body=body,
            response=response,
        )

    def persist(self, *, principal: str, session_id: str) -> TargetTurn:
        client = self._client(principal)
        try:
            _, response = client.persist(session_id)
        except httpx.RequestError as exc:
            return TargetTurn(
                method="POST",
                url=client.persist_url(session_id),
                request_body=None,
                error=str(exc),
            )
        return TargetTurn(
            method="POST",
            url=client.persist_url(session_id),
            request_body=None,
            response=response,
        )

    def isolate(self) -> TargetTurn:
        client = self._client(PRINCIPAL_ATTACKER)
        try:
            _, response = client.isolate()
        except httpx.RequestError as exc:
            return TargetTurn(
                method="POST",
                url=client.isolate_url(),
                request_body=None,
                error=str(exc),
            )
        return TargetTurn(
            method="POST",
            url=client.isolate_url(),
            request_body=None,
            response=response,
            error=isolate_error(response),
        )
