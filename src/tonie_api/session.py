"""The module of the Toniecloud session."""
import json
from pathlib import Path

import requests


class TonieCloudSession(requests.Session):
    """A regular restss session to the TonieCloud REST API."""

    URI: str = "https://api.tonie.cloud/v2"
    OPENID_CONNECT: str = "https://login.tonies.com/auth/realms/tonies/protocol/openid-connect/token"
    TOKEN_FILE: Path = Path("tonie_api_token.json")  # File to store the token

    def __init__(self):
        """Initialize the session."""
        super().__init__()
        self.token: None | str = self.load_token()

    def acquire_token(self, username: str, password: str) -> None:
        """Acquire the token from the ToniCloud SSO login using username and password.

        Args:
            username (str): The username
            password (str): The password_
        """
        if self.token is None:  # Acquire token only if it doesn't exist
            self.token = self._acquire_token(username, password)
            self.save_token()

    def _acquire_token(self, username: str, password: str) -> str:
        data = {
            "grant_type": "password",
            "client_id": "my-tonies",
            "scope": "openid",
            "username": username,
            "password": password,
        }
        response = requests.post(self.OPENID_CONNECT, data=data, timeout=15)
        return response.json()["access_token"]

    def save_token(self) -> None:
        """Save the token to a file."""
        if self.token:
            with Path.open(self.TOKEN_FILE, "w") as f:
                json.dump({"access_token": self.token}, f)

    def load_token(self) -> None | str:
        """Load the token from a file if it exists."""
        if Path.exists(self.TOKEN_FILE):
            with Path.open(self.TOKEN_FILE) as f:
                data = json.load(f)
                return data.get("access_token")
        return None

    def refresh_token(self, username: str, password: str) -> None:
        """Reacquire and save a new token, overwriting the previous one."""
        self.token = self._acquire_token(username, password)
        self.save_token()

    def get_auth_header(self) -> dict:
        """Get authorization header to use with authenticated requests."""
        if not self.token:
            msg = "No token available. Call acquire_token() first."
            raise ValueError(msg)
        return {"Authorization": f"Bearer {self.token}"}
