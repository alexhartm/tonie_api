"""The module of the Toniecloud session."""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import jwt
import requests
from jwt.exceptions import DecodeError

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())


class TonieCloudSession(requests.Session):
    """A session to the TonieCloud REST API with token management."""

    URI: str = "https://api.tonie.cloud/v2"
    OPENID_CONNECT: str = "https://login.tonies.com/auth/realms/tonies/protocol/openid-connect/token"
    TOKEN_FILE: Path = Path("tonie_api_token.json")  # File to store the tokens

    def __init__(self):
        """Initialize the session."""
        super().__init__()
        self.token: None | str = None
        self.refresh_token: None | str = None
        self.load_tokens()

    def acquire_token(self, username: str, password: str) -> None:
        """Acquire a new access and refresh token using username and password."""
        if self.token is None or self.is_token_expired(self.token):
            log.info("No valid token found, acquiring a new token...")
            self.token, self.refresh_token = self._acquire_tokens(username, password)
            self.save_tokens()

    def _acquire_tokens(self, username: str, password: str) -> tuple[str, str]:
        log.debug("Requesting new access and refresh tokens from Tonie Cloud.")
        data = {
            "grant_type": "password",
            "client_id": "my-tonies",
            "scope": "openid",
            "username": username,
            "password": password,
        }
        response = requests.post(self.OPENID_CONNECT, data=data, timeout=15)
        response_data = response.json()
        log.debug("Received response from token endpoint.")

        access_token = response_data["access_token"]
        refresh_token = response_data["refresh_token"]

        expiration = self._get_token_expiration(access_token)
        log.info("New access token acquired with expiration date: %s", expiration)

        return access_token, refresh_token

    def _acquire_access_token_from_refresh_token(self) -> str | None:
        """Attempt to acquire a new access token using the refresh token."""
        if self.refresh_token is None:
            log.debug("No refresh token available.")
            return None

        log.info("Attempting to refresh access token using refresh token.")
        data = {
            "grant_type": "refresh_token",
            "client_id": "my-tonies",
            "refresh_token": self.refresh_token,
        }
        response = requests.post(self.OPENID_CONNECT, data=data, timeout=15)

        if response.status_code == requests.codes.ok:
            response_data = response.json()
            log.info("Access token successfully refreshed.")
            self.token = response_data["access_token"]
            self.refresh_token = response_data.get("refresh_token", self.refresh_token)  # Update refresh token if given
            self.save_tokens()
            return self.token

        log.warning("Failed to refresh access token with refresh token.")
        return None

    def save_tokens(self) -> None:
        """Save the access and refresh tokens to a file."""
        if self.token:
            with Path.open(self.TOKEN_FILE, "w") as f:
                json.dump({"access_token": self.token, "refresh_token": self.refresh_token}, f)
                expiration = self._get_token_expiration(self.token)
                log.info("Tokens saved to file %s with expiration date: %s", self.TOKEN_FILE, expiration)
                log.debug("Tokens saved successfully.")

    def load_tokens(self) -> None:
        """Load the access and refresh tokens from a file if they exist."""
        if Path.exists(self.TOKEN_FILE):
            with Path.open(self.TOKEN_FILE) as f:
                data = json.load(f)
                self.token = data.get("access_token")
                self.refresh_token = data.get("refresh_token")
                expiration = self._get_token_expiration(self.token) if self.token else "Unknown"
                log.info("Loaded tokens from file %s with expiration date: %s", self.TOKEN_FILE, expiration)
                log.debug("Tokens loaded successfully.")

    def is_token_expired(self, token: str) -> bool:
        """Check if the provided JWT token has expired."""
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
        except (DecodeError, TypeError):
            log.exception("Failed to decode JWT.")
            return True
        else:
            expiration = datetime.fromtimestamp(payload.get("exp"), tz=timezone.utc)
            log.info("Token expiration date: %s", expiration)
            is_expired = datetime.now(tz=timezone.utc) >= expiration
            log.debug("Token expired: %s", is_expired)
            return is_expired

    def _get_token_expiration(self, token: str) -> datetime | str:
        """Helper to extract the expiration date of a JWT token.

        Returns:
            datetime | str: The expiration datetime if available, otherwise "Unknown".
        """
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            exp_timestamp = payload.get("exp")
            if exp_timestamp is not None:
                expiration = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
            else:
                # Handle missing 'exp' field by logging and setting expiration to "Unknown"
                log.warning("JWT payload does not contain 'exp' field.")
                expiration = "Unknown"
        except (DecodeError, TypeError):
            # Handle decoding errors by logging and setting expiration to "Unknown"
            log.exception("Failed to decode JWT for expiration.")
            expiration = "Unknown"

        return expiration

    def get_auth_header(self) -> dict:
        """Get the authorization header to use with authenticated requests."""
        if (
            self.token is None or self.is_token_expired(self.token)
        ) and not self._acquire_access_token_from_refresh_token():
            msg = "Access token expired and refresh token unavailable. Re-authentication required."
            raise ValueError(msg)
        return {"Authorization": f"Bearer {self.token}"}

    def refresh_token(self, username: str, password: str) -> None:
        """Reacquire and save a new access token, using refresh or username/password fallback."""
        if not self._acquire_access_token_from_refresh_token():
            log.warning("Re-authenticating with username and password due to missing refresh token.")
            self.token, self.refresh_token = self._acquire_tokens(username, password)
            self.save_tokens()
