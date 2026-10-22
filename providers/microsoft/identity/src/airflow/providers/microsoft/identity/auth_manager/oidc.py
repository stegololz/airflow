# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""OpenID Connect client for Microsoft AD FS."""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets
import ssl
from collections.abc import Sequence
from functools import cached_property
from typing import Any
from urllib.parse import urlencode

import jwt
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

log = logging.getLogger(__name__)

# AD FS signs tokens with RS256 only. Pinning the algorithm also rules out ``none`` and
# HMAC/RSA key confusion.
SIGNING_ALGORITHMS = ["RS256"]

_REQUIRED_METADATA_KEYS = ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri")


class AdfsAuthenticationError(ValueError):
    """
    AD FS rejected the request or returned a response that cannot be used to log the user in.

    :param message: description of the failure, safe to log
    :param error: OAuth 2.0 ``error`` code returned by AD FS, if any
    """

    def __init__(self, message: str, *, error: str | None = None) -> None:
        super().__init__(message)
        self.error = error


def create_pkce_pair() -> tuple[str, str]:
    """
    Create a PKCE code verifier and its ``S256`` code challenge (RFC 7636).

    :return: a ``(code_verifier, code_challenge)`` tuple
    """
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


class AdfsOidcClient:
    """
    Minimal OpenID Connect relying party for AD FS, using the authorization code flow with PKCE.

    All endpoints are read from the discovery document of the issuer. The user information
    endpoint is never used: AD FS only returns ``sub`` from it, so the user identity is read from
    the validated tokens instead.

    :param issuer: AD FS issuer URL, e.g. ``https://adfs.example.com/adfs``
    :param client_id: client identifier of the Airflow application in AD FS
    :param client_secret: client secret, or ``None`` for a public client
    :param scope: space-separated scopes to request
    :param resource: identifier of the AD FS Web API to request an access token for, or ``None``
    :param access_token_issuers: accepted ``iss`` values for access tokens; when empty, the
        ``issuer`` and ``access_token_issuer`` values of the discovery document are accepted
    :param leeway_seconds: clock skew tolerated when validating token timestamps
    :param ca_bundle_path: CA bundle used to verify the AD FS TLS certificate, or ``None`` for the
        ``REQUESTS_CA_BUNDLE`` environment variable or the ``certifi`` bundle
    :param request_timeout_seconds: timeout of the HTTP requests made to AD FS
    :param jwks_cache_ttl_seconds: time during which the signing keys are cached
    """

    def __init__(
        self,
        *,
        issuer: str,
        client_id: str,
        client_secret: str | None,
        scope: str,
        resource: str | None,
        access_token_issuers: Sequence[str],
        leeway_seconds: int,
        ca_bundle_path: str | None,
        request_timeout_seconds: int,
        jwks_cache_ttl_seconds: int,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret or None
        self.scope = scope
        self.resource = resource or None
        self.access_token_issuers = list(access_token_issuers)
        self.leeway_seconds = leeway_seconds
        self.ca_bundle_path = ca_bundle_path or None
        self.request_timeout_seconds = request_timeout_seconds
        self.jwks_cache_ttl_seconds = jwks_cache_ttl_seconds
        self._metadata: dict[str, Any] | None = None

    @cached_property
    def http_session(self) -> requests.Session:
        """Return the HTTP session used to call AD FS."""
        session = requests.Session()
        # Only idempotent requests are retried: an authorization code can be redeemed once, so a
        # retried token request would fail with ``invalid_grant`` even if the first one succeeded.
        retry = Retry(
            total=3,
            backoff_factor=0.1,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET"],
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    @property
    def _verify(self) -> str | bool:
        """
        Return the ``verify`` argument of the requests made to AD FS.

        It is passed on each request because ``REQUESTS_CA_BUNDLE`` takes precedence over
        ``Session.verify``.

        :meta private:
        """
        return self.ca_bundle_path or True

    @property
    def metadata(self) -> dict[str, Any]:
        """
        Return the OpenID Connect discovery document of the issuer.

        The document is fetched on first use and cached only once it has been validated, so that an
        AD FS outage while Airflow starts does not prevent later logins.
        """
        if self._metadata is None:
            response = self.http_session.get(
                f"{self.issuer}/.well-known/openid-configuration",
                timeout=self.request_timeout_seconds,
                verify=self._verify,
            )
            response.raise_for_status()
            metadata = response.json()
            if not isinstance(metadata, dict):
                raise AdfsAuthenticationError("The AD FS discovery document is not a JSON object")
            missing = [key for key in _REQUIRED_METADATA_KEYS if not metadata.get(key)]
            if missing:
                raise AdfsAuthenticationError(f"The AD FS discovery document is missing {', '.join(missing)}")
            # OpenID Connect Discovery 1.0, section 4.3: the issuer in the document must be identical
            # to the URL the document was retrieved from.
            if str(metadata["issuer"]).rstrip("/") != self.issuer:
                raise AdfsAuthenticationError(
                    "The issuer of the AD FS discovery document does not match the configured issuer"
                )
            self._metadata = metadata
        return self._metadata

    @property
    def end_session_endpoint(self) -> str | None:
        """Return the AD FS logout endpoint, if AD FS advertises one."""
        return self.metadata.get("end_session_endpoint")

    @cached_property
    def _jwks_client(self) -> jwt.PyJWKClient:
        """
        Return the client fetching the AD FS token signing keys.

        ``PyJWKClient`` fetches the key set again when a token is signed with an unknown key, which
        happens when AD FS rolls its token signing certificate over. Only the key set is cached, so a
        key removed from AD FS stops being trusted once the cache expires.

        :meta private:
        """
        return jwt.PyJWKClient(
            self.metadata["jwks_uri"],
            cache_keys=False,
            lifespan=self.jwks_cache_ttl_seconds,
            timeout=self.request_timeout_seconds,
            ssl_context=self._get_ssl_context(),
        )

    def _get_ssl_context(self) -> ssl.SSLContext:
        """
        Return an SSL context trusting the same certificates as :attr:`http_session`.

        :meta private:
        """
        ca_bundle = (
            self.ca_bundle_path
            or os.environ.get("REQUESTS_CA_BUNDLE")
            or os.environ.get("CURL_CA_BUNDLE")
            or requests.utils.DEFAULT_CA_BUNDLE_PATH
        )
        if os.path.isdir(ca_bundle):
            return ssl.create_default_context(capath=ca_bundle)
        return ssl.create_default_context(cafile=ca_bundle)

    def build_authorization_url(
        self, *, redirect_uri: str, state: str, nonce: str, code_challenge: str
    ) -> str:
        """
        Build the URL of the AD FS authorization endpoint to redirect the user to.

        :param redirect_uri: URL AD FS redirects the user back to; must be registered in AD FS
        :param state: opaque value bound to the browser session, protecting against CSRF
        :param nonce: value AD FS copies into the ID token, protecting against token replay
        :param code_challenge: PKCE ``S256`` code challenge
        """
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": self.scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        if self.resource:
            params["resource"] = self.resource
        endpoint = self.metadata["authorization_endpoint"]
        separator = "&" if "?" in endpoint else "?"
        return f"{endpoint}{separator}{urlencode(params)}"

    def exchange_code(self, *, code: str, redirect_uri: str, code_verifier: str) -> dict[str, Any]:
        """
        Redeem an authorization code at the AD FS token endpoint.

        :param code: authorization code returned by AD FS
        :param redirect_uri: redirect URI used in the authorization request
        :param code_verifier: PKCE code verifier matching the code challenge
        :return: the token response, containing at least ``id_token``
        """
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.client_id,
            "code_verifier": code_verifier,
        }
        if self.client_secret:
            data["client_secret"] = self.client_secret
        if self.resource:
            data["resource"] = self.resource
        response = self.http_session.post(
            self.metadata["token_endpoint"],
            data=data,
            timeout=self.request_timeout_seconds,
            verify=self._verify,
        )
        if not response.ok:
            error, description = self._get_oauth_error(response)
            log.warning("AD FS token endpoint returned HTTP %s, error: %s", response.status_code, error)
            log.debug("AD FS token endpoint error description: %s", description)
            raise AdfsAuthenticationError("AD FS rejected the authorization code", error=error)
        tokens = response.json()
        if not isinstance(tokens, dict) or not isinstance(tokens.get("id_token"), str):
            raise AdfsAuthenticationError("The AD FS token response does not contain an ID token")
        return tokens

    def validate_id_token(self, id_token: str, *, nonce: str) -> dict[str, Any]:
        """
        Validate an ID token and return its claims.

        :param id_token: ID token returned by the token endpoint
        :param nonce: nonce sent in the authorization request
        """
        claims = jwt.decode(
            id_token,
            self._jwks_client.get_signing_key_from_jwt(id_token).key,
            algorithms=SIGNING_ALGORITHMS,
            audience=self.client_id,
            issuer=self.metadata["issuer"],
            leeway=self.leeway_seconds,
            options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce"]},
        )
        token_nonce = claims["nonce"]
        if not isinstance(token_nonce, str) or not secrets.compare_digest(
            token_nonce.encode(), nonce.encode()
        ):
            raise jwt.InvalidTokenError("The ID token nonce does not match the authorization request")
        return claims

    def validate_access_token(self, access_token: str) -> dict[str, Any]:
        """
        Validate an access token issued for :attr:`resource` and return its claims.

        ``sub`` is not required: AD FS access tokens may identify the user with ``unique_name`` or
        ``upn`` only.

        :param access_token: access token returned by the token endpoint
        """
        if not self.resource:
            raise ValueError("An access token can only be validated when a resource is configured")
        return jwt.decode(
            access_token,
            self._jwks_client.get_signing_key_from_jwt(access_token).key,
            algorithms=SIGNING_ALGORITHMS,
            audience=self.resource,
            issuer=self.get_access_token_issuers(),
            leeway=self.leeway_seconds,
            options={"require": ["exp", "iss", "aud"]},
        )

    def get_access_token_issuers(self) -> list[str]:
        """
        Return the accepted ``iss`` values for access tokens.

        AD FS issues access tokens with ``http://<host>/adfs/services/trust``, which differs from the
        OpenID Connect issuer, and advertises it as ``access_token_issuer`` in its discovery document.
        """
        if self.access_token_issuers:
            return self.access_token_issuers
        issuers = [self.metadata["issuer"]]
        if access_token_issuer := self.metadata.get("access_token_issuer"):
            issuers.append(access_token_issuer)
        return issuers

    @staticmethod
    def _get_oauth_error(response: requests.Response) -> tuple[str | None, str | None]:
        """
        Extract the OAuth 2.0 ``error`` and ``error_description`` from an error response.

        :meta private:
        """
        try:
            body = response.json()
        except ValueError:
            return None, None
        if not isinstance(body, dict):
            return None, None
        return body.get("error"), body.get("error_description")
