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

from __future__ import annotations

import base64
import json
import logging
import re
import secrets
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlencode, urljoin

import jwt
import requests
from fastapi import HTTPException, Request
from fastapi.responses import RedirectResponse

from airflow.api_fastapi.app import AUTH_MANAGER_FASTAPI_APP_PREFIX, get_auth_manager
from airflow.api_fastapi.auth.managers.base_auth_manager import COOKIE_NAME_JWT_TOKEN
from airflow.api_fastapi.common.router import AirflowRouter
from airflow.api_fastapi.core_api.security import is_safe_url
from airflow.providers.common.compat.sdk import conf
from airflow.providers.microsoft.identity.auth_manager.constants import (
    AUTH_REQUEST_COOKIE_MAX_AGE,
    CONF_LOGOUT_FROM_ADFS_KEY,
    CONF_SECTION_NAME,
    COOKIE_NAME_AUTH_REQUEST,
    COOKIE_NAME_ID_TOKEN,
    MAX_ID_TOKEN_COOKIE_LENGTH,
)
from airflow.providers.microsoft.identity.auth_manager.oidc import AdfsAuthenticationError, create_pkce_pair
from airflow.providers.microsoft.identity.version_compat import (
    AIRFLOW_V_3_1_1_PLUS,
    AIRFLOW_V_3_1_8_PLUS,
    AIRFLOW_V_3_2_PLUS,
)

if AIRFLOW_V_3_1_8_PLUS:
    from airflow.api_fastapi.app import get_cookie_path
else:
    get_cookie_path = lambda: "/"

if TYPE_CHECKING:
    from starlette.responses import Response

    from airflow.providers.microsoft.identity.auth_manager.adfs_auth_manager import AdfsAuthManager

log = logging.getLogger(__name__)
login_router = AirflowRouter(tags=["AdfsAuthManagerLogin"])

_JWT_PATTERN = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_AUTH_REQUEST_KEYS = ("state", "nonce", "code_verifier")


def _get_auth_manager() -> AdfsAuthManager:
    return cast("AdfsAuthManager", get_auth_manager())


def _get_redirect_uri(request: Request, route_name: str) -> str:
    """
    Build the URL AD FS redirects the browser back to.

    Prefer the configured public base URL so the value handed to AD FS does not depend on the request
    ``Host``/``X-Forwarded-Host`` headers, which are attacker-controlled when the API server runs with
    ``--proxy-headers``. AD FS also requires an exact match with a registered redirect URI. Fall back to
    the request URL when ``base_url`` is not configured.

    :meta private:
    """
    base_url = conf.get("api", "base_url", fallback=None)
    if base_url:
        return urljoin(base_url, f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/{route_name}")
    return str(request.url_for(route_name))


def _is_secure(request: Request) -> bool:
    return request.base_url.scheme == "https" or bool(conf.get("api", "ssl_cert", fallback=""))


def _get_safe_next_url(request: Request, next_url: Any) -> str | None:
    if isinstance(next_url, str) and next_url and is_safe_url(next_url, request=request):
        return next_url
    return None


def _encode_auth_request(auth_request: dict[str, str | None]) -> str:
    return base64.urlsafe_b64encode(json.dumps(auth_request).encode()).decode("ascii")


def _get_auth_request(request: Request) -> dict[str, Any] | None:
    """
    Return the authorization request stored in the browser by ``/login``, or ``None`` if it is invalid.

    :meta private:
    """
    raw = request.cookies.get(COOKIE_NAME_AUTH_REQUEST)
    if not raw:
        return None
    try:
        auth_request = json.loads(base64.urlsafe_b64decode(raw.encode("ascii")))
    except ValueError:
        return None
    if not isinstance(auth_request, dict) or not all(
        isinstance(auth_request.get(key), str) and auth_request[key] for key in _AUTH_REQUEST_KEYS
    ):
        return None
    return auth_request


def _delete_cookie(response: Response, key: str, request: Request) -> None:
    response.delete_cookie(key=key, path=get_cookie_path(), secure=_is_secure(request), httponly=True)


@login_router.get("/login")
def login(request: Request, next: str | None = None) -> RedirectResponse:
    """Redirect the user to AD FS to authenticate."""
    client = _get_auth_manager().get_oidc_client()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier, code_challenge = create_pkce_pair()
    try:
        authorization_url = client.build_authorization_url(
            redirect_uri=_get_redirect_uri(request, "login_callback"),
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
        )
    except (requests.RequestException, AdfsAuthenticationError):
        log.exception("Could not read the AD FS discovery document")
        raise HTTPException(status_code=502, detail="Identity provider unavailable")

    response = RedirectResponse(authorization_url, status_code=307)
    response.set_cookie(
        COOKIE_NAME_AUTH_REQUEST,
        _encode_auth_request(
            {
                "state": state,
                "nonce": nonce,
                "code_verifier": code_verifier,
                "next": _get_safe_next_url(request, next),
            }
        ),
        max_age=AUTH_REQUEST_COOKIE_MAX_AGE,
        path=get_cookie_path(),
        secure=_is_secure(request),
        httponly=True,
        # AD FS redirects back with a top-level GET, for which ``lax`` cookies are sent.
        samesite="lax",
    )
    # A stale token sent to the callback makes the core JWT refresh middleware delete the new one.
    if COOKIE_NAME_JWT_TOKEN in request.cookies:
        _delete_cookie(response, COOKIE_NAME_JWT_TOKEN, request)
    return response


@login_router.get("/login_callback")
def login_callback(
    request: Request, code: str | None = None, state: str | None = None, error: str | None = None
) -> RedirectResponse:
    """Complete the authentication once AD FS redirects the user back to Airflow."""
    if error:
        log.info("AD FS returned an authorization error: %r", error[:100])
        raise HTTPException(status_code=403, detail="Authentication failed")
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")
    auth_request = _get_auth_request(request)
    if (
        auth_request is None
        or not state
        or not secrets.compare_digest(state.encode(), auth_request["state"].encode())
    ):
        raise HTTPException(status_code=403, detail="Invalid OAuth state parameter")

    auth_manager = _get_auth_manager()
    client = auth_manager.get_oidc_client()
    try:
        tokens = client.exchange_code(
            code=code,
            redirect_uri=_get_redirect_uri(request, "login_callback"),
            code_verifier=auth_request["code_verifier"],
        )
        claims = client.validate_id_token(tokens["id_token"], nonce=auth_request["nonce"])
        if client.resource:
            # ID token claims take precedence: the ID token is bound to this client and this login.
            claims = {**client.validate_access_token(tokens.get("access_token", "")), **claims}
        user = auth_manager.get_user_from_claims(claims)
    except (requests.RequestException, jwt.PyJWKClientConnectionError):
        log.exception("Could not reach AD FS to complete the login")
        raise HTTPException(status_code=502, detail="Identity provider unavailable")
    except (jwt.PyJWTError, AdfsAuthenticationError) as e:
        log.warning("AD FS login rejected: %s", e)
        raise HTTPException(status_code=403, detail="Authentication failed")
    except PermissionError:
        raise HTTPException(status_code=403, detail="Not authorized to access Airflow")

    token = auth_manager.generate_jwt(user)
    redirect_url = _get_safe_next_url(request, auth_request.get("next")) or conf.get(
        "api", "base_url", fallback="/"
    )
    response = RedirectResponse(url=redirect_url, status_code=303)
    secure = _is_secure(request)
    cookie_path = get_cookie_path()
    # In Airflow 3.1.1 authentication changes, front-end no longer handle the token
    # See https://github.com/apache/airflow/pull/55506
    if AIRFLOW_V_3_1_1_PLUS:
        response.set_cookie(COOKIE_NAME_JWT_TOKEN, token, path=cookie_path, secure=secure, httponly=True)
    else:
        response.set_cookie(COOKIE_NAME_JWT_TOKEN, token, path=cookie_path, secure=secure)

    id_token = tokens["id_token"]
    if conf.getboolean(CONF_SECTION_NAME, CONF_LOGOUT_FROM_ADFS_KEY, fallback=True):
        if len(id_token) <= MAX_ID_TOKEN_COOKIE_LENGTH:
            response.set_cookie(
                COOKIE_NAME_ID_TOKEN, id_token, path=cookie_path, secure=secure, httponly=True, samesite="lax"
            )
        else:
            log.warning(
                "The AD FS ID token of user %s is %d characters long, too long to keep for the logout: "
                "AD FS will not redirect back to Airflow after logout. Issue fewer group claims.",
                user.user_id,
                len(id_token),
            )
    _delete_cookie(response, COOKIE_NAME_AUTH_REQUEST, request)
    return response


@login_router.get("/logout")
def logout(request: Request) -> RedirectResponse:
    """Log the user out of AD FS, then redirect to ``/logout_callback``."""
    auth_manager = _get_auth_manager()
    if AIRFLOW_V_3_2_PLUS and (token := request.cookies.get(COOKIE_NAME_JWT_TOKEN)):
        auth_manager.revoke_token(token)
    logout_callback_url = _get_redirect_uri(request, "logout_callback")
    redirect_url = logout_callback_url
    if conf.getboolean(CONF_SECTION_NAME, CONF_LOGOUT_FROM_ADFS_KEY, fallback=True):
        client = auth_manager.get_oidc_client()
        try:
            end_session_endpoint = client.end_session_endpoint
        except (requests.RequestException, AdfsAuthenticationError) as e:
            # The Airflow cookies are still deleted below, only the AD FS session is kept.
            log.warning("Could not read the AD FS discovery document, logging out of Airflow only: %s", e)
            end_session_endpoint = None
        if end_session_endpoint:
            params = {"post_logout_redirect_uri": logout_callback_url, "client_id": client.client_id}
            id_token = request.cookies.get(COOKIE_NAME_ID_TOKEN)
            if id_token and _JWT_PATTERN.fullmatch(id_token):
                params["id_token_hint"] = id_token
            separator = "&" if "?" in end_session_endpoint else "?"
            redirect_url = f"{end_session_endpoint}{separator}{urlencode(params)}"

    response = RedirectResponse(redirect_url, status_code=307)
    _delete_cookie(response, COOKIE_NAME_JWT_TOKEN, request)
    _delete_cookie(response, COOKIE_NAME_ID_TOKEN, request)
    return response


@login_router.get("/logout_callback")
def logout_callback(request: Request) -> RedirectResponse:
    """
    Complete the log-out.

    AD FS redirects the user to this route once logged out of AD FS.
    """
    response = RedirectResponse(_get_auth_manager().get_url_login(), status_code=307)
    for cookie_name in (COOKIE_NAME_JWT_TOKEN, COOKIE_NAME_ID_TOKEN, COOKIE_NAME_AUTH_REQUEST):
        _delete_cookie(response, cookie_name, request)
    return response
