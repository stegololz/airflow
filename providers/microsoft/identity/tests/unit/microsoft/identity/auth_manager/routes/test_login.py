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
import hashlib
import json
from unittest.mock import ANY, PropertyMock, patch
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
import requests

from airflow.api_fastapi.app import AUTH_MANAGER_FASTAPI_APP_PREFIX, get_auth_manager
from airflow.providers.microsoft.identity.auth_manager.adfs_auth_manager import AdfsAuthManager
from airflow.providers.microsoft.identity.auth_manager.constants import (
    CONF_LOGOUT_FROM_ADFS_KEY,
    CONF_SECTION_NAME,
    COOKIE_NAME_AUTH_REQUEST,
    COOKIE_NAME_ID_TOKEN,
    MAX_ID_TOKEN_COOKIE_LENGTH,
)
from airflow.providers.microsoft.identity.auth_manager.oidc import AdfsAuthenticationError
from airflow.providers.microsoft.identity.auth_manager.roles import AdfsAuthManagerRole
from airflow.providers.microsoft.identity.auth_manager.user import AdfsAuthManagerUser

from tests_common.test_utils.config import conf_vars
from unit.microsoft.identity.auth_manager.adfs_fixtures import BASE_URL, CLIENT_ID, METADATA, RESOURCE

LOGIN_CALLBACK_URL = f"{BASE_URL}{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login_callback"
LOGOUT_CALLBACK_URL = f"{BASE_URL}{AUTH_MANAGER_FASTAPI_APP_PREFIX}/logout_callback"
ID_TOKEN = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvcGFxdWUifQ.c2lnbmF0dXJl"
AUTH_REQUEST = {"state": "state", "nonce": "nonce", "code_verifier": "verifier", "next": None}
LOGIN_MODULE = "airflow.providers.microsoft.identity.auth_manager.routes.login"


def _encode_cookie(value) -> str:
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode()


def _decode_cookie(value: str):
    return json.loads(base64.urlsafe_b64decode(value))


def _get_set_cookie(response, name: str) -> str:
    return next(header for header in response.headers.get_list("set-cookie") if header.startswith(f"{name}="))


def _is_deleted(response, name: str) -> bool:
    return any(
        header.startswith(f'{name}=""') and "Max-Age=0" in header
        for header in response.headers.get_list("set-cookie")
    )


class TestLogin:
    def test_login(self, client, oidc_client):
        response = client.get(
            f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login", params={"next": "/dags"}, follow_redirects=False
        )

        assert response.status_code == 307
        assert response.headers["location"] == oidc_client.build_authorization_url.return_value
        auth_request = _decode_cookie(response.cookies[COOKIE_NAME_AUTH_REQUEST])
        assert auth_request["next"] == "/dags"
        code_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(auth_request["code_verifier"].encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        oidc_client.build_authorization_url.assert_called_once_with(
            redirect_uri=LOGIN_CALLBACK_URL,
            state=auth_request["state"],
            nonce=auth_request["nonce"],
            code_challenge=code_challenge,
        )
        assert auth_request["state"] != auth_request["nonce"]

    def test_login_sets_secure_cookie_over_https(self, client):
        response = client.get(
            f"https://testserver{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login", follow_redirects=False
        )

        set_cookie = _get_set_cookie(response, COOKIE_NAME_AUTH_REQUEST)
        assert "Secure" in set_cookie
        assert "HttpOnly" in set_cookie
        assert "SameSite=lax" in set_cookie
        assert "Max-Age=300" in set_cookie

    def test_login_deletes_stale_token(self, client):
        user = AdfsAuthManagerUser(
            user_id="jdoe@example.com", name="John Doe", role=AdfsAuthManagerRole.VIEWER
        )
        client.cookies.set("_token", get_auth_manager().generate_jwt(user))

        response = client.get(f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login", follow_redirects=False)

        assert response.status_code == 307
        assert _is_deleted(response, "_token")

    def test_login_without_token_does_not_delete_it(self, client):
        response = client.get(f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login", follow_redirects=False)

        assert not any(header.startswith("_token=") for header in response.headers.get_list("set-cookie"))

    def test_login_drops_unsafe_next(self, client):
        response = client.get(
            f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login",
            params={"next": "https://attacker.example.com/"},
            follow_redirects=False,
        )

        assert _decode_cookie(response.cookies[COOKIE_NAME_AUTH_REQUEST])["next"] is None

    @pytest.mark.parametrize(
        "error", [requests.ConnectionError("unreachable"), AdfsAuthenticationError("issuer mismatch")]
    )
    def test_login_discovery_failure(self, client, oidc_client, error):
        oidc_client.build_authorization_url.side_effect = error

        response = client.get(f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login", follow_redirects=False)

        assert response.status_code == 502


class TestLoginCallback:
    @staticmethod
    def _callback(client, *, auth_request=AUTH_REQUEST, cookie=None, **params):
        params = {"code": "code", "state": "state", **params}
        client.cookies.set(COOKIE_NAME_AUTH_REQUEST, cookie or _encode_cookie(auth_request))
        return client.get(
            f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login_callback", params=params, follow_redirects=False
        )

    @pytest.fixture
    def oidc_client(self, oidc_client):
        oidc_client.exchange_code.return_value = {"id_token": ID_TOKEN, "access_token": "access.token.value"}
        oidc_client.validate_id_token.return_value = {
            "sub": "opaque",
            "upn": "jdoe@example.com",
            "name": "John Doe",
            "role": "Airflow Admins",
        }
        return oidc_client

    def test_login_callback(self, client, oidc_client):
        response = self._callback(client, auth_request={**AUTH_REQUEST, "next": "/dags"})

        assert response.status_code == 303
        assert response.headers["location"] == "/dags"
        oidc_client.exchange_code.assert_called_once_with(
            code="code", redirect_uri=LOGIN_CALLBACK_URL, code_verifier="verifier"
        )
        oidc_client.validate_id_token.assert_called_once_with(ID_TOKEN, nonce="nonce")
        oidc_client.validate_access_token.assert_not_called()
        claims = jwt.decode(response.cookies["_token"], options={"verify_signature": False})
        assert (claims["sub"], claims["name"], claims["role"]) == ("jdoe@example.com", "John Doe", "ADMIN")
        assert response.cookies[COOKIE_NAME_ID_TOKEN] == ID_TOKEN
        assert "HttpOnly" in _get_set_cookie(response, "_token")
        assert "HttpOnly" in _get_set_cookie(response, COOKIE_NAME_ID_TOKEN)
        assert _is_deleted(response, COOKIE_NAME_AUTH_REQUEST)

    def test_login_callback_without_next_redirects_to_base_url(self, client):
        response = self._callback(client)

        assert response.status_code == 303
        assert response.headers["location"] == BASE_URL

    @pytest.mark.parametrize("next_url", ["https://attacker.example.com/", "//attacker.example.com", 42])
    def test_login_callback_drops_unsafe_next(self, client, next_url):
        response = self._callback(client, auth_request={**AUTH_REQUEST, "next": next_url})

        assert response.status_code == 303
        assert response.headers["location"] == BASE_URL

    @pytest.mark.parametrize(
        ("url", "config"),
        [
            pytest.param("https://testserver", {}, id="https"),
            pytest.param("http://testserver", {("api", "ssl_cert"): "/x.pem"}, id="ssl_cert"),
        ],
    )
    def test_login_callback_cookie_flags_when_secure(self, client, url, config):
        client.cookies.set(COOKIE_NAME_AUTH_REQUEST, _encode_cookie(AUTH_REQUEST))
        with conf_vars(config):
            response = client.get(
                f"{url}{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login_callback",
                params={"code": "code", "state": "state"},
                follow_redirects=False,
            )

        for name in ("_token", COOKIE_NAME_ID_TOKEN):
            set_cookie = _get_set_cookie(response, name)
            assert "Secure" in set_cookie
            assert "HttpOnly" in set_cookie
        assert "SameSite=lax" in _get_set_cookie(response, COOKIE_NAME_ID_TOKEN)

    @patch(f"{LOGIN_MODULE}.get_cookie_path", return_value="/airflow")
    def test_login_callback_sets_cookies_on_cookie_path(self, _, client):
        response = self._callback(client)

        for name in ("_token", COOKIE_NAME_ID_TOKEN):
            assert "Path=/airflow" in _get_set_cookie(response, name)
        assert "Path=/airflow" in _get_set_cookie(response, COOKIE_NAME_AUTH_REQUEST)
        assert _is_deleted(response, COOKIE_NAME_AUTH_REQUEST)

    def test_login_callback_uses_access_token_claims_with_resource(self, client, oidc_client):
        oidc_client.resource = RESOURCE
        oidc_client.validate_id_token.return_value = {"sub": "opaque", "upn": "jdoe@example.com"}
        oidc_client.validate_access_token.return_value = {
            "unique_name": "EXAMPLE\\jdoe",
            "role": "Airflow Operators",
        }

        response = self._callback(client)

        assert response.status_code == 303
        oidc_client.validate_access_token.assert_called_once_with("access.token.value")
        claims = jwt.decode(response.cookies["_token"], options={"verify_signature": False})
        assert (claims["sub"], claims["role"]) == ("jdoe@example.com", "OP")

    def test_login_callback_id_token_claims_take_precedence(self, client, oidc_client):
        oidc_client.resource = RESOURCE
        oidc_client.validate_id_token.return_value = {
            "sub": "opaque",
            "upn": "jdoe@example.com",
            "role": "Airflow Users",
        }
        oidc_client.validate_access_token.return_value = {
            "upn": "other@example.com",
            "role": "Airflow Admins",
        }

        response = self._callback(client)

        assert response.status_code == 303
        claims = jwt.decode(response.cookies["_token"], options={"verify_signature": False})
        assert (claims["sub"], claims["role"]) == ("jdoe@example.com", "USER")

    def test_login_callback_invalid_access_token(self, client, oidc_client):
        oidc_client.resource = RESOURCE
        oidc_client.validate_access_token.side_effect = jwt.InvalidAudienceError("aud")

        response = self._callback(client)

        assert response.status_code == 403
        assert response.json() == {"detail": "Authentication failed"}
        assert "_token" not in response.cookies

    @patch(f"{LOGIN_MODULE}.log", autospec=True)
    def test_login_callback_skips_oversized_id_token_cookie(self, mock_log, client, oidc_client):
        oidc_client.exchange_code.return_value = {"id_token": "a" * (MAX_ID_TOKEN_COOKIE_LENGTH + 1)}

        response = self._callback(client)

        assert response.status_code == 303
        assert "_token" in response.cookies
        assert COOKIE_NAME_ID_TOKEN not in response.cookies
        mock_log.warning.assert_called_once_with(ANY, "jdoe@example.com", MAX_ID_TOKEN_COOKIE_LENGTH + 1)

    @patch(f"{LOGIN_MODULE}.log", autospec=True)
    def test_login_callback_keeps_id_token_cookie_at_max_length(self, mock_log, client, oidc_client):
        id_token = "a" * MAX_ID_TOKEN_COOKIE_LENGTH
        oidc_client.exchange_code.return_value = {"id_token": id_token}

        response = self._callback(client)

        assert response.cookies[COOKIE_NAME_ID_TOKEN] == id_token
        mock_log.warning.assert_not_called()

    @conf_vars({(CONF_SECTION_NAME, CONF_LOGOUT_FROM_ADFS_KEY): "False"})
    def test_login_callback_without_adfs_logout_skips_id_token_cookie(self, client):
        response = self._callback(client)

        assert response.status_code == 303
        assert COOKIE_NAME_ID_TOKEN not in response.cookies

    @pytest.mark.parametrize(
        ("kwargs", "expected_status"),
        [
            ({"code": ""}, 400),
            ({"error": "access_denied"}, 403),
            ({"state": "other-state"}, 403),
            ({"state": ""}, 403),
            ({"cookie": "not-base64-json!"}, 403),
            ({"cookie": _encode_cookie(["state"])}, 403),
            ({"auth_request": {"state": "state", "nonce": "nonce"}}, 403),
        ],
    )
    def test_login_callback_invalid_request(self, client, oidc_client, kwargs, expected_status):
        response = self._callback(client, **kwargs)

        assert response.status_code == expected_status
        oidc_client.exchange_code.assert_not_called()

    def test_login_callback_without_cookie(self, client, oidc_client):
        response = client.get(
            f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login_callback",
            params={"code": "code", "state": "state"},
            follow_redirects=False,
        )

        assert response.status_code == 403
        oidc_client.exchange_code.assert_not_called()

    @pytest.mark.parametrize(
        ("method_name", "error", "expected_status", "expected_detail"),
        [
            (
                "exchange_code",
                AdfsAuthenticationError("rejected", error="invalid_grant"),
                403,
                "Authentication failed",
            ),
            ("exchange_code", requests.ConnectionError("unreachable"), 502, "Identity provider unavailable"),
            ("validate_id_token", jwt.InvalidAudienceError("aud"), 403, "Authentication failed"),
            (
                "validate_id_token",
                jwt.PyJWKClientConnectionError("keys"),
                502,
                "Identity provider unavailable",
            ),
        ],
    )
    def test_login_callback_failure(
        self, client, oidc_client, method_name, error, expected_status, expected_detail
    ):
        getattr(oidc_client, method_name).side_effect = error

        response = self._callback(client)

        assert response.status_code == expected_status
        assert response.json() == {"detail": expected_detail}
        assert "_token" not in response.cookies

    def test_login_callback_user_without_role(self, client, oidc_client):
        oidc_client.validate_id_token.return_value = {"sub": "opaque", "upn": "jdoe@example.com"}

        response = self._callback(client)

        assert response.status_code == 403
        assert response.json() == {"detail": "Not authorized to access Airflow"}
        assert "_token" not in response.cookies


class TestLogout:
    def test_logout(self, client):
        client.cookies.set(COOKIE_NAME_ID_TOKEN, ID_TOKEN)

        response = client.get(f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/logout", follow_redirects=False)

        assert response.status_code == 307
        location = urlsplit(response.headers["location"])
        assert f"{location.scheme}://{location.netloc}{location.path}" == METADATA["end_session_endpoint"]
        assert parse_qs(location.query) == {
            "post_logout_redirect_uri": [LOGOUT_CALLBACK_URL],
            "client_id": [CLIENT_ID],
            "id_token_hint": [ID_TOKEN],
        }
        assert _is_deleted(response, "_token")
        assert _is_deleted(response, COOKIE_NAME_ID_TOKEN)

    @pytest.mark.parametrize(("airflow_3_2_plus", "revoked"), [(True, True), (False, False)])
    @patch.object(AdfsAuthManager, "revoke_token", autospec=True)
    def test_logout_revokes_token(self, mock_revoke_token, client, airflow_3_2_plus, revoked):
        client.cookies.set("_token", "airflow-token")

        with patch(f"{LOGIN_MODULE}.AIRFLOW_V_3_2_PLUS", airflow_3_2_plus):
            response = client.get(f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/logout", follow_redirects=False)

        assert response.status_code == 307
        if revoked:
            mock_revoke_token.assert_called_once_with(ANY, "airflow-token")
        else:
            mock_revoke_token.assert_not_called()
        assert _is_deleted(response, "_token")

    @patch(f"{LOGIN_MODULE}.AIRFLOW_V_3_2_PLUS", True)
    @patch.object(AdfsAuthManager, "revoke_token", autospec=True)
    def test_logout_without_token_does_not_revoke(self, mock_revoke_token, client):
        response = client.get(f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/logout", follow_redirects=False)

        assert response.status_code == 307
        mock_revoke_token.assert_not_called()

    @pytest.mark.parametrize("id_token", [None, "not-a-jwt", f"{ID_TOKEN}&x=y"])
    def test_logout_without_valid_id_token(self, client, id_token):
        if id_token:
            client.cookies.set(COOKIE_NAME_ID_TOKEN, id_token)

        response = client.get(f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/logout", follow_redirects=False)

        assert response.status_code == 307
        assert parse_qs(urlsplit(response.headers["location"]).query) == {
            "post_logout_redirect_uri": [LOGOUT_CALLBACK_URL],
            "client_id": [CLIENT_ID],
        }

    @conf_vars({(CONF_SECTION_NAME, CONF_LOGOUT_FROM_ADFS_KEY): "False"})
    def test_logout_without_adfs_logout(self, client):
        response = client.get(f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/logout", follow_redirects=False)

        assert response.status_code == 307
        assert response.headers["location"] == LOGOUT_CALLBACK_URL
        assert _is_deleted(response, "_token")

    def test_logout_without_end_session_endpoint(self, client, oidc_client):
        oidc_client.end_session_endpoint = None

        response = client.get(f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/logout", follow_redirects=False)

        assert response.headers["location"] == LOGOUT_CALLBACK_URL

    def test_logout_discovery_failure(self, client, oidc_client):
        type(oidc_client).end_session_endpoint = PropertyMock(side_effect=requests.ConnectionError("down"))

        response = client.get(f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/logout", follow_redirects=False)

        assert response.status_code == 307
        assert response.headers["location"] == LOGOUT_CALLBACK_URL
        assert _is_deleted(response, "_token")


def test_logout_callback(client):
    response = client.get(f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/logout_callback", follow_redirects=False)

    assert response.status_code == 307
    assert response.headers["location"] == f"{BASE_URL}{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login"
    for cookie_name in ("_token", COOKIE_NAME_ID_TOKEN, COOKIE_NAME_AUTH_REQUEST):
        assert _is_deleted(response, cookie_name)


@pytest.mark.parametrize(
    ("route", "cookie_names"),
    [
        ("logout", ("_token", COOKIE_NAME_ID_TOKEN)),
        ("logout_callback", ("_token", COOKIE_NAME_ID_TOKEN, COOKIE_NAME_AUTH_REQUEST)),
    ],
)
@patch(f"{LOGIN_MODULE}.get_cookie_path", return_value="/airflow")
def test_logout_deletes_cookies_on_cookie_path(_, client, route, cookie_names):
    response = client.get(
        f"https://testserver{AUTH_MANAGER_FASTAPI_APP_PREFIX}/{route}", follow_redirects=False
    )

    for name in cookie_names:
        set_cookie = _get_set_cookie(response, name)
        assert _is_deleted(response, name)
        assert "Path=/airflow" in set_cookie
        assert "Secure" in set_cookie
        assert "HttpOnly" in set_cookie
