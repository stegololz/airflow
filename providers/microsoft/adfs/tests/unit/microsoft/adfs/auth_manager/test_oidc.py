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
import time
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
import requests
import time_machine
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import PyJWKClient

from airflow.providers.microsoft.adfs.auth_manager.oidc import (
    AdfsAuthenticationError,
    AdfsOidcClient,
    create_pkce_pair,
)

from unit.microsoft.adfs.auth_manager.adfs_fixtures import (
    ACCESS_TOKEN_ISSUER,
    CLIENT_ID,
    ISSUER,
    JWKS_URI,
    METADATA,
    NONCE,
    NOW,
    RESOURCE,
    build_jwk,
)

OIDC_MODULE = "airflow.providers.microsoft.adfs.auth_manager.oidc"


def _response(*, status_code: int = 200, json_data=None) -> Mock:
    response = Mock(spec=requests.Response)
    response.status_code = status_code
    response.ok = status_code < 400
    response.json.return_value = json_data
    if status_code >= 400:
        response.raise_for_status.side_effect = requests.HTTPError(f"{status_code} error")
    return response


def _build_client(**kwargs) -> AdfsOidcClient:
    params = {
        "issuer": ISSUER,
        "client_id": CLIENT_ID,
        "client_secret": None,
        "scope": "openid profile email allatclaims",
        "resource": None,
        "access_token_issuers": [],
        "leeway_seconds": 30,
        "ca_bundle_path": None,
        "request_timeout_seconds": 10,
        "jwks_cache_ttl_seconds": 300,
        **kwargs,
    }
    client = AdfsOidcClient(**params)
    client.http_session = Mock(spec=requests.Session)
    client.http_session.get.return_value = _response(json_data=METADATA)
    return client


@pytest.fixture
def client():
    return _build_client()


@pytest.fixture
def client_with_resource():
    return _build_client(resource=RESOURCE)


@pytest.fixture
def mock_fetch_jwks(jwks):
    with patch.object(PyJWKClient, "fetch_data", autospec=True, return_value=jwks) as mock_fetch:
        yield mock_fetch


@pytest.fixture(autouse=True)
def frozen_time():
    with time_machine.travel(NOW, tick=False):
        yield


def test_create_pkce_pair():
    code_verifier, code_challenge = create_pkce_pair()

    assert 43 <= len(code_verifier) <= 128
    expected = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=")
    assert code_challenge == expected.decode()


class TestDiscovery:
    def test_metadata_is_fetched_once(self, client):
        assert client.metadata == METADATA
        assert client.metadata == METADATA

        client.http_session.get.assert_called_once_with(
            f"{ISSUER}/.well-known/openid-configuration", timeout=10, verify=True
        )

    def test_configured_issuer_trailing_slash_is_ignored(self):
        client = _build_client(issuer=f"{ISSUER}/")

        assert client.metadata["issuer"] == ISSUER
        client.http_session.get.assert_called_once_with(
            f"{ISSUER}/.well-known/openid-configuration", timeout=10, verify=True
        )

    def test_issuer_mismatch_is_rejected(self, client):
        client.http_session.get.return_value = _response(
            json_data={**METADATA, "issuer": "https://other.example.com/adfs"}
        )

        with pytest.raises(AdfsAuthenticationError, match="does not match"):
            client.metadata

    def test_missing_endpoint_is_rejected(self, client):
        metadata = {key: value for key, value in METADATA.items() if key != "jwks_uri"}
        client.http_session.get.return_value = _response(json_data=metadata)

        with pytest.raises(AdfsAuthenticationError, match="jwks_uri"):
            client.metadata

    def test_failure_is_not_cached(self, client):
        client.http_session.get.side_effect = [_response(status_code=503), _response(json_data=METADATA)]

        with pytest.raises(requests.HTTPError):
            client.metadata
        assert client.metadata == METADATA

    def test_end_session_endpoint(self, client):
        assert client.end_session_endpoint == METADATA["end_session_endpoint"]

    def test_ca_bundle_takes_precedence_over_environment(self, monkeypatch):
        monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/etc/ssl/other.pem")
        client = _build_client(ca_bundle_path="/etc/ssl/internal-ca.pem")
        client.http_session.post.return_value = _response(json_data={"id_token": "id.token.value"})

        client.metadata
        client.exchange_code(code="code", redirect_uri="https://redirect", code_verifier="verifier")

        assert client.http_session.get.call_args.kwargs["verify"] == "/etc/ssl/internal-ca.pem"
        assert client.http_session.post.call_args.kwargs["verify"] == "/etc/ssl/internal-ca.pem"

    def test_http_session_retries_only_idempotent_requests(self):
        client = AdfsOidcClient(
            issuer=ISSUER,
            client_id=CLIENT_ID,
            client_secret=None,
            scope="openid",
            resource=None,
            access_token_issuers=[],
            leeway_seconds=30,
            ca_bundle_path=None,
            request_timeout_seconds=10,
            jwks_cache_ttl_seconds=300,
        )

        retry = client.http_session.get_adapter(ISSUER).max_retries

        assert "GET" in retry.allowed_methods
        assert "POST" not in retry.allowed_methods
        assert 503 in retry.status_forcelist

    @patch(f"{OIDC_MODULE}.ssl.create_default_context", autospec=True)
    def test_jwks_client(self, mock_create_default_context):
        client = _build_client(ca_bundle_path="/etc/ssl/internal-ca.pem", request_timeout_seconds=7)

        jwks_client = client._jwks_client

        mock_create_default_context.assert_called_once_with(cafile="/etc/ssl/internal-ca.pem")
        assert jwks_client.ssl_context is mock_create_default_context.return_value
        assert jwks_client.uri == JWKS_URI
        assert jwks_client.timeout == 7


class TestGetSslContext:
    @pytest.fixture(autouse=True)
    def mock_create_default_context(self, monkeypatch):
        monkeypatch.delenv("REQUESTS_CA_BUNDLE", raising=False)
        monkeypatch.delenv("CURL_CA_BUNDLE", raising=False)
        with patch(f"{OIDC_MODULE}.ssl.create_default_context", autospec=True) as mock_create:
            yield mock_create

    @pytest.mark.parametrize(
        ("ca_bundle_path", "env", "expected_cafile"),
        [
            pytest.param(
                "/etc/ssl/ca.pem",
                {"REQUESTS_CA_BUNDLE": "/requests.pem", "CURL_CA_BUNDLE": "/curl.pem"},
                "/etc/ssl/ca.pem",
                id="ca_bundle_path",
            ),
            pytest.param(
                None,
                {"REQUESTS_CA_BUNDLE": "/requests.pem", "CURL_CA_BUNDLE": "/curl.pem"},
                "/requests.pem",
                id="requests_ca_bundle",
            ),
            pytest.param(None, {"CURL_CA_BUNDLE": "/curl.pem"}, "/curl.pem", id="curl_ca_bundle"),
            pytest.param(None, {}, requests.utils.DEFAULT_CA_BUNDLE_PATH, id="certifi"),
        ],
    )
    def test_cafile(self, monkeypatch, mock_create_default_context, ca_bundle_path, env, expected_cafile):
        for name, value in env.items():
            monkeypatch.setenv(name, value)
        client = _build_client(ca_bundle_path=ca_bundle_path)

        assert client._get_ssl_context() is mock_create_default_context.return_value
        mock_create_default_context.assert_called_once_with(cafile=expected_cafile)

    def test_directory_is_capath(self, mock_create_default_context, tmp_path):
        client = _build_client(ca_bundle_path=str(tmp_path))

        client._get_ssl_context()

        mock_create_default_context.assert_called_once_with(capath=str(tmp_path))


class TestBuildAuthorizationUrl:
    @pytest.mark.parametrize(("resource", "expected_resource"), [(None, None), (RESOURCE, [RESOURCE])])
    def test_build_authorization_url(self, resource, expected_resource):
        client = _build_client(resource=resource)

        url = client.build_authorization_url(
            redirect_uri="https://airflow.example.com/auth/login_callback",
            state="state",
            nonce="nonce",
            code_challenge="challenge",
        )

        split_url = urlsplit(url)
        assert (
            f"{split_url.scheme}://{split_url.netloc}{split_url.path}" == METADATA["authorization_endpoint"]
        )
        params = parse_qs(split_url.query)
        assert params.pop("resource", None) == expected_resource
        assert params == {
            "response_type": ["code"],
            "client_id": [CLIENT_ID],
            "redirect_uri": ["https://airflow.example.com/auth/login_callback"],
            "scope": ["openid profile email allatclaims"],
            "state": ["state"],
            "nonce": ["nonce"],
            "code_challenge": ["challenge"],
            "code_challenge_method": ["S256"],
        }


class TestExchangeCode:
    @pytest.mark.parametrize(
        ("client_secret", "resource", "expected_extra"),
        [
            (None, None, {}),
            ("secret", None, {"client_secret": "secret"}),
            (None, RESOURCE, {"resource": RESOURCE}),
        ],
    )
    def test_exchange_code(self, client_secret, resource, expected_extra):
        client = _build_client(client_secret=client_secret, resource=resource)
        tokens = {"id_token": "id.token.value", "access_token": "access.token.value"}
        client.http_session.post.return_value = _response(json_data=tokens)

        result = client.exchange_code(code="code", redirect_uri="https://redirect", code_verifier="verifier")

        assert result == tokens
        client.http_session.post.assert_called_once_with(
            METADATA["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": "code",
                "redirect_uri": "https://redirect",
                "client_id": CLIENT_ID,
                "code_verifier": "verifier",
                **expected_extra,
            },
            timeout=10,
            verify=True,
        )

    def test_error_response(self, client):
        client.http_session.post.return_value = _response(
            status_code=400, json_data={"error": "invalid_grant", "error_description": "MSIS9612: expired"}
        )

        with pytest.raises(AdfsAuthenticationError) as ctx:
            client.exchange_code(code="code", redirect_uri="https://redirect", code_verifier="verifier")

        assert ctx.value.error == "invalid_grant"

    def test_error_response_without_json_body(self, client):
        response = _response(status_code=500)
        response.json.side_effect = requests.JSONDecodeError("Expecting value", "", 0)
        client.http_session.post.return_value = response

        with pytest.raises(AdfsAuthenticationError) as ctx:
            client.exchange_code(code="code", redirect_uri="https://redirect", code_verifier="verifier")

        assert ctx.value.error is None

    def test_response_without_id_token(self, client):
        client.http_session.post.return_value = _response(json_data={"access_token": "access.token.value"})

        with pytest.raises(AdfsAuthenticationError, match="ID token"):
            client.exchange_code(code="code", redirect_uri="https://redirect", code_verifier="verifier")

    def test_connection_error_propagates(self, client):
        client.http_session.post.side_effect = requests.ConnectionError("unreachable")

        with pytest.raises(requests.ConnectionError):
            client.exchange_code(code="code", redirect_uri="https://redirect", code_verifier="verifier")


@pytest.mark.usefixtures("mock_fetch_jwks")
class TestValidateIdToken:
    def test_valid_token(self, client, make_token, id_token_claims):
        claims = client.validate_id_token(make_token(id_token_claims), nonce=NONCE)

        assert claims == id_token_claims

    @pytest.mark.parametrize(
        ("overrides", "expected_error"),
        [
            ({"aud": "another-client"}, jwt.InvalidAudienceError),
            ({"iss": ACCESS_TOKEN_ISSUER}, jwt.InvalidIssuerError),
            ({"exp": NOW - 31}, jwt.ExpiredSignatureError),
            ({"nonce": "replayed-nonce"}, jwt.InvalidTokenError),
            ({"nonce": 42}, jwt.InvalidTokenError),
            ({"nonce": None}, jwt.MissingRequiredClaimError),
            ({"sub": None}, jwt.MissingRequiredClaimError),
        ],
    )
    def test_invalid_claims_are_rejected(
        self, client, make_token, id_token_claims, overrides, expected_error
    ):
        claims = {key: value for key, value in {**id_token_claims, **overrides}.items() if value is not None}

        with pytest.raises(expected_error):
            client.validate_id_token(make_token(claims), nonce=NONCE)

    def test_expired_token_within_leeway_is_accepted(self, client, make_token, id_token_claims):
        id_token_claims["exp"] = NOW - 29

        assert client.validate_id_token(make_token(id_token_claims), nonce=NONCE)["exp"] == NOW - 29

    def test_token_signed_by_another_key_is_rejected(self, client, make_token, id_token_claims):
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        with pytest.raises(jwt.InvalidSignatureError):
            client.validate_id_token(make_token(id_token_claims, key=other_key), nonce=NONCE)

    @pytest.mark.parametrize(
        ("algorithm", "key"),
        [("HS256", "a-shared-secret-long-enough-for-hmac-sha256"), ("none", None)],
    )
    def test_other_algorithms_are_rejected(self, client, make_token, id_token_claims, algorithm, key):
        token = jwt.encode(id_token_claims, key, algorithm=algorithm, headers={"kid": "key-1"})

        with pytest.raises(jwt.PyJWTError):
            client.validate_id_token(token, nonce=NONCE)

    def test_signing_keys_are_fetched_again_after_rollover(
        self, client, make_token, id_token_claims, jwks, mock_fetch_jwks
    ):
        client.validate_id_token(make_token(id_token_claims), nonce=NONCE)
        new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        mock_fetch_jwks.return_value = {"keys": [*jwks["keys"], build_jwk(new_key, "key-2")]}
        mock_fetch_jwks.reset_mock()

        claims = client.validate_id_token(make_token(id_token_claims, kid="key-2", key=new_key), nonce=NONCE)

        assert claims == id_token_claims
        mock_fetch_jwks.assert_called_once()

    def test_removed_signing_key_is_rejected_after_cache_expiry(
        self, client, make_token, id_token_claims, mock_fetch_jwks
    ):
        token = make_token(id_token_claims)
        client.validate_id_token(token, nonce=NONCE)
        new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        mock_fetch_jwks.return_value = {"keys": [build_jwk(new_key, "key-2")]}

        expired = time.monotonic() + 301
        with patch("jwt.jwk_set_cache.time.monotonic", return_value=expired):
            with pytest.raises(jwt.PyJWKClientError, match="Unable to find a signing key"):
                client.validate_id_token(token, nonce=NONCE)

    def test_signing_keys_are_fetched_from_discovered_jwks_uri(self, client, make_token, id_token_claims):
        client.validate_id_token(make_token(id_token_claims), nonce=NONCE)

        assert client._jwks_client.uri == JWKS_URI


@pytest.mark.usefixtures("mock_fetch_jwks")
class TestValidateAccessToken:
    def test_token_without_sub_from_services_trust_issuer(
        self, client_with_resource, make_token, access_token_claims
    ):
        claims = client_with_resource.validate_access_token(make_token(access_token_claims))

        assert claims == access_token_claims

    def test_token_with_oidc_issuer(self, client_with_resource, make_token, access_token_claims):
        access_token_claims["iss"] = ISSUER

        assert client_with_resource.validate_access_token(make_token(access_token_claims))["iss"] == ISSUER

    def test_wrong_audience_is_rejected(self, client_with_resource, make_token, access_token_claims):
        access_token_claims["aud"] = "urn:another-api"

        with pytest.raises(jwt.InvalidAudienceError):
            client_with_resource.validate_access_token(make_token(access_token_claims))

    def test_configured_issuers_replace_discovered_issuers(self, make_token, access_token_claims):
        client = _build_client(resource=RESOURCE, access_token_issuers=["https://sts.example.com/trust"])

        with pytest.raises(jwt.InvalidIssuerError):
            client.validate_access_token(make_token(access_token_claims))
        access_token_claims["iss"] = "https://sts.example.com/trust"
        assert (
            client.validate_access_token(make_token(access_token_claims))["iss"] == access_token_claims["iss"]
        )

    def test_discovery_without_access_token_issuer(
        self, client_with_resource, make_token, access_token_claims
    ):
        client_with_resource.http_session.get.return_value = _response(
            json_data={key: value for key, value in METADATA.items() if key != "access_token_issuer"}
        )

        with pytest.raises(jwt.InvalidIssuerError):
            client_with_resource.validate_access_token(make_token(access_token_claims))

    def test_requires_resource(self, client, make_token, access_token_claims):
        with pytest.raises(ValueError, match="resource"):
            client.validate_access_token(make_token(access_token_claims))
