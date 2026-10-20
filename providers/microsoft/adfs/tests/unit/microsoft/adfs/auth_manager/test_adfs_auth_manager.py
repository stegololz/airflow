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

from unittest.mock import Mock, patch

import pytest

from airflow.api_fastapi.app import AUTH_MANAGER_FASTAPI_APP_PREFIX
from airflow.api_fastapi.auth.managers.models.resource_details import (
    AccessView,
    AssetAliasDetails,
    AssetDetails,
    ConfigurationDetails,
    ConnectionDetails,
    DagAccessEntity,
    DagDetails,
    PoolDetails,
    VariableDetails,
)
from airflow.api_fastapi.common.types import MenuItem
from airflow.exceptions import AirflowProviderDeprecationWarning
from airflow.providers.microsoft.adfs.auth_manager.adfs_auth_manager import AdfsAuthManager
from airflow.providers.microsoft.adfs.auth_manager.constants import (
    CONF_ACCESS_TOKEN_ISSUERS_KEY,
    CONF_CA_BUNDLE_PATH_KEY,
    CONF_CLIENT_ID_KEY,
    CONF_CLIENT_SECRET_KEY,
    CONF_DEFAULT_ROLE_KEY,
    CONF_ISSUER_KEY,
    CONF_JWKS_CACHE_TTL_SECONDS_KEY,
    CONF_LEEWAY_SECONDS_KEY,
    CONF_REQUEST_TIMEOUT_SECONDS_KEY,
    CONF_RESOURCE_KEY,
    CONF_ROLE_MAPPING_KEY,
    CONF_SCOPE_KEY,
    CONF_SECTION_NAME,
    CONF_STRIP_DOMAIN_PREFIX_KEY,
    CONF_USERNAME_CLAIMS_KEY,
    DEFAULT_SCOPE,
)
from airflow.providers.microsoft.adfs.auth_manager.oidc import AdfsAuthenticationError
from airflow.providers.microsoft.adfs.auth_manager.roles import AdfsAuthManagerRole
from airflow.providers.microsoft.adfs.auth_manager.user import AdfsAuthManagerUser

from tests_common.test_utils.config import conf_vars
from unit.microsoft.adfs.auth_manager.adfs_fixtures import AUTH_MANAGER_CONF, CLIENT_ID, ISSUER

VIEWER = AdfsAuthManagerRole.VIEWER
USER = AdfsAuthManagerRole.USER
OP = AdfsAuthManagerRole.OP
ADMIN = AdfsAuthManagerRole.ADMIN

# Resource name: (method name, extra keyword arguments)
RESOURCES = {
    "configuration": ("is_authorized_configuration", {"details": ConfigurationDetails(section="core")}),
    "connection": ("is_authorized_connection", {"details": ConnectionDetails(conn_id="conn")}),
    "dag": ("is_authorized_dag", {"details": DagDetails(id="dag")}),
    "dag_run": ("is_authorized_dag", {"access_entity": DagAccessEntity.RUN, "details": DagDetails(id="dag")}),
    "all_dags": ("is_authorized_dag", {}),
    "asset": ("is_authorized_asset", {"details": AssetDetails(id="1")}),
    "asset_alias": ("is_authorized_asset_alias", {"details": AssetAliasDetails(id="1")}),
    "pool": ("is_authorized_pool", {"details": PoolDetails(name="default_pool")}),
    "variable": ("is_authorized_variable", {"details": VariableDetails(key="key")}),
}

# Boundary cases: the role just below and at the minimal role for GET and for writes
RESOURCE_CASES = [
    ("configuration", "GET", VIEWER, True),
    ("configuration", "POST", USER, False),
    ("configuration", "POST", OP, True),
    ("connection", "GET", USER, False),
    ("connection", "GET", OP, True),
    ("connection", "POST", USER, False),
    ("connection", "POST", OP, True),
    ("connection", "DELETE", USER, False),
    ("connection", "DELETE", OP, True),
    ("dag", "GET", VIEWER, True),
    ("dag", "POST", VIEWER, False),
    ("dag", "POST", USER, True),
    ("dag_run", "GET", VIEWER, True),
    ("dag_run", "POST", VIEWER, False),
    ("dag_run", "POST", USER, True),
    ("all_dags", "GET", VIEWER, True),
    ("all_dags", "POST", VIEWER, False),
    ("all_dags", "POST", USER, True),
    ("asset", "GET", VIEWER, True),
    ("asset", "POST", USER, False),
    ("asset", "POST", OP, True),
    ("asset_alias", "GET", VIEWER, True),
    ("asset_alias", "POST", USER, False),
    ("asset_alias", "POST", OP, True),
    ("pool", "GET", VIEWER, True),
    ("pool", "POST", USER, False),
    ("pool", "POST", OP, True),
    ("variable", "GET", USER, False),
    ("variable", "GET", OP, True),
    ("variable", "POST", USER, False),
    ("variable", "POST", OP, True),
]


def _user(role: AdfsAuthManagerRole) -> AdfsAuthManagerUser:
    return AdfsAuthManagerUser(user_id="jdoe@example.com", name="John Doe", role=role)


class TestAdfsAuthManager:
    @pytest.mark.parametrize(("resource", "method", "role", "expected"), RESOURCE_CASES)
    def test_is_authorized_resource(self, auth_manager, resource, method, role, expected):
        method_name, kwargs = RESOURCES[resource]
        is_authorized = getattr(auth_manager, method_name)

        assert is_authorized(method=method, user=_user(role), **kwargs) is expected

    @pytest.mark.parametrize(
        ("method", "role", "expected"), [("GET", VIEWER, True), ("POST", VIEWER, False), ("POST", USER, True)]
    )
    def test_is_authorized_backfill(self, auth_manager, method, role, expected):
        with pytest.warns(AirflowProviderDeprecationWarning, match="DagAccessEntity.RUN"):
            assert auth_manager.is_authorized_backfill(method=method, user=_user(role)) is expected

    @pytest.mark.parametrize(
        ("access_view", "role", "expected"),
        [
            (AccessView.DOCS, VIEWER, True),
            (AccessView.IMPORT_ERRORS, VIEWER, True),
            (AccessView.AUDIT_LOGS_ALL, OP, False),
            (AccessView.AUDIT_LOGS_ALL, ADMIN, True),
            (AccessView.IMPORT_ERRORS_ALL, OP, False),
            (AccessView.IMPORT_ERRORS_ALL, ADMIN, True),
            (AccessView.REPARSE_ALL, OP, False),
            (AccessView.REPARSE_ALL, ADMIN, True),
        ],
    )
    def test_is_authorized_view(self, auth_manager, access_view, role, expected):
        assert auth_manager.is_authorized_view(access_view=access_view, user=_user(role)) is expected
        assert (
            auth_manager.authorize_view(access_view=access_view, user=_user(role), team_name="team")
            is expected
        )

    @pytest.mark.parametrize(("role", "expected"), [(OP, False), (ADMIN, True)])
    def test_is_authorized_view_unknown_view(self, auth_manager, role, expected):
        unknown_view = Mock(value="NEW_VIEW")

        assert auth_manager.is_authorized_view(access_view=unknown_view, user=_user(role)) is expected

    @pytest.mark.parametrize(
        ("method", "role", "expected"),
        [
            ("GET", VIEWER, True),
            ("POST", USER, False),
            ("POST", OP, True),
            ("can_trigger", USER, False),
            ("can_trigger", OP, True),
        ],
    )
    def test_is_authorized_custom_view(self, auth_manager, method, role, expected):
        assert (
            auth_manager.is_authorized_custom_view(method=method, resource_name="plugin", user=_user(role))
            is expected
        )

    @pytest.mark.parametrize(
        ("role", "hidden_items"),
        [
            (VIEWER, {MenuItem.CONNECTIONS, MenuItem.VARIABLES}),
            (USER, {MenuItem.CONNECTIONS, MenuItem.VARIABLES}),
            (OP, set()),
            (ADMIN, set()),
        ],
    )
    def test_filter_authorized_menu_items(self, auth_manager, role, hidden_items):
        menu_items = list(MenuItem)

        result = auth_manager.filter_authorized_menu_items(menu_items, user=_user(role))

        assert result == [item for item in menu_items if item not in hidden_items]

    def test_serialize_user_round_trip(self, auth_manager):
        user = _user(OP)

        serialized = auth_manager.serialize_user(user)

        assert serialized == {"sub": "jdoe@example.com", "name": "John Doe", "role": "OP"}
        assert auth_manager.deserialize_user(serialized) == user

    @pytest.mark.parametrize(
        "token",
        [
            {"sub": "jdoe@example.com", "name": "John Doe", "role": "SUPERUSER"},
            {"sub": "jdoe@example.com", "name": "John Doe"},
        ],
    )
    def test_deserialize_user_invalid_token(self, auth_manager, token):
        with pytest.raises(KeyError):
            auth_manager.deserialize_user(token)

    @conf_vars({("api", "base_url"): "https://airflow.example.com/"})
    @pytest.mark.parametrize(
        ("kwargs", "expected_query"),
        [
            ({}, ""),
            (
                {"next_url": "https://airflow.example.com/dags?a=b"},
                "?next=https%3A%2F%2Fairflow.example.com%2Fdags%3Fa%3Db",
            ),
        ],
    )
    def test_get_url_login(self, auth_manager, kwargs, expected_query):
        assert (
            auth_manager.get_url_login(**kwargs)
            == f"https://airflow.example.com{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login{expected_query}"
        )

    @conf_vars({("api", "base_url"): "https://airflow.example.com/"})
    def test_get_url_logout(self, auth_manager):
        assert (
            auth_manager.get_url_logout()
            == f"https://airflow.example.com{AUTH_MANAGER_FASTAPI_APP_PREFIX}/logout"
        )

    def test_get_fastapi_app(self, auth_manager):
        app = auth_manager.get_fastapi_app()

        assert {route.path for route in app.routes} >= {
            "/login",
            "/login_callback",
            "/logout",
            "/logout_callback",
        }

    def test_get_oidc_client(self, auth_manager):
        client = auth_manager.get_oidc_client()

        assert client is auth_manager.get_oidc_client()
        assert client.issuer == ISSUER
        assert client.client_id == CLIENT_ID
        assert client.client_secret is None
        assert client.scope == DEFAULT_SCOPE
        assert client.resource is None
        assert client.access_token_issuers == []
        assert client.leeway_seconds == 30
        assert client.ca_bundle_path is None
        assert client.request_timeout_seconds == 10
        assert client.jwks_cache_ttl_seconds == 300

    @conf_vars(
        {
            (CONF_SECTION_NAME, CONF_CLIENT_SECRET_KEY): "secret",
            (CONF_SECTION_NAME, CONF_SCOPE_KEY): "openid allatclaims",
            (CONF_SECTION_NAME, CONF_RESOURCE_KEY): "urn:airflow",
            (CONF_SECTION_NAME, CONF_ACCESS_TOKEN_ISSUERS_KEY): " https://a/trust , https://b/trust ",
            (CONF_SECTION_NAME, CONF_LEEWAY_SECONDS_KEY): "5",
            (CONF_SECTION_NAME, CONF_CA_BUNDLE_PATH_KEY): "/etc/ssl/ca.pem",
            (CONF_SECTION_NAME, CONF_REQUEST_TIMEOUT_SECONDS_KEY): "3",
            (CONF_SECTION_NAME, CONF_JWKS_CACHE_TTL_SECONDS_KEY): "60",
        }
    )
    def test_get_oidc_client_options(self, auth_manager):
        client = auth_manager.get_oidc_client()

        assert client.client_secret == "secret"
        assert client.scope == "openid allatclaims"
        assert client.resource == "urn:airflow"
        assert client.access_token_issuers == ["https://a/trust", "https://b/trust"]
        assert client.leeway_seconds == 5
        assert client.ca_bundle_path == "/etc/ssl/ca.pem"
        assert client.request_timeout_seconds == 3
        assert client.jwks_cache_ttl_seconds == 60

    @conf_vars({(CONF_SECTION_NAME, CONF_SCOPE_KEY): ""})
    def test_get_oidc_client_empty_scope(self, auth_manager):
        assert auth_manager.get_oidc_client().scope == DEFAULT_SCOPE

    def test_init(self, auth_manager):
        auth_manager.init()

    @pytest.mark.parametrize(
        ("overrides", "match"),
        [
            ({(CONF_SECTION_NAME, CONF_ISSUER_KEY): None}, "issuer must be set"),
            ({(CONF_SECTION_NAME, CONF_CLIENT_ID_KEY): None}, "client_id must be set"),
            ({(CONF_SECTION_NAME, CONF_ROLE_MAPPING_KEY): None}, "role_mapping must be set"),
            ({(CONF_SECTION_NAME, CONF_ISSUER_KEY): "http://adfs.example.com/adfs"}, "https"),
            ({(CONF_SECTION_NAME, CONF_ROLE_MAPPING_KEY): '{"Airflow Admins": "ROOT"}'}, "Airflow Admins"),
            ({(CONF_SECTION_NAME, CONF_DEFAULT_ROLE_KEY): "ROOT"}, "ROOT"),
            ({(CONF_SECTION_NAME, CONF_USERNAME_CLAIMS_KEY): " , "}, "username_claims"),
            ({("core", "multi_team"): "True"}, "Multi-team"),
        ],
    )
    def test_init_invalid_config(self, overrides, match):
        with conf_vars({**AUTH_MANAGER_CONF, **overrides}):
            auth_manager = AdfsAuthManager()
            with pytest.raises(ValueError, match=match):
                auth_manager.init()


class TestGetUserFromClaims:
    @pytest.mark.parametrize(
        ("claims", "expected_name"),
        [
            ({"upn": "jdoe@example.com", "name": "John Doe"}, "John Doe"),
            ({"upn": "jdoe@example.com", "given_name": "John", "family_name": "Doe"}, "John Doe"),
            ({"upn": "jdoe@example.com", "family_name": "Doe"}, "Doe"),
            ({"upn": "jdoe@example.com", "name": " "}, "jdoe@example.com"),
        ],
    )
    def test_display_name(self, auth_manager, claims, expected_name):
        user = auth_manager.get_user_from_claims({**claims, "role": "Airflow Users"})

        assert user == AdfsAuthManagerUser(user_id="jdoe@example.com", name=expected_name, role=USER)

    def test_role_from_several_claims(self, auth_manager):
        claims = {
            "upn": "jdoe@example.com",
            "role": "Airflow Users",
            "groups": ["Domain Users", "airflow admins"],
        }

        assert auth_manager.get_user_from_claims(claims).role == ADMIN

    @conf_vars(
        {
            (CONF_SECTION_NAME, CONF_USERNAME_CLAIMS_KEY): "unique_name",
            (CONF_SECTION_NAME, CONF_STRIP_DOMAIN_PREFIX_KEY): "True",
        }
    )
    def test_username_options(self, auth_manager):
        claims = {"upn": "jdoe@example.com", "unique_name": "EXAMPLE\\JDOE", "role": "Airflow Users"}

        assert auth_manager.get_user_from_claims(claims).get_id() == "JDOE"

    def test_no_username(self, auth_manager):
        with pytest.raises(AdfsAuthenticationError):
            auth_manager.get_user_from_claims({"name": "John Doe", "role": "Airflow Users"})

    @patch("airflow.providers.microsoft.adfs.auth_manager.adfs_auth_manager.log", autospec=True)
    def test_no_role(self, mock_log, auth_manager):
        with pytest.raises(PermissionError):
            auth_manager.get_user_from_claims({"upn": "jdoe@example.com", "role": "Domain Users"})

        mock_log.info.assert_called_once_with(
            "User %s has no Airflow role; unmapped claim values: %s", "jdoe@example.com", ["Domain Users"]
        )

    @conf_vars({(CONF_SECTION_NAME, CONF_DEFAULT_ROLE_KEY): "viewer"})
    def test_default_role(self, auth_manager):
        assert (
            auth_manager.get_user_from_claims({"upn": "jdoe@example.com", "role": "Domain Users"}).role
            == VIEWER
        )
