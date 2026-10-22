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

import json
import warnings
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
    TeamDetails,
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
    CONF_TEAM_ROLE_MAPPING_KEY,
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

TEAM_ROLE_MAPPING = json.dumps(
    {
        "Team A Viewers": "team_a:VIEWER",
        "Team A Operators": "team_a:OP",
        "Team B Users": "team_b:USER",
    }
)
MULTI_TEAM_CONF = {
    ("core", "multi_team"): "True",
    (CONF_SECTION_NAME, CONF_TEAM_ROLE_MAPPING_KEY): TEAM_ROLE_MAPPING,
}


def _user(
    role: AdfsAuthManagerRole | None, teams: dict[str, AdfsAuthManagerRole] | None = None
) -> AdfsAuthManagerUser:
    return AdfsAuthManagerUser(user_id="jdoe@example.com", name="John Doe", role=role, teams=teams or {})


@pytest.fixture
def multi_team_auth_manager():
    with conf_vars({**AUTH_MANAGER_CONF, **MULTI_TEAM_CONF}):
        yield AdfsAuthManager()


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

        assert serialized == {"sub": "jdoe@example.com", "name": "John Doe", "role": "OP", "teams": {}}
        assert auth_manager.deserialize_user(serialized) == user

    @conf_vars({("core", "multi_team"): "True"})
    def test_serialize_user_with_teams_round_trip(self, auth_manager):
        user = _user(None, {"team_a": OP, "team_b": VIEWER})

        serialized = auth_manager.serialize_user(user)

        assert serialized == {
            "sub": "jdoe@example.com",
            "name": "John Doe",
            "role": None,
            "teams": {"team_a": "OP", "team_b": "VIEWER"},
        }
        assert auth_manager.deserialize_user(serialized) == user

    def test_deserialize_user_without_teams(self, auth_manager):
        token = {"sub": "jdoe@example.com", "name": "John Doe", "role": "OP"}

        assert auth_manager.deserialize_user(token) == _user(OP)

    @conf_vars({("core", "multi_team"): "True"})
    def test_deserialize_user_invalid_team_role(self, auth_manager):
        token = {
            "sub": "jdoe@example.com",
            "name": "John Doe",
            "role": None,
            "teams": {"team_a": "SUPERUSER"},
        }

        with pytest.raises(KeyError):
            auth_manager.deserialize_user(token)

    def test_deserialize_user_ignores_teams_without_multi_team(self, auth_manager):
        token = {"sub": "jdoe@example.com", "name": "John Doe", "role": None, "teams": {"team_a": "OP"}}

        user = auth_manager.deserialize_user(token)

        assert user == _user(None)
        assert auth_manager.is_authorized_dag(method="GET", user=user, details=DagDetails(id="dag")) is False

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

    @patch(
        "airflow.api_fastapi.auth.managers.base_auth_manager.Team.get_all_team_names",
        return_value={"team_a", "team_b"},
    )
    def test_init_multi_team(self, _, multi_team_auth_manager):
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            multi_team_auth_manager.init()

    @conf_vars({(CONF_SECTION_NAME, CONF_ROLE_MAPPING_KEY): None})
    @patch(
        "airflow.api_fastapi.auth.managers.base_auth_manager.Team.get_all_team_names",
        return_value={"team_a", "team_b"},
    )
    def test_init_multi_team_without_role_mapping(self, _, multi_team_auth_manager):
        multi_team_auth_manager.init()

    @patch(
        "airflow.api_fastapi.auth.managers.base_auth_manager.Team.get_all_team_names",
        return_value={"team_a", "team_c"},
    )
    def test_init_multi_team_warns_on_team_mismatch(self, _, multi_team_auth_manager):
        with pytest.warns(UserWarning, match="Teams defined") as record:
            multi_team_auth_manager.init()

        assert [str(w.message) for w in record] == [
            "Teams defined in the auth manager are not present in the database ({'team_b'}).",
            "Teams defined in the database are not present in the auth manager ({'team_c'}).",
        ]

    def test_get_teams(self, multi_team_auth_manager):
        assert multi_team_auth_manager._get_teams() == {"team_a", "team_b"}

    def test_get_teams_without_team_role_mapping(self, auth_manager):
        assert auth_manager._get_teams() == set()

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
            (
                {(CONF_SECTION_NAME, CONF_TEAM_ROLE_MAPPING_KEY): TEAM_ROLE_MAPPING},
                "team_role_mapping requires \\[core\\] multi_team",
            ),
            (
                {("core", "multi_team"): "True", (CONF_SECTION_NAME, CONF_ROLE_MAPPING_KEY): None},
                "role_mapping must be set",
            ),
            (
                {**MULTI_TEAM_CONF, (CONF_SECTION_NAME, CONF_TEAM_ROLE_MAPPING_KEY): "{not json"},
                "not valid JSON",
            ),
            (
                {**MULTI_TEAM_CONF, (CONF_SECTION_NAME, CONF_TEAM_ROLE_MAPPING_KEY): '{"Team A": "OP"}'},
                "'Team A' must be a '<team>:<role>' string",
            ),
            (
                {
                    **MULTI_TEAM_CONF,
                    (CONF_SECTION_NAME, CONF_TEAM_ROLE_MAPPING_KEY): '{"Team A": "team_a:ROOT"}',
                },
                "Invalid role for team_role_mapping key 'Team A'",
            ),
            (
                {
                    **MULTI_TEAM_CONF,
                    (
                        CONF_SECTION_NAME,
                        CONF_TEAM_ROLE_MAPPING_KEY,
                    ): '{"Team A": "team_a:OP", "TEAM A": "team_a:VIEWER"}',
                },
                "'TEAM A' is defined more than once",
            ),
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


class TestGetUserFromClaimsMultiTeam:
    def test_global_and_team_roles(self, multi_team_auth_manager):
        claims = {
            "upn": "jdoe@example.com",
            "name": "John Doe",
            "groups": ["Airflow Users", "Team A Viewers", "Team B Users"],
        }

        assert multi_team_auth_manager.get_user_from_claims(claims) == _user(
            USER, {"team_a": VIEWER, "team_b": USER}
        )

    def test_highest_role_per_team(self, multi_team_auth_manager):
        claims = {"upn": "jdoe@example.com", "groups": ["Team A Operators", "team a viewers"]}

        assert multi_team_auth_manager.get_user_from_claims(claims).teams == {"team_a": OP}

    def test_team_roles_only(self, multi_team_auth_manager):
        user = multi_team_auth_manager.get_user_from_claims(
            {"upn": "jdoe@example.com", "role": "Team B Users"}
        )

        assert user.role is None
        assert user.teams == {"team_b": USER}

    @conf_vars({(CONF_SECTION_NAME, CONF_ROLE_MAPPING_KEY): None})
    def test_without_role_mapping(self, multi_team_auth_manager):
        user = multi_team_auth_manager.get_user_from_claims(
            {"upn": "jdoe@example.com", "role": "Team B Users"}
        )

        assert (user.role, user.teams) == (None, {"team_b": USER})

    def test_no_global_nor_team_role(self, multi_team_auth_manager):
        with pytest.raises(PermissionError):
            multi_team_auth_manager.get_user_from_claims({"upn": "jdoe@example.com", "role": "Domain Users"})


# Resource name: (method name, extra keyword arguments), for resources of team_a
TEAM_A_RESOURCES = {
    "connection": (
        "is_authorized_connection",
        {"details": ConnectionDetails(conn_id="c", team_name="team_a")},
    ),
    "dag": ("is_authorized_dag", {"details": DagDetails(id="dag", team_name="team_a")}),
    "dag_run": (
        "is_authorized_dag",
        {"access_entity": DagAccessEntity.RUN, "details": DagDetails(id="dag", team_name="team_a")},
    ),
    "pool": ("is_authorized_pool", {"details": PoolDetails(name="pool", team_name="team_a")}),
    "variable": ("is_authorized_variable", {"details": VariableDetails(key="key", team_name="team_a")}),
}

GLOBAL_ADMIN = _user(ADMIN)
GLOBAL_OP = _user(OP)
TEAM_A_VIEWER = _user(None, {"team_a": VIEWER})
TEAM_A_USER = _user(None, {"team_a": USER})
TEAM_A_OP = _user(None, {"team_a": OP})
TEAM_B_ADMIN = _user(None, {"team_b": ADMIN})
TEAM_A_OP_GLOBAL_VIEWER = _user(VIEWER, {"team_a": OP})


class TestMultiTeamAuthorization:
    @pytest.mark.parametrize(
        ("resource", "method", "user", "expected"),
        [
            ("connection", "DELETE", GLOBAL_ADMIN, True),
            ("variable", "POST", GLOBAL_ADMIN, True),
            ("dag", "POST", GLOBAL_ADMIN, True),
            ("connection", "GET", GLOBAL_OP, False),
            ("variable", "GET", GLOBAL_OP, False),
            ("pool", "GET", GLOBAL_OP, False),
            ("dag", "GET", GLOBAL_OP, False),
            ("connection", "GET", TEAM_A_OP, True),
            ("connection", "POST", TEAM_A_OP, True),
            ("variable", "GET", TEAM_A_OP, True),
            ("variable", "DELETE", TEAM_A_OP, True),
            ("pool", "POST", TEAM_A_OP, True),
            ("dag", "POST", TEAM_A_OP, True),
            ("dag_run", "POST", TEAM_A_OP, True),
            ("connection", "GET", TEAM_A_USER, False),
            ("variable", "GET", TEAM_A_USER, False),
            ("pool", "GET", TEAM_A_USER, True),
            ("pool", "POST", TEAM_A_USER, False),
            ("dag", "POST", TEAM_A_USER, True),
            ("dag_run", "POST", TEAM_A_USER, True),
            ("dag", "GET", TEAM_A_VIEWER, True),
            ("dag", "POST", TEAM_A_VIEWER, False),
            ("connection", "GET", TEAM_B_ADMIN, False),
            ("variable", "GET", TEAM_B_ADMIN, False),
            ("pool", "GET", TEAM_B_ADMIN, False),
            ("dag", "GET", TEAM_B_ADMIN, False),
            ("connection", "POST", TEAM_A_OP_GLOBAL_VIEWER, True),
        ],
    )
    def test_is_authorized_team_resource(self, auth_manager, resource, method, user, expected):
        method_name, kwargs = TEAM_A_RESOURCES[resource]
        is_authorized = getattr(auth_manager, method_name)

        assert is_authorized(method=method, user=user, **kwargs) is expected

    @pytest.mark.parametrize(
        ("resource", "method", "user", "expected"),
        [
            ("dag", "GET", TEAM_A_OP, True),
            ("dag", "POST", TEAM_A_OP, False),
            ("all_dags", "GET", TEAM_A_OP, True),
            ("all_dags", "POST", TEAM_A_OP, True),
            ("pool", "GET", TEAM_A_OP, True),
            ("pool", "POST", TEAM_A_OP, False),
            ("connection", "GET", TEAM_A_OP, False),
            ("variable", "GET", TEAM_A_OP, False),
            ("configuration", "GET", TEAM_A_OP, True),
            ("configuration", "POST", TEAM_A_OP, False),
            ("asset", "GET", TEAM_A_OP, True),
            ("asset", "POST", TEAM_A_OP, False),
            ("asset_alias", "GET", TEAM_A_OP, True),
            ("asset_alias", "POST", TEAM_A_OP, False),
            ("dag", "POST", TEAM_A_OP_GLOBAL_VIEWER, False),
            ("connection", "GET", TEAM_A_OP_GLOBAL_VIEWER, False),
            ("connection", "GET", GLOBAL_OP, True),
        ],
    )
    def test_is_authorized_resource_without_team(self, auth_manager, resource, method, user, expected):
        method_name, kwargs = RESOURCES[resource]
        is_authorized = getattr(auth_manager, method_name)

        assert is_authorized(method=method, user=user, **kwargs) is expected

    @pytest.mark.parametrize(
        ("access_view", "user", "expected"),
        [
            (AccessView.DOCS, TEAM_A_VIEWER, True),
            (AccessView.IMPORT_ERRORS, TEAM_A_VIEWER, True),
            (AccessView.AUDIT_LOGS_ALL, TEAM_B_ADMIN, False),
            (AccessView.REPARSE_ALL, TEAM_B_ADMIN, False),
            (AccessView.REPARSE_ALL, GLOBAL_ADMIN, True),
        ],
    )
    def test_is_authorized_view(self, auth_manager, access_view, user, expected):
        assert (
            auth_manager.is_authorized_view(access_view=access_view, user=user, team_name="team_b")
            is expected
        )

    @pytest.mark.parametrize(
        ("details", "user", "expected"),
        [
            (TeamDetails(name="team_a"), TEAM_A_VIEWER, True),
            (TeamDetails(name="team_b"), TEAM_A_OP, False),
            (TeamDetails(name="team_b"), GLOBAL_ADMIN, True),
            (TeamDetails(name="team_a"), GLOBAL_OP, False),
            (None, TEAM_A_OP, False),
        ],
    )
    def test_is_authorized_team(self, auth_manager, details, user, expected):
        assert auth_manager.is_authorized_team(method="GET", user=user, details=details) is expected

    @pytest.mark.parametrize(
        ("method", "user", "expected"),
        [("POST", TEAM_A_VIEWER, False), ("DELETE", TEAM_A_USER, False), ("POST", TEAM_A_OP, True)],
    )
    def test_is_authorized_team_write(self, auth_manager, method, user, expected):
        details = TeamDetails(name="team_a")

        assert auth_manager.is_authorized_team(method=method, user=user, details=details) is expected

    @pytest.mark.parametrize(
        ("method_name", "details", "method", "user", "expected"),
        [
            ("is_authorized_connection", ConnectionDetails(), "GET", TEAM_A_OP, True),
            ("is_authorized_variable", VariableDetails(), "GET", TEAM_A_OP, True),
            ("is_authorized_variable", VariableDetails(), "GET", TEAM_A_USER, False),
            ("is_authorized_connection", ConnectionDetails(), "POST", TEAM_A_OP, False),
            ("is_authorized_variable", None, "POST", TEAM_A_OP, False),
        ],
    )
    def test_is_authorized_list(self, auth_manager, method_name, details, method, user, expected):
        is_authorized = getattr(auth_manager, method_name)

        assert is_authorized(method=method, user=user, details=details) is expected

    def test_filter_authorized_teams(self, auth_manager):
        user = _user(None, {"team_a": VIEWER, "team_b": USER})

        assert auth_manager.filter_authorized_teams(
            teams_names={"team_a", "team_b", "team_c"}, user=user
        ) == {
            "team_a",
            "team_b",
        }

    @pytest.mark.parametrize(
        ("user", "hidden_items"),
        [
            (TEAM_A_USER, {MenuItem.CONNECTIONS, MenuItem.VARIABLES}),
            (TEAM_A_OP, set()),
            (TEAM_A_OP_GLOBAL_VIEWER, set()),
            (_user(None), set(MenuItem)),
        ],
    )
    def test_filter_authorized_menu_items(self, auth_manager, user, hidden_items):
        menu_items = list(MenuItem)

        result = auth_manager.filter_authorized_menu_items(menu_items, user=user)

        assert result == [item for item in menu_items if item not in hidden_items]

    @pytest.mark.parametrize(
        ("method", "user", "expected"),
        [
            ("GET", TEAM_A_VIEWER, True),
            ("POST", TEAM_A_USER, False),
            ("POST", TEAM_A_OP, False),
            ("can_trigger", TEAM_A_OP_GLOBAL_VIEWER, False),
            ("GET", _user(None), False),
        ],
    )
    def test_is_authorized_custom_view(self, auth_manager, method, user, expected):
        assert (
            auth_manager.is_authorized_custom_view(method=method, resource_name="plugin", user=user)
            is expected
        )
