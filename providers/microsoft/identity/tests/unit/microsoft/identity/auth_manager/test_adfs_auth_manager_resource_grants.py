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
from unittest.mock import patch

import pytest

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
from airflow.providers.microsoft.identity.auth_manager.adfs_auth_manager import AdfsAuthManager
from airflow.providers.microsoft.identity.auth_manager.constants import (
    CONF_RESOURCE_ROLE_MAPPING_KEY,
    CONF_ROLE_MAPPING_KEY,
    CONF_SECTION_NAME,
    CONF_TEAM_ROLE_MAPPING_KEY,
)
from airflow.providers.microsoft.identity.auth_manager.roles import (
    AdfsAuthManagerRole,
    ResourceGrant,
    ResourceKind,
)
from airflow.providers.microsoft.identity.auth_manager.user import AdfsAuthManagerUser

from tests_common.test_utils.config import conf_vars
from tests_common.test_utils.version_compat import AIRFLOW_V_3_4_PLUS
from unit.microsoft.identity.auth_manager.adfs_fixtures import AUTH_MANAGER_CONF

VIEWER = AdfsAuthManagerRole.VIEWER
USER = AdfsAuthManagerRole.USER
OP = AdfsAuthManagerRole.OP
ADMIN = AdfsAuthManagerRole.ADMIN

AIRFLOW_V_3_2_PLUS_PATH = (
    "airflow.providers.microsoft.identity.auth_manager.adfs_auth_manager.AIRFLOW_V_3_2_PLUS"
)

RESOURCE_ROLE_MAPPING = json.dumps(
    {
        "Finance Ops": [
            {"dags": "finance_*", "role": "USER"},
            {"connections": "finance_*", "role": "OP"},
            {"variables": "finance_*", "role": "OP"},
            {"pools": "finance", "role": "OP"},
        ],
        "Finance Auditors": [{"dags": "finance_*", "role": "VIEWER"}],
        "Payroll Admins": [{"dags": "payroll_export", "role": "OP"}],
        "Platform Admins": [{"dags": "platform_*", "role": "ADMIN"}],
        "Pool Watchers": [{"pools": "finance*", "role": "VIEWER"}],
        "Conn Only": [{"connections": "finance_*", "role": "OP"}],
    }
)
GRANTS_CONF = {
    **AUTH_MANAGER_CONF,
    (CONF_SECTION_NAME, CONF_RESOURCE_ROLE_MAPPING_KEY): RESOURCE_ROLE_MAPPING,
}

TEAM_ROLE_MAPPING = json.dumps({"Team A Viewers": "team_a:VIEWER", "Team B Users": "team_b:USER"})
TEAM_RESOURCE_ROLE_MAPPING = json.dumps(
    {
        "Team A Finance": [
            {"dags": "finance_*", "role": "USER", "team": "team_a"},
            {"connections": "finance_*", "role": "OP", "team": "team_a"},
            {"variables": "finance_*", "role": "OP", "team": "team_a"},
            {"pools": "finance", "role": "OP", "team": "team_a"},
        ],
        "Shared Finance": [
            {"dags": "finance_*", "role": "VIEWER"},
            {"connections": "finance_*", "role": "OP"},
        ],
        "Team C Reports": [{"connections": "report_*", "role": "OP", "team": "team_c"}],
    }
)
TEAM_GRANTS_CONF = {
    **AUTH_MANAGER_CONF,
    ("core", "multi_team"): "True",
    (CONF_SECTION_NAME, CONF_TEAM_ROLE_MAPPING_KEY): TEAM_ROLE_MAPPING,
    (CONF_SECTION_NAME, CONF_RESOURCE_ROLE_MAPPING_KEY): TEAM_RESOURCE_ROLE_MAPPING,
}


def _user(
    role: AdfsAuthManagerRole | None = None,
    teams: dict[str, AdfsAuthManagerRole] | None = None,
    grant_groups: list[str] | None = None,
) -> AdfsAuthManagerUser:
    return AdfsAuthManagerUser(
        user_id="jdoe@example.com",
        name="John Doe",
        role=role,
        teams=teams or {},
        grant_groups=grant_groups or [],
    )


FINANCE_OPS = _user(grant_groups=["finance ops"])
FINANCE_AUDITOR = _user(grant_groups=["finance auditors"])
PAYROLL_ADMIN = _user(grant_groups=["payroll admins"])
PLATFORM_ADMIN = _user(grant_groups=["platform admins"])
POOL_WATCHER = _user(grant_groups=["pool watchers"])
CONN_ONLY = _user(grant_groups=["conn only"])
TEAM_A_FINANCE = _user(grant_groups=["team a finance"])
SHARED_FINANCE = _user(grant_groups=["shared finance"])


@pytest.fixture(autouse=True)
def _airflow_3_2_plus():
    with patch(AIRFLOW_V_3_2_PLUS_PATH, True):
        yield


@pytest.fixture
def auth_manager():
    with conf_vars(GRANTS_CONF):
        yield AdfsAuthManager()


@pytest.fixture
def team_auth_manager():
    with conf_vars(TEAM_GRANTS_CONF):
        yield AdfsAuthManager()


def _is_authorized_dag(auth_manager, method, user, dag_id=None, team_name=None, access_entity=None):
    details = None if dag_id is None and team_name is None else DagDetails(id=dag_id, team_name=team_name)
    return auth_manager.is_authorized_dag(
        method=method, user=user, access_entity=access_entity, details=details
    )


def _connection(resource_id, team_name=None):
    return ConnectionDetails(conn_id=resource_id, team_name=team_name)


def _variable(resource_id, team_name=None):
    return VariableDetails(key=resource_id, team_name=team_name)


def _pool(resource_id, team_name=None):
    return PoolDetails(name=resource_id, team_name=team_name)


# Connections, variables and pools: check method, batch method, details factory and an ID matching
# the grants of "Finance Ops" and "Team A Finance".
RESOURCE_KINDS = [
    pytest.param(
        "is_authorized_connection", "batch_is_authorized_connection", _connection, "finance_db", id="conn"
    ),
    pytest.param(
        "is_authorized_variable", "batch_is_authorized_variable", _variable, "finance_rate", id="var"
    ),
    pytest.param("is_authorized_pool", "batch_is_authorized_pool", _pool, "finance", id="pool"),
]


class TestResourceRoleMappingConfig:
    def test_get_resource_role_mapping(self, auth_manager):
        assert auth_manager.get_resource_role_mapping() == {
            "finance ops": [
                ResourceGrant(ResourceKind.DAGS, "finance_*", USER, None),
                ResourceGrant(ResourceKind.CONNECTIONS, "finance_*", OP, None),
                ResourceGrant(ResourceKind.VARIABLES, "finance_*", OP, None),
                ResourceGrant(ResourceKind.POOLS, "finance", OP, None),
            ],
            "finance auditors": [ResourceGrant(ResourceKind.DAGS, "finance_*", VIEWER, None)],
            "payroll admins": [ResourceGrant(ResourceKind.DAGS, "payroll_export", OP, None)],
            "platform admins": [ResourceGrant(ResourceKind.DAGS, "platform_*", ADMIN, None)],
            "pool watchers": [ResourceGrant(ResourceKind.POOLS, "finance*", VIEWER, None)],
            "conn only": [ResourceGrant(ResourceKind.CONNECTIONS, "finance_*", OP, None)],
        }

    def test_get_resource_role_mapping_unset(self):
        with conf_vars(AUTH_MANAGER_CONF):
            assert AdfsAuthManager().get_resource_role_mapping() == {}

    def test_init_with_only_resource_role_mapping(self):
        with conf_vars({**GRANTS_CONF, (CONF_SECTION_NAME, CONF_ROLE_MAPPING_KEY): None}):
            auth_manager = AdfsAuthManager()
            auth_manager.init()

            user = auth_manager.get_user_from_claims(
                {"upn": "jdoe@example.com", "name": "John Doe", "groups": ["Finance Ops"]}
            )

        assert user == FINANCE_OPS

    @pytest.mark.parametrize(
        ("raw", "match"),
        [
            (
                None,
                "^\\[adfs_auth_manager\\] role_mapping, team_role_mapping or resource_role_mapping must be set$",
            ),
            ("{not json", "^resource_role_mapping is not valid JSON"),
            ("[]", "^resource_role_mapping must be a JSON object$"),
            (
                '{"Finance Ops": []}',
                "^The value of resource_role_mapping key 'Finance Ops' must be a non-empty list$",
            ),
            (
                '{"Finance Ops": [{"assets": "a", "role": "OP"}]}',
                "^Each grant of resource_role_mapping key 'Finance Ops' must be an object with one of",
            ),
            (
                '{"Finance Ops": [{"dags": "a", "role": "ROOT"}]}',
                "^Invalid role for resource_role_mapping key",
            ),
            (
                '{"Finance Ops": [{"variables": "a", "role": "USER"}]}',
                "^The role of a 'variables' grant of resource_role_mapping key 'Finance Ops' must be at least "
                "OP$",
            ),
            (
                '{"Finance Ops": [{"pools": "a", "role": "OP", "team": "team_a"}]}',
                "^The 'team' of resource_role_mapping key 'Finance Ops' must be a team name and requires "
                "\\[core\\] multi_team$",
            ),
            (
                '{"Finance Ops": [{"dags": "a", "role": "OP"}], "finance ops": [{"dags": "b", "role": "OP"}]}',
                "^resource_role_mapping key 'finance ops' is defined more than once",
            ),
        ],
    )
    def test_init_invalid_config(self, raw, match):
        overrides = {
            (CONF_SECTION_NAME, CONF_ROLE_MAPPING_KEY): None,
            (CONF_SECTION_NAME, CONF_RESOURCE_ROLE_MAPPING_KEY): raw,
        }
        with conf_vars({**AUTH_MANAGER_CONF, **overrides}):
            auth_manager = AdfsAuthManager()
            with pytest.raises(ValueError, match=match):
                auth_manager.init()

    @pytest.mark.parametrize("kind", ["connections", "variables", "pools"])
    def test_init_refuses_non_dag_grants_before_airflow_3_2(self, kind):
        mapping = json.dumps(
            {"Finance Ops": [{"dags": "finance_*", "role": "USER"}, {kind: "a", "role": "OP"}]}
        )
        with (
            conf_vars({**AUTH_MANAGER_CONF, (CONF_SECTION_NAME, CONF_RESOURCE_ROLE_MAPPING_KEY): mapping}),
            patch(AIRFLOW_V_3_2_PLUS_PATH, False),
        ):
            auth_manager = AdfsAuthManager()
            with pytest.raises(
                ValueError,
                match="^\\[adfs_auth_manager\\] resource_role_mapping grants on connections, variables or "
                "pools require Airflow 3\\.2\\.0 or later$",
            ):
                auth_manager.init()

    def test_init_accepts_dag_grants_before_airflow_3_2(self):
        mapping = json.dumps({"Finance Ops": [{"dags": "finance_*", "role": "USER"}]})
        with (
            conf_vars({**AUTH_MANAGER_CONF, (CONF_SECTION_NAME, CONF_RESOURCE_ROLE_MAPPING_KEY): mapping}),
            patch(AIRFLOW_V_3_2_PLUS_PATH, False),
        ):
            auth_manager = AdfsAuthManager()
            auth_manager.init()

            assert auth_manager.get_resource_role_mapping() == {
                "finance ops": [ResourceGrant(ResourceKind.DAGS, "finance_*", USER, None)]
            }

    def test_get_teams_includes_grant_teams(self, team_auth_manager):
        assert team_auth_manager._get_teams() == {"team_a", "team_b", "team_c"}

    def test_get_teams_from_grants_only(self):
        conf = {**TEAM_GRANTS_CONF, (CONF_SECTION_NAME, CONF_TEAM_ROLE_MAPPING_KEY): None}
        with conf_vars(conf):
            assert AdfsAuthManager()._get_teams() == {"team_a", "team_c"}

    @patch(
        "airflow.api_fastapi.auth.managers.base_auth_manager.Team.get_all_team_names",
        return_value={"team_a", "team_b", "team_c"},
    )
    def test_init_multi_team(self, _, team_auth_manager):
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            team_auth_manager.init()

    @patch(
        "airflow.api_fastapi.auth.managers.base_auth_manager.Team.get_all_team_names",
        return_value={"team_a", "team_b"},
    )
    def test_init_multi_team_reports_unknown_connection_grant_team(self, _, team_auth_manager):
        if AIRFLOW_V_3_4_PLUS:
            with pytest.warns(UserWarning, match="Teams defined") as record:
                team_auth_manager.init()

            assert [str(w.message) for w in record] == [
                "Teams defined in the auth manager are not present in the database ({'team_c'}).",
            ]
        else:
            with pytest.raises(ValueError, match="Teams defined in the auth manager"):
                team_auth_manager.init()


class TestGetUserFromClaimsGrants:
    def test_stores_grant_groups(self, auth_manager):
        claims = {
            "upn": "jdoe@example.com",
            "name": "John Doe",
            "groups": ["FINANCE OPS", "Domain Users", "finance auditors", "Finance Ops"],
        }

        assert auth_manager.get_user_from_claims(claims) == _user(
            grant_groups=["finance auditors", "finance ops"]
        )

    def test_global_role_and_grant_groups(self, auth_manager):
        claims = {
            "upn": "jdoe@example.com",
            "name": "John Doe",
            "role": ["Airflow Viewers", "Payroll Admins"],
        }

        assert auth_manager.get_user_from_claims(claims) == _user(VIEWER, grant_groups=["payroll admins"])

    def test_global_role_without_grant_groups(self, auth_manager):
        claims = {"upn": "jdoe@example.com", "name": "John Doe", "role": "Airflow Users"}

        assert auth_manager.get_user_from_claims(claims) == _user(USER)

    def test_connection_grant_only(self, auth_manager):
        claims = {"upn": "jdoe@example.com", "name": "John Doe", "groups": ["Conn Only"]}

        assert auth_manager.get_user_from_claims(claims) == CONN_ONLY

    def test_no_role_nor_grant(self, auth_manager):
        with pytest.raises(PermissionError, match="^User jdoe@example.com is not mapped to an Airflow role$"):
            auth_manager.get_user_from_claims({"upn": "jdoe@example.com", "groups": ["Domain Users"]})

    def test_team_grant_groups(self, team_auth_manager):
        claims = {"upn": "jdoe@example.com", "name": "John Doe", "groups": ["Team A Finance", "Team B Users"]}

        assert team_auth_manager.get_user_from_claims(claims) == _user(
            teams={"team_b": USER}, grant_groups=["team a finance"]
        )


class TestSerializeGrantGroups:
    def test_round_trip(self, auth_manager):
        user = _user(VIEWER, grant_groups=["conn only", "finance auditors"])

        serialized = auth_manager.serialize_user(user)

        assert serialized == {
            "sub": "jdoe@example.com",
            "name": "John Doe",
            "role": "VIEWER",
            "teams": {},
            "grant_groups": ["conn only", "finance auditors"],
        }
        assert json.loads(json.dumps(serialized)) == serialized
        assert auth_manager.deserialize_user(serialized) == user

    def test_round_trip_grant_only(self, auth_manager):
        serialized = auth_manager.serialize_user(FINANCE_OPS)

        assert serialized == {
            "sub": "jdoe@example.com",
            "name": "John Doe",
            "role": None,
            "teams": {},
            "grant_groups": ["finance ops"],
        }
        assert auth_manager.deserialize_user(serialized) == FINANCE_OPS

    def test_deserialize_token_without_grant_groups(self, auth_manager):
        token = {"sub": "jdoe@example.com", "name": "John Doe", "role": "USER", "teams": {}}

        assert auth_manager.deserialize_user(token) == _user(USER)

    def test_legacy_dag_groups_give_no_access(self, auth_manager):
        token = {"sub": "jdoe@example.com", "name": "John Doe", "role": None, "dag_groups": ["finance ops"]}

        user = auth_manager.deserialize_user(token)

        assert user.grant_groups == []
        assert _is_authorized_dag(auth_manager, "GET", user, "finance_daily") is False
        assert auth_manager.filter_authorized_menu_items(list(MenuItem), user=user) == []


class TestIsAuthorizedDagWithGrants:
    @pytest.mark.parametrize(
        ("user", "method", "dag_id", "expected"),
        [
            (FINANCE_OPS, "GET", "finance_daily", True),
            (FINANCE_OPS, "POST", "finance_daily", True),
            (FINANCE_OPS, "PUT", "finance_daily", True),
            (FINANCE_OPS, "DELETE", "finance_daily", True),
            (FINANCE_OPS, "GET", "hr_daily", False),
            (FINANCE_OPS, "POST", "hr_daily", False),
            (FINANCE_OPS, "GET", "Finance_daily", False),
            (FINANCE_OPS, "GET", "payroll_export", False),
            (FINANCE_AUDITOR, "GET", "finance_daily", True),
            (FINANCE_AUDITOR, "POST", "finance_daily", False),
            (FINANCE_AUDITOR, "PUT", "finance_daily", False),
            (FINANCE_AUDITOR, "DELETE", "finance_daily", False),
            (FINANCE_AUDITOR, "GET", "hr_daily", False),
            (PAYROLL_ADMIN, "GET", "payroll_export", True),
            (PAYROLL_ADMIN, "POST", "payroll_export", True),
            (PAYROLL_ADMIN, "GET", "payroll_export_v2", False),
            (PAYROLL_ADMIN, "GET", "finance_daily", False),
            (_user(grant_groups=["finance auditors", "finance ops"]), "POST", "finance_daily", True),
            (_user(grant_groups=["unknown group"]), "GET", "finance_daily", False),
            (_user(grant_groups=["Finance Ops"]), "GET", "finance_daily", False),
        ],
    )
    def test_grant_only_user(self, auth_manager, user, method, dag_id, expected):
        assert _is_authorized_dag(auth_manager, method, user, dag_id) is expected

    @pytest.mark.parametrize(
        "access_entity", [DagAccessEntity.RUN, DagAccessEntity.TASK_INSTANCE, DagAccessEntity.TASK_LOGS]
    )
    @pytest.mark.parametrize(
        ("user", "method", "dag_id", "expected"),
        [
            (FINANCE_OPS, "POST", "finance_daily", True),
            (FINANCE_OPS, "POST", "hr_daily", False),
            (FINANCE_AUDITOR, "GET", "finance_daily", True),
            (FINANCE_AUDITOR, "POST", "finance_daily", False),
            (FINANCE_AUDITOR, "GET", "hr_daily", False),
        ],
    )
    def test_grant_only_user_dag_entities(self, auth_manager, access_entity, user, method, dag_id, expected):
        assert _is_authorized_dag(auth_manager, method, user, dag_id, access_entity=access_entity) is expected

    @pytest.mark.parametrize(
        ("user", "method", "dag_id", "expected"),
        [
            (_user(VIEWER, grant_groups=["finance ops"]), "POST", "finance_daily", True),
            (_user(VIEWER, grant_groups=["finance ops"]), "POST", "hr_daily", False),
            (_user(VIEWER, grant_groups=["finance ops"]), "GET", "hr_daily", True),
            (_user(OP, grant_groups=["finance auditors"]), "POST", "finance_daily", True),
            (_user(OP, grant_groups=["finance auditors"]), "POST", "hr_daily", True),
            (_user(USER, grant_groups=["finance auditors"]), "DELETE", "finance_daily", True),
            (_user(VIEWER, grant_groups=["finance auditors"]), "POST", "finance_daily", False),
        ],
    )
    def test_grants_add_to_global_role(self, auth_manager, user, method, dag_id, expected):
        assert _is_authorized_dag(auth_manager, method, user, dag_id) is expected

    @pytest.mark.parametrize(
        ("user", "method", "expected"),
        [
            (FINANCE_AUDITOR, "GET", True),
            (FINANCE_AUDITOR, "POST", False),
            (FINANCE_OPS, "GET", True),
            (FINANCE_OPS, "POST", False),
            (PAYROLL_ADMIN, "POST", False),
            (_user(VIEWER, grant_groups=["finance ops"]), "POST", False),
            (_user(USER, grant_groups=["finance ops"]), "POST", True),
            (_user(grant_groups=["unknown group"]), "GET", False),
            (_user(), "GET", False),
        ],
    )
    def test_without_dag_id_uses_highest_role_with_grants(self, auth_manager, user, method, expected):
        assert _is_authorized_dag(auth_manager, method, user) is expected
        assert _is_authorized_dag(auth_manager, method, user, team_name="team_a") is expected

    @pytest.mark.parametrize("user", [CONN_ONLY, POOL_WATCHER], ids=["connection", "pool"])
    @pytest.mark.parametrize("method", ["GET", "POST"])
    def test_other_kind_grant_gives_no_dag_access(self, auth_manager, user, method):
        assert _is_authorized_dag(auth_manager, method, user, "finance_daily") is False
        assert _is_authorized_dag(auth_manager, method, user) is False

    @pytest.mark.parametrize(("method", "expected"), [("GET", True), ("POST", False)])
    def test_backfill_naming_no_dag(self, auth_manager, method, expected):
        # Backfills name no Dag before Airflow 3.1.8, so a Dag grant must not authorize creating them.
        with pytest.warns(AirflowProviderDeprecationWarning, match="DagAccessEntity.RUN"):
            assert auth_manager.is_authorized_backfill(method=method, user=FINANCE_OPS) is expected

    @pytest.mark.parametrize(
        ("user", "dag_ids", "method", "expected"),
        [
            (
                FINANCE_AUDITOR,
                {"finance_a", "finance_b", "hr", "payroll_export"},
                "GET",
                {"finance_a", "finance_b"},
            ),
            (FINANCE_AUDITOR, {"finance_a", "finance_b", "hr", "payroll_export"}, "POST", set()),
            (FINANCE_OPS, {"finance_a", "Finance_b", "hr"}, "POST", {"finance_a"}),
            (
                _user(grant_groups=["finance auditors", "payroll admins"]),
                {"finance_a", "hr", "payroll_export"},
                "GET",
                {"finance_a", "payroll_export"},
            ),
            (_user(grant_groups=["unknown group"]), {"finance_a", "hr"}, "GET", set()),
        ],
    )
    def test_filter_authorized_dag_ids(self, auth_manager, user, dag_ids, method, expected):
        assert auth_manager.filter_authorized_dag_ids(dag_ids=dag_ids, user=user, method=method) == expected

    def test_removed_rule_revokes_access_of_existing_token(self):
        with conf_vars(GRANTS_CONF):
            auth_manager = AdfsAuthManager()
            token = auth_manager.serialize_user(
                auth_manager.get_user_from_claims(
                    {"upn": "jdoe@example.com", "name": "John Doe", "groups": ["Finance Ops"]}
                )
            )
            user = auth_manager.deserialize_user(token)
            assert _is_authorized_dag(auth_manager, "POST", user, "finance_daily") is True

        reduced = json.dumps({"Finance Auditors": [{"dags": "finance_*", "role": "VIEWER"}]})
        with conf_vars({**GRANTS_CONF, (CONF_SECTION_NAME, CONF_RESOURCE_ROLE_MAPPING_KEY): reduced}):
            auth_manager = AdfsAuthManager()
            user = auth_manager.deserialize_user(token)

            assert user.grant_groups == ["finance ops"]
            assert _is_authorized_dag(auth_manager, "GET", user, "finance_daily") is False
            assert _is_authorized_dag(auth_manager, "POST", user, "finance_daily") is False
            assert _is_authorized_dag(auth_manager, "GET", user) is False
            assert auth_manager.filter_authorized_dag_ids(dag_ids={"finance_daily"}, user=user) == set()
            assert auth_manager.filter_authorized_menu_items(list(MenuItem), user=user) == []

    def test_downgraded_rule_applies_to_existing_token(self):
        token = {"sub": "jdoe@example.com", "name": "John Doe", "role": None, "grant_groups": ["finance ops"]}
        downgraded = json.dumps({"Finance Ops": [{"dags": "finance_*", "role": "VIEWER"}]})
        with conf_vars({**GRANTS_CONF, (CONF_SECTION_NAME, CONF_RESOURCE_ROLE_MAPPING_KEY): downgraded}):
            auth_manager = AdfsAuthManager()
            user = auth_manager.deserialize_user(token)

            assert _is_authorized_dag(auth_manager, "GET", user, "finance_daily") is True
            assert _is_authorized_dag(auth_manager, "POST", user, "finance_daily") is False
            assert _is_authorized_dag(auth_manager, "POST", user) is False


@pytest.mark.parametrize(("method_name", "batch_method_name", "details", "resource_id"), RESOURCE_KINDS)
class TestIsAuthorizedResourceWithGrants:
    @pytest.mark.parametrize("method", ["GET", "POST", "PUT", "DELETE"])
    def test_matching_id(self, auth_manager, method_name, batch_method_name, details, resource_id, method):
        # ``POST`` with an ID is a creation through the bulk endpoint, which names each resource.
        check = getattr(auth_manager, method_name)

        assert check(method=method, user=FINANCE_OPS, details=details(resource_id)) is True

    @pytest.mark.parametrize("method", ["GET", "PUT"])
    def test_non_matching_id(
        self, auth_manager, method_name, batch_method_name, details, resource_id, method
    ):
        check = getattr(auth_manager, method_name)

        assert check(method=method, user=FINANCE_OPS, details=details("hr")) is False
        assert check(method=method, user=FINANCE_OPS, details=details(resource_id.upper())) is False

    @pytest.mark.parametrize(
        ("method", "expected"), [("GET", True), ("POST", False), ("PUT", False), ("DELETE", False)]
    )
    def test_without_id(
        self, auth_manager, method_name, batch_method_name, details, resource_id, method, expected
    ):
        # Lists are filtered per resource by core. Single creations, connection tests and bulk changes on
        # Airflow 3.0 name no resource, so grants never authorize them.
        check = getattr(auth_manager, method_name)

        assert check(method=method, user=FINANCE_OPS, details=details(None)) is expected
        assert check(method=method, user=FINANCE_OPS, details=None) is expected

    @pytest.mark.parametrize(
        ("user", "dag_grant_id"),
        [(FINANCE_AUDITOR, "finance_x"), (PLATFORM_ADMIN, "platform_x")],
        ids=["viewer", "admin"],
    )
    @pytest.mark.parametrize("method", ["GET", "PUT"])
    def test_dag_grant_gives_nothing(
        self, auth_manager, method_name, batch_method_name, details, resource_id, user, dag_grant_id, method
    ):
        # ``dag_grant_id`` matches the pattern of the user's Dag grant, which only applies to Dags.
        check = getattr(auth_manager, method_name)

        assert check(method=method, user=user, details=details(resource_id)) is False
        assert check(method=method, user=user, details=details(dag_grant_id)) is False
        assert check(method=method, user=user, details=details(None)) is False

    def test_batch(self, auth_manager, method_name, batch_method_name, details, resource_id):
        batch = getattr(auth_manager, batch_method_name)
        matching = [
            {"method": "POST", "details": details(resource_id)},
            {"method": "DELETE", "details": details(resource_id)},
        ]

        assert batch(requests=matching, user=FINANCE_OPS) is True
        assert (
            batch(requests=[*matching, {"method": "PUT", "details": details("hr")}], user=FINANCE_OPS)
            is False
        )
        assert (
            batch(requests=[*matching, {"method": "PUT", "details": details(None)}], user=FINANCE_OPS)
            is False
        )


class TestResourceGrantKinds:
    @pytest.mark.parametrize(
        ("method_name", "details"),
        [
            ("is_authorized_variable", VariableDetails(key="finance_rate")),
            ("is_authorized_variable", None),
            ("is_authorized_pool", PoolDetails(name="finance")),
            ("is_authorized_pool", None),
        ],
    )
    def test_connection_grant_gives_nothing_on_other_kinds(self, auth_manager, method_name, details):
        assert getattr(auth_manager, method_name)(method="GET", user=CONN_ONLY, details=details) is False

    @pytest.mark.parametrize(
        ("method", "details", "expected"),
        [
            ("GET", PoolDetails(name="finance"), True),
            ("GET", PoolDetails(name="finance_eu"), True),
            ("GET", PoolDetails(name="default_pool"), False),
            ("GET", None, True),
            ("PUT", PoolDetails(name="finance"), False),
            ("DELETE", PoolDetails(name="finance"), False),
        ],
    )
    def test_viewer_pool_grant(self, auth_manager, method, details, expected):
        assert auth_manager.is_authorized_pool(method=method, user=POOL_WATCHER, details=details) is expected

    @pytest.mark.parametrize(
        ("user", "method_name", "method", "details", "expected"),
        [
            (
                _user(VIEWER, grant_groups=["conn only"]),
                "is_authorized_connection",
                "GET",
                _connection("finance_x"),
                True,
            ),
            (
                _user(VIEWER, grant_groups=["conn only"]),
                "is_authorized_connection",
                "GET",
                _connection("hr"),
                False,
            ),
            (_user(VIEWER, grant_groups=["conn only"]), "is_authorized_connection", "GET", None, True),
            (
                _user(OP, grant_groups=["conn only"]),
                "is_authorized_connection",
                "PUT",
                _connection("hr"),
                True,
            ),
            (_user(USER, grant_groups=["finance ops"]), "is_authorized_pool", "PUT", _pool("finance"), True),
            (
                _user(USER, grant_groups=["finance ops"]),
                "is_authorized_pool",
                "PUT",
                _pool("default_pool"),
                False,
            ),
            (
                _user(USER, grant_groups=["finance ops"]),
                "is_authorized_pool",
                "GET",
                _pool("default_pool"),
                True,
            ),
        ],
    )
    def test_grants_add_to_global_role(self, auth_manager, user, method_name, method, details, expected):
        assert getattr(auth_manager, method_name)(method=method, user=user, details=details) is expected

    @pytest.mark.parametrize(
        ("filter_method_name", "ids_param", "ids", "expected"),
        [
            ("filter_authorized_connections", "conn_ids", {"finance_a", "Finance_b", "hr"}, {"finance_a"}),
            ("filter_authorized_variables", "variable_keys", {"finance_a", "hr"}, {"finance_a"}),
            ("filter_authorized_pools", "pool_names", {"finance", "finance_a", "default_pool"}, {"finance"}),
        ],
    )
    @pytest.mark.parametrize("method", ["GET", "PUT"])
    def test_filter_authorized(self, auth_manager, filter_method_name, ids_param, ids, expected, method):
        filter_method = getattr(auth_manager, filter_method_name)

        assert filter_method(**{ids_param: ids}, user=FINANCE_OPS, method=method) == expected
        assert filter_method(**{ids_param: ids}, user=FINANCE_OPS, method=method, team_name="team_a") == set()

    def test_removed_connection_grant_revokes_access_of_existing_token(self):
        token = {"sub": "jdoe@example.com", "name": "John Doe", "role": None, "grant_groups": ["conn only"]}
        with conf_vars(GRANTS_CONF):
            auth_manager = AdfsAuthManager()
            user = auth_manager.deserialize_user(token)
            assert auth_manager.is_authorized_connection(
                method="GET", user=user, details=_connection("finance_db")
            )

        reduced = json.dumps({"Finance Auditors": [{"dags": "finance_*", "role": "VIEWER"}]})
        with conf_vars({**GRANTS_CONF, (CONF_SECTION_NAME, CONF_RESOURCE_ROLE_MAPPING_KEY): reduced}):
            auth_manager = AdfsAuthManager()
            user = auth_manager.deserialize_user(token)

            assert (
                auth_manager.is_authorized_connection(
                    method="GET", user=user, details=_connection("finance_db")
                )
                is False
            )
            assert auth_manager.is_authorized_connection(method="GET", user=user) is False
            assert auth_manager.filter_authorized_connections(conn_ids={"finance_db"}, user=user) == set()
            assert auth_manager.filter_authorized_menu_items(list(MenuItem), user=user) == []

    def test_downgraded_pool_grant_applies_to_existing_token(self):
        token = {"sub": "jdoe@example.com", "name": "John Doe", "role": None, "grant_groups": ["finance ops"]}
        downgraded = json.dumps({"Finance Ops": [{"pools": "finance", "role": "VIEWER"}]})
        with conf_vars({**GRANTS_CONF, (CONF_SECTION_NAME, CONF_RESOURCE_ROLE_MAPPING_KEY): downgraded}):
            auth_manager = AdfsAuthManager()
            user = auth_manager.deserialize_user(token)

            assert auth_manager.is_authorized_pool(method="GET", user=user, details=_pool("finance")) is True
            assert auth_manager.is_authorized_pool(method="PUT", user=user, details=_pool("finance")) is False


GRANT_ONLY_USERS = [FINANCE_AUDITOR, FINANCE_OPS, PAYROLL_ADMIN, PLATFORM_ADMIN, POOL_WATCHER, CONN_ONLY]


@pytest.mark.parametrize("user", GRANT_ONLY_USERS, ids=lambda u: u.grant_groups[0])
class TestGrantOnlyUserOtherResources:
    @pytest.mark.parametrize(
        ("method_name", "details"),
        [
            ("is_authorized_connection", ConnectionDetails(conn_id="conn")),
            ("is_authorized_variable", VariableDetails(key="key")),
            ("is_authorized_pool", PoolDetails(name="default_pool")),
            ("is_authorized_asset", AssetDetails(id="1")),
            ("is_authorized_asset", None),
            ("is_authorized_asset_alias", AssetAliasDetails(id="1")),
            ("is_authorized_configuration", ConfigurationDetails(section="core")),
            ("is_authorized_configuration", None),
            ("is_authorized_team", TeamDetails(name="team_a")),
        ],
    )
    @pytest.mark.parametrize("method", ["GET", "POST", "PUT", "DELETE"])
    def test_denied(self, auth_manager, user, method_name, details, method):
        assert getattr(auth_manager, method_name)(method=method, user=user, details=details) is False

    @pytest.mark.parametrize("method", ["GET", "POST", "can_trigger"])
    def test_plugins_denied(self, auth_manager, user, method):
        assert (
            auth_manager.is_authorized_custom_view(method=method, resource_name="plugin", user=user) is False
        )

    @pytest.mark.parametrize(
        "access_view", [AccessView.AUDIT_LOGS_ALL, AccessView.IMPORT_ERRORS_ALL, AccessView.REPARSE_ALL]
    )
    def test_admin_views_denied(self, auth_manager, user, access_view):
        assert auth_manager.is_authorized_view(access_view=access_view, user=user) is False


@pytest.mark.parametrize(
    "user", [FINANCE_AUDITOR, PAYROLL_ADMIN, PLATFORM_ADMIN], ids=lambda u: u.grant_groups[0]
)
@pytest.mark.parametrize(
    ("method_name", "details"),
    [
        ("is_authorized_connection", ConnectionDetails()),
        ("is_authorized_connection", None),
        ("is_authorized_variable", VariableDetails()),
        ("is_authorized_variable", None),
        ("is_authorized_pool", None),
    ],
)
def test_dag_grant_gives_no_connection_variable_pool_list(auth_manager, user, method_name, details):
    assert getattr(auth_manager, method_name)(method="GET", user=user, details=details) is False


DAG_MENU_ITEMS = {"Audit Log", "Dag Bundles", "Dags", "Deadlines", "Required Actions", "XComs"}
OPEN_MENU_ITEMS = {"Docs", "Jobs", "Plugins", "Providers"}


def _menu_items(values: set[str]) -> list[MenuItem]:
    return [item for item in MenuItem if item.value in values]


class TestMenuItemsWithGrants:
    @pytest.mark.parametrize(
        "user", [FINANCE_AUDITOR, PAYROLL_ADMIN, PLATFORM_ADMIN], ids=["viewer", "op", "admin"]
    )
    def test_dag_grant(self, auth_manager, user):
        result = auth_manager.filter_authorized_menu_items(list(MenuItem), user=user)

        assert result == _menu_items(DAG_MENU_ITEMS | OPEN_MENU_ITEMS)

    @pytest.mark.parametrize(
        ("user", "values"),
        [
            (CONN_ONLY, {"Connections"} | OPEN_MENU_ITEMS),
            (POOL_WATCHER, {"Pools"} | OPEN_MENU_ITEMS),
            (FINANCE_OPS, DAG_MENU_ITEMS | {"Connections", "Variables", "Pools"} | OPEN_MENU_ITEMS),
            (_user(grant_groups=["unknown group"]), set()),
            (_user(VIEWER, grant_groups=["conn only"]), {item.value for item in MenuItem} - {"Variables"}),
        ],
    )
    def test_grants_add_menu_items_of_their_kind(self, auth_manager, user, values):
        result = auth_manager.filter_authorized_menu_items(list(MenuItem), user=user)

        assert result == _menu_items(values)


TEAM_A_FINANCE_TEAM_B_USER = _user(teams={"team_b": USER}, grant_groups=["team a finance"])
TEAM_A_VIEWER_FINANCE = _user(teams={"team_a": VIEWER}, grant_groups=["team a finance"])


class TestTeamScopedGrants:
    @pytest.mark.parametrize(
        ("user", "method", "dag_id", "team_name", "expected"),
        [
            (TEAM_A_FINANCE, "GET", "finance_daily", "team_a", True),
            (TEAM_A_FINANCE, "POST", "finance_daily", "team_a", True),
            (TEAM_A_FINANCE, "GET", "hr_daily", "team_a", False),
            (TEAM_A_FINANCE, "GET", "finance_daily", "team_b", False),
            (TEAM_A_FINANCE, "POST", "finance_daily", "team_b", False),
            (TEAM_A_FINANCE, "GET", "finance_daily", None, False),
            (TEAM_A_FINANCE, "GET", "finance_daily", "TEAM_A", False),
            (SHARED_FINANCE, "GET", "finance_daily", None, True),
            (SHARED_FINANCE, "POST", "finance_daily", None, False),
            (SHARED_FINANCE, "GET", "finance_daily", "team_a", False),
            (SHARED_FINANCE, "GET", "finance_daily", "team_b", False),
            (TEAM_A_VIEWER_FINANCE, "POST", "finance_daily", "team_a", True),
            (TEAM_A_VIEWER_FINANCE, "POST", "hr_daily", "team_a", False),
            (TEAM_A_VIEWER_FINANCE, "GET", "hr_daily", "team_a", True),
            (TEAM_A_VIEWER_FINANCE, "GET", "hr_daily", "team_b", False),
            (TEAM_A_FINANCE_TEAM_B_USER, "POST", "finance_daily", "team_a", True),
            (TEAM_A_FINANCE_TEAM_B_USER, "POST", "hr_daily", "team_b", True),
            (TEAM_A_FINANCE_TEAM_B_USER, "GET", "hr_daily", "team_a", False),
            (_user(OP, grant_groups=["team a finance"]), "GET", "finance_daily", "team_a", True),
            (_user(OP), "GET", "finance_daily", "team_a", False),
        ],
    )
    def test_is_authorized_dag(self, team_auth_manager, user, method, dag_id, team_name, expected):
        assert _is_authorized_dag(team_auth_manager, method, user, dag_id, team_name) is expected

    @pytest.mark.parametrize(
        ("team_name", "expected"),
        [("team_a", {"finance_a"}), ("team_b", set()), (None, set())],
    )
    def test_filter_authorized_dag_ids(self, team_auth_manager, team_name, expected):
        assert (
            team_auth_manager.filter_authorized_dag_ids(
                dag_ids={"finance_a", "hr"}, user=TEAM_A_FINANCE, method="POST", team_name=team_name
            )
            == expected
        )

    @pytest.mark.parametrize(("method_name", "batch_method_name", "details", "resource_id"), RESOURCE_KINDS)
    @pytest.mark.parametrize(
        ("team_name", "expected"), [("team_a", True), (None, False), ("team_b", False), ("TEAM_A", False)]
    )
    def test_team_grant_matches_its_team_only(
        self, team_auth_manager, method_name, batch_method_name, details, resource_id, team_name, expected
    ):
        check = getattr(team_auth_manager, method_name)

        assert check(method="PUT", user=TEAM_A_FINANCE, details=details(resource_id, team_name)) is expected
        assert check(method="PUT", user=TEAM_A_FINANCE, details=details("hr", team_name)) is False

    @pytest.mark.parametrize(("method_name", "batch_method_name", "details", "resource_id"), RESOURCE_KINDS)
    @pytest.mark.parametrize(
        ("method", "expected"), [("GET", True), ("POST", False), ("PUT", False), ("DELETE", False)]
    )
    def test_team_grant_without_id(
        self, team_auth_manager, method_name, batch_method_name, details, resource_id, method, expected
    ):
        # Single creations name the team of the body but no resource, so grants never authorize them.
        # Lists are filtered per resource by core.
        check = getattr(team_auth_manager, method_name)

        assert check(method=method, user=TEAM_A_FINANCE, details=details(None, "team_a")) is expected

    @pytest.mark.parametrize(("team_name", "expected"), [(None, True), ("team_a", False), ("team_b", False)])
    def test_no_team_grant_matches_no_team_resources_only(self, team_auth_manager, team_name, expected):
        details = _connection("finance_db", team_name)

        assert (
            team_auth_manager.is_authorized_connection(method="PUT", user=SHARED_FINANCE, details=details)
            is expected
        )

    @pytest.mark.parametrize(("conn_id", "expected"), [("finance_db", True), ("hr", False)])
    def test_grants_combine_with_team_roles(self, team_auth_manager, conn_id, expected):
        details = _connection(conn_id, "team_a")

        assert (
            team_auth_manager.is_authorized_connection(
                method="GET", user=TEAM_A_VIEWER_FINANCE, details=details
            )
            is expected
        )

    @pytest.mark.parametrize(
        ("filter_method_name", "ids_param", "team_name", "expected"),
        [
            ("filter_authorized_connections", "conn_ids", "team_a", {"finance_x"}),
            ("filter_authorized_connections", "conn_ids", None, set()),
            ("filter_authorized_variables", "variable_keys", "team_a", {"finance_x"}),
            ("filter_authorized_variables", "variable_keys", "team_b", set()),
            ("filter_authorized_pools", "pool_names", "team_a", {"finance"}),
            ("filter_authorized_pools", "pool_names", None, set()),
        ],
    )
    def test_filter_authorized(self, team_auth_manager, filter_method_name, ids_param, team_name, expected):
        filter_method = getattr(team_auth_manager, filter_method_name)

        assert (
            filter_method(
                **{ids_param: {"finance", "finance_x", "hr"}},
                user=TEAM_A_FINANCE,
                method="PUT",
                team_name=team_name,
            )
            == expected
        )

    @pytest.mark.parametrize("method", ["GET", "POST"])
    def test_team_grant_gives_no_team_access(self, team_auth_manager, method):
        assert (
            team_auth_manager.is_authorized_team(
                method=method, user=TEAM_A_FINANCE, details=TeamDetails(name="team_a")
            )
            is False
        )

    def test_filter_authorized_teams(self, team_auth_manager):
        assert (
            team_auth_manager.filter_authorized_teams(teams_names={"team_a", "team_b"}, user=TEAM_A_FINANCE)
            == set()
        )
