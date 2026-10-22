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
from airflow.providers.microsoft.identity.auth_manager.adfs_auth_manager import AdfsAuthManager
from airflow.providers.microsoft.identity.auth_manager.constants import (
    CONF_DAG_ROLE_MAPPING_KEY,
    CONF_ROLE_MAPPING_KEY,
    CONF_SECTION_NAME,
    CONF_TEAM_ROLE_MAPPING_KEY,
)
from airflow.providers.microsoft.identity.auth_manager.roles import AdfsAuthManagerRole, DagGrant
from airflow.providers.microsoft.identity.auth_manager.user import AdfsAuthManagerUser

from tests_common.test_utils.config import conf_vars
from unit.microsoft.identity.auth_manager.adfs_fixtures import AUTH_MANAGER_CONF

VIEWER = AdfsAuthManagerRole.VIEWER
USER = AdfsAuthManagerRole.USER
OP = AdfsAuthManagerRole.OP
ADMIN = AdfsAuthManagerRole.ADMIN

DAG_ROLE_MAPPING = json.dumps(
    {
        "Finance Ops": [{"dags": "finance_*", "role": "USER"}],
        "Finance Auditors": [{"dags": "finance_*", "role": "VIEWER"}],
        "Payroll Admins": [{"dags": "payroll_export", "role": "OP"}],
        "Platform Admins": [{"dags": "platform_*", "role": "ADMIN"}],
    }
)
DAG_GRANTS_CONF = {**AUTH_MANAGER_CONF, (CONF_SECTION_NAME, CONF_DAG_ROLE_MAPPING_KEY): DAG_ROLE_MAPPING}

TEAM_ROLE_MAPPING = json.dumps({"Team A Viewers": "team_a:VIEWER", "Team B Users": "team_b:USER"})
TEAM_DAG_ROLE_MAPPING = json.dumps(
    {
        "Team A Finance": [{"dags": "finance_*", "role": "USER", "team": "team_a"}],
        "Shared Finance": [{"dags": "finance_*", "role": "VIEWER"}],
        "Team C Reports": [{"dags": "report_*", "role": "VIEWER", "team": "team_c"}],
    }
)
TEAM_DAG_GRANTS_CONF = {
    **AUTH_MANAGER_CONF,
    ("core", "multi_team"): "True",
    (CONF_SECTION_NAME, CONF_TEAM_ROLE_MAPPING_KEY): TEAM_ROLE_MAPPING,
    (CONF_SECTION_NAME, CONF_DAG_ROLE_MAPPING_KEY): TEAM_DAG_ROLE_MAPPING,
}


def _user(
    role: AdfsAuthManagerRole | None = None,
    teams: dict[str, AdfsAuthManagerRole] | None = None,
    dag_groups: list[str] | None = None,
) -> AdfsAuthManagerUser:
    return AdfsAuthManagerUser(
        user_id="jdoe@example.com", name="John Doe", role=role, teams=teams or {}, dag_groups=dag_groups or []
    )


FINANCE_OPS = _user(dag_groups=["finance ops"])
FINANCE_AUDITOR = _user(dag_groups=["finance auditors"])
PAYROLL_ADMIN = _user(dag_groups=["payroll admins"])
PLATFORM_ADMIN = _user(dag_groups=["platform admins"])
TEAM_A_FINANCE = _user(dag_groups=["team a finance"])
SHARED_FINANCE = _user(dag_groups=["shared finance"])


@pytest.fixture
def auth_manager():
    with conf_vars(DAG_GRANTS_CONF):
        yield AdfsAuthManager()


@pytest.fixture
def team_auth_manager():
    with conf_vars(TEAM_DAG_GRANTS_CONF):
        yield AdfsAuthManager()


def _is_authorized_dag(auth_manager, method, user, dag_id=None, team_name=None, access_entity=None):
    details = None if dag_id is None and team_name is None else DagDetails(id=dag_id, team_name=team_name)
    return auth_manager.is_authorized_dag(
        method=method, user=user, access_entity=access_entity, details=details
    )


class TestDagRoleMappingConfig:
    def test_get_dag_role_mapping(self, auth_manager):
        assert auth_manager.get_dag_role_mapping() == {
            "finance ops": [DagGrant("finance_*", USER, None)],
            "finance auditors": [DagGrant("finance_*", VIEWER, None)],
            "payroll admins": [DagGrant("payroll_export", OP, None)],
            "platform admins": [DagGrant("platform_*", ADMIN, None)],
        }

    def test_get_dag_role_mapping_unset(self):
        with conf_vars(AUTH_MANAGER_CONF):
            assert AdfsAuthManager().get_dag_role_mapping() == {}

    def test_init_with_only_dag_role_mapping(self):
        with conf_vars({**DAG_GRANTS_CONF, (CONF_SECTION_NAME, CONF_ROLE_MAPPING_KEY): None}):
            auth_manager = AdfsAuthManager()
            auth_manager.init()

            user = auth_manager.get_user_from_claims(
                {"upn": "jdoe@example.com", "name": "John Doe", "groups": ["Finance Ops"]}
            )

        assert user == _user(dag_groups=["finance ops"])

    @pytest.mark.parametrize(
        ("overrides", "match"),
        [
            (
                {
                    (CONF_SECTION_NAME, CONF_ROLE_MAPPING_KEY): None,
                    (CONF_SECTION_NAME, CONF_DAG_ROLE_MAPPING_KEY): None,
                },
                "^\\[adfs_auth_manager\\] role_mapping, team_role_mapping or dag_role_mapping must be set$",
            ),
            (
                {(CONF_SECTION_NAME, CONF_DAG_ROLE_MAPPING_KEY): "{not json"},
                "^dag_role_mapping is not valid JSON",
            ),
            (
                {(CONF_SECTION_NAME, CONF_DAG_ROLE_MAPPING_KEY): "[]"},
                "^dag_role_mapping must be a JSON object$",
            ),
            (
                {(CONF_SECTION_NAME, CONF_DAG_ROLE_MAPPING_KEY): '{"Finance Ops": []}'},
                "^The value of dag_role_mapping key 'Finance Ops' must be a non-empty list$",
            ),
            (
                {
                    (
                        CONF_SECTION_NAME,
                        CONF_DAG_ROLE_MAPPING_KEY,
                    ): '{"Finance Ops": [{"dags": "a", "role": "ROOT"}]}'
                },
                "^Invalid role for dag_role_mapping key 'Finance Ops'",
            ),
            (
                {
                    (CONF_SECTION_NAME, CONF_DAG_ROLE_MAPPING_KEY): (
                        '{"Finance Ops": [{"dags": "a", "role": "OP", "team": "team_a"}]}'
                    )
                },
                "^The 'team' of dag_role_mapping key 'Finance Ops' must be a team name and requires "
                "\\[core\\] multi_team$",
            ),
            (
                {
                    (CONF_SECTION_NAME, CONF_DAG_ROLE_MAPPING_KEY): (
                        '{"Finance Ops": [{"dags": "a", "role": "OP"}], "finance ops": [{"dags": "b", "role": "OP"}]}'
                    )
                },
                "^dag_role_mapping key 'finance ops' is defined more than once",
            ),
        ],
    )
    def test_init_invalid_config(self, overrides, match):
        with conf_vars({**AUTH_MANAGER_CONF, **overrides}):
            auth_manager = AdfsAuthManager()
            with pytest.raises(ValueError, match=match):
                auth_manager.init()

    def test_get_teams_includes_dag_grant_teams(self, team_auth_manager):
        assert team_auth_manager._get_teams() == {"team_a", "team_b", "team_c"}

    def test_get_teams_from_dag_grants_only(self):
        conf = {**TEAM_DAG_GRANTS_CONF, (CONF_SECTION_NAME, CONF_TEAM_ROLE_MAPPING_KEY): None}
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
    def test_init_multi_team_warns_on_unknown_dag_grant_team(self, _, team_auth_manager):
        with pytest.warns(UserWarning, match="Teams defined") as record:
            team_auth_manager.init()

        assert [str(w.message) for w in record] == [
            "Teams defined in the auth manager are not present in the database ({'team_c'}).",
        ]


class TestGetUserFromClaimsDagGrants:
    def test_stores_dag_groups(self, auth_manager):
        claims = {
            "upn": "jdoe@example.com",
            "name": "John Doe",
            "groups": ["FINANCE OPS", "Domain Users", "finance auditors", "Finance Ops"],
        }

        assert auth_manager.get_user_from_claims(claims) == _user(
            dag_groups=["finance auditors", "finance ops"]
        )

    def test_global_role_and_dag_groups(self, auth_manager):
        claims = {
            "upn": "jdoe@example.com",
            "name": "John Doe",
            "role": ["Airflow Viewers", "Payroll Admins"],
        }

        assert auth_manager.get_user_from_claims(claims) == _user(VIEWER, dag_groups=["payroll admins"])

    def test_global_role_without_dag_groups(self, auth_manager):
        claims = {"upn": "jdoe@example.com", "name": "John Doe", "role": "Airflow Users"}

        assert auth_manager.get_user_from_claims(claims) == _user(USER)

    def test_no_role_nor_dag_grant(self, auth_manager):
        with pytest.raises(PermissionError, match="^User jdoe@example.com is not mapped to an Airflow role$"):
            auth_manager.get_user_from_claims({"upn": "jdoe@example.com", "groups": ["Domain Users"]})

    def test_team_dag_groups(self, team_auth_manager):
        claims = {"upn": "jdoe@example.com", "name": "John Doe", "groups": ["Team A Finance", "Team B Users"]}

        assert team_auth_manager.get_user_from_claims(claims) == _user(
            teams={"team_b": USER}, dag_groups=["team a finance"]
        )


class TestSerializeDagGroups:
    def test_round_trip(self, auth_manager):
        user = _user(VIEWER, dag_groups=["finance auditors", "finance ops"])

        serialized = auth_manager.serialize_user(user)

        assert serialized == {
            "sub": "jdoe@example.com",
            "name": "John Doe",
            "role": "VIEWER",
            "teams": {},
            "dag_groups": ["finance auditors", "finance ops"],
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
            "dag_groups": ["finance ops"],
        }
        assert auth_manager.deserialize_user(serialized) == FINANCE_OPS

    def test_deserialize_token_without_dag_groups(self, auth_manager):
        token = {"sub": "jdoe@example.com", "name": "John Doe", "role": "USER", "teams": {}}

        user = auth_manager.deserialize_user(token)

        assert user == _user(USER)
        assert user.dag_groups == []


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
            (_user(dag_groups=["finance auditors", "finance ops"]), "POST", "finance_daily", True),
            (_user(dag_groups=["unknown group"]), "GET", "finance_daily", False),
            (_user(dag_groups=["Finance Ops"]), "GET", "finance_daily", False),
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
            (_user(VIEWER, dag_groups=["finance ops"]), "POST", "finance_daily", True),
            (_user(VIEWER, dag_groups=["finance ops"]), "POST", "hr_daily", False),
            (_user(VIEWER, dag_groups=["finance ops"]), "GET", "hr_daily", True),
            (_user(OP, dag_groups=["finance auditors"]), "POST", "finance_daily", True),
            (_user(OP, dag_groups=["finance auditors"]), "POST", "hr_daily", True),
            (_user(USER, dag_groups=["finance auditors"]), "DELETE", "finance_daily", True),
            (_user(VIEWER, dag_groups=["finance auditors"]), "POST", "finance_daily", False),
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
            (_user(VIEWER, dag_groups=["finance ops"]), "POST", False),
            (_user(USER, dag_groups=["finance ops"]), "POST", True),
            (_user(dag_groups=["unknown group"]), "GET", False),
            (_user(), "GET", False),
        ],
    )
    def test_without_dag_id_uses_highest_role_with_grants(self, auth_manager, user, method, expected):
        assert _is_authorized_dag(auth_manager, method, user) is expected
        assert _is_authorized_dag(auth_manager, method, user, team_name="team_a") is expected

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
                _user(dag_groups=["finance auditors", "payroll admins"]),
                {"finance_a", "hr", "payroll_export"},
                "GET",
                {"finance_a", "payroll_export"},
            ),
            (_user(dag_groups=["unknown group"]), {"finance_a", "hr"}, "GET", set()),
        ],
    )
    def test_filter_authorized_dag_ids(self, auth_manager, user, dag_ids, method, expected):
        assert auth_manager.filter_authorized_dag_ids(dag_ids=dag_ids, user=user, method=method) == expected

    def test_removed_rule_revokes_access_of_existing_token(self):
        with conf_vars(DAG_GRANTS_CONF):
            auth_manager = AdfsAuthManager()
            token = auth_manager.serialize_user(
                auth_manager.get_user_from_claims(
                    {"upn": "jdoe@example.com", "name": "John Doe", "groups": ["Finance Ops"]}
                )
            )
            user = auth_manager.deserialize_user(token)
            assert _is_authorized_dag(auth_manager, "POST", user, "finance_daily") is True

        reduced = json.dumps({"Finance Auditors": [{"dags": "finance_*", "role": "VIEWER"}]})
        with conf_vars({**DAG_GRANTS_CONF, (CONF_SECTION_NAME, CONF_DAG_ROLE_MAPPING_KEY): reduced}):
            auth_manager = AdfsAuthManager()
            user = auth_manager.deserialize_user(token)

            assert user.dag_groups == ["finance ops"]
            assert _is_authorized_dag(auth_manager, "GET", user, "finance_daily") is False
            assert _is_authorized_dag(auth_manager, "POST", user, "finance_daily") is False
            assert _is_authorized_dag(auth_manager, "GET", user) is False
            assert auth_manager.filter_authorized_dag_ids(dag_ids={"finance_daily"}, user=user) == set()
            assert auth_manager.filter_authorized_menu_items(list(MenuItem), user=user) == []

    def test_downgraded_rule_applies_to_existing_token(self):
        token = {"sub": "jdoe@example.com", "name": "John Doe", "role": None, "dag_groups": ["finance ops"]}
        downgraded = json.dumps({"Finance Ops": [{"dags": "finance_*", "role": "VIEWER"}]})
        with conf_vars({**DAG_GRANTS_CONF, (CONF_SECTION_NAME, CONF_DAG_ROLE_MAPPING_KEY): downgraded}):
            auth_manager = AdfsAuthManager()
            user = auth_manager.deserialize_user(token)

            assert _is_authorized_dag(auth_manager, "GET", user, "finance_daily") is True
            assert _is_authorized_dag(auth_manager, "POST", user, "finance_daily") is False
            assert _is_authorized_dag(auth_manager, "POST", user) is False


GRANT_ONLY_USERS = [FINANCE_AUDITOR, FINANCE_OPS, PAYROLL_ADMIN, PLATFORM_ADMIN]


@pytest.mark.parametrize("user", GRANT_ONLY_USERS, ids=lambda u: u.dag_groups[0])
class TestGrantOnlyUserOtherResources:
    @pytest.mark.parametrize(
        ("method_name", "details"),
        [
            ("is_authorized_connection", ConnectionDetails(conn_id="conn")),
            ("is_authorized_connection", ConnectionDetails()),
            ("is_authorized_connection", None),
            ("is_authorized_variable", VariableDetails(key="key")),
            ("is_authorized_variable", VariableDetails()),
            ("is_authorized_variable", None),
            ("is_authorized_pool", PoolDetails(name="default_pool")),
            ("is_authorized_pool", None),
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


class TestMenuItemsWithGrants:
    @pytest.mark.parametrize(
        ("user", "hidden_items"),
        [
            (FINANCE_AUDITOR, {MenuItem.CONNECTIONS, MenuItem.VARIABLES}),
            (FINANCE_OPS, {MenuItem.CONNECTIONS, MenuItem.VARIABLES}),
            (_user(dag_groups=["unknown group"]), set(MenuItem)),
        ],
    )
    def test_filter_authorized_menu_items(self, auth_manager, user, hidden_items):
        menu_items = list(MenuItem)

        result = auth_manager.filter_authorized_menu_items(menu_items, user=user)

        assert result == [item for item in menu_items if item not in hidden_items]

    @pytest.mark.xfail(
        strict=True,
        reason="An OP or ADMIN Dag grant shows the Connections and Variables menu entries that it cannot use",
    )
    @pytest.mark.parametrize("user", [PAYROLL_ADMIN, PLATFORM_ADMIN], ids=["op", "admin"])
    def test_op_grant_hides_connections_and_variables(self, auth_manager, user):
        result = auth_manager.filter_authorized_menu_items(list(MenuItem), user=user)

        assert MenuItem.CONNECTIONS not in result
        assert MenuItem.VARIABLES not in result


TEAM_A_FINANCE_TEAM_B_USER = _user(teams={"team_b": USER}, dag_groups=["team a finance"])
TEAM_A_VIEWER_FINANCE = _user(teams={"team_a": VIEWER}, dag_groups=["team a finance"])


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
            (_user(OP, dag_groups=["team a finance"]), "GET", "finance_daily", "team_a", True),
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

    @pytest.mark.parametrize(
        ("method_name", "details"),
        [
            ("is_authorized_connection", ConnectionDetails(conn_id="c", team_name="team_a")),
            ("is_authorized_variable", VariableDetails(key="k", team_name="team_a")),
            ("is_authorized_pool", PoolDetails(name="p", team_name="team_a")),
            ("is_authorized_team", TeamDetails(name="team_a")),
        ],
    )
    @pytest.mark.parametrize("method", ["GET", "POST"])
    def test_team_grant_gives_no_team_resource_access(self, team_auth_manager, method_name, details, method):
        assert (
            getattr(team_auth_manager, method_name)(method=method, user=TEAM_A_FINANCE, details=details)
            is False
        )

    def test_filter_authorized_teams(self, team_auth_manager):
        assert (
            team_auth_manager.filter_authorized_teams(teams_names={"team_a", "team_b"}, user=TEAM_A_FINANCE)
            == set()
        )
