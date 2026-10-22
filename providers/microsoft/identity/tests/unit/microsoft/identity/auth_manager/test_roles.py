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

import pytest

from airflow.providers.microsoft.identity.auth_manager.oidc import AdfsAuthenticationError
from airflow.providers.microsoft.identity.auth_manager.roles import (
    AdfsAuthManagerRole,
    DagGrant,
    get_claim_values,
    get_dag_role,
    get_role_by_name,
    parse_dag_role_mapping,
    parse_role_mapping,
    parse_team_role_mapping,
    resolve_dag_groups,
    resolve_role,
    resolve_team_roles,
    resolve_username,
)

USERNAME_CLAIMS = ["upn", "unique_name", "email", "sub"]
ROLE_URI_CLAIM = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
ROLES_CLAIMS = ["role", "roles", "group", "groups", ROLE_URI_CLAIM]


class TestResolveUsername:
    @pytest.mark.parametrize(
        ("claims", "expected"),
        [
            (
                {"upn": "jdoe@example.com", "unique_name": "EXAMPLE\\jdoe", "sub": "opaque"},
                "jdoe@example.com",
            ),
            ({"unique_name": "EXAMPLE\\jdoe", "sub": "opaque"}, "EXAMPLE\\jdoe"),
            ({"upn": "  ", "unique_name": " jdoe ", "sub": "opaque"}, "jdoe"),
            ({"upn": ["jdoe@example.com"], "email": "jdoe@example.com"}, "jdoe@example.com"),
            ({"name": "Doe John", "sub": "opaque"}, "opaque"),
        ],
    )
    def test_first_non_blank_string_claim_is_used(self, claims, expected):
        assert resolve_username(claims, USERNAME_CLAIMS, strip_domain=False) == expected

    @pytest.mark.parametrize(
        ("claims", "expected"),
        [
            ({"unique_name": "EXAMPLE\\jdoe"}, "jdoe"),
            ({"unique_name": "jdoe"}, "jdoe"),
            ({"unique_name": "EXAMPLE\\", "email": "jdoe@example.com"}, "jdoe@example.com"),
        ],
    )
    def test_strip_domain(self, claims, expected):
        assert resolve_username(claims, USERNAME_CLAIMS, strip_domain=True) == expected

    def test_no_username_claim(self):
        with pytest.raises(AdfsAuthenticationError):
            resolve_username({"name": "Doe John", "upn": ""}, USERNAME_CLAIMS, strip_domain=False)


class TestGetClaimValues:
    @pytest.mark.parametrize(
        ("claims", "expected"),
        [
            ({"role": "Airflow Users"}, ["Airflow Users"]),
            ({"role": ["Airflow Users", "Domain Users"]}, ["Airflow Users", "Domain Users"]),
            ({"role": ["Airflow Users", 42, None]}, ["Airflow Users"]),
            ({ROLE_URI_CLAIM: "Airflow Admins"}, ["Airflow Admins"]),
            ({"role": "Airflow Users", "group": ["Airflow Admins"]}, ["Airflow Users", "Airflow Admins"]),
            ({"role": {"name": "Airflow Users"}, "unrelated": "Airflow Admins"}, []),
        ],
    )
    def test_get_claim_values(self, claims, expected):
        assert get_claim_values(claims, ROLES_CLAIMS) == expected


class TestParseRoleMapping:
    def test_valid_mapping(self):
        assert parse_role_mapping('{"Airflow Admins": "ADMIN", "CN=Ops,OU=Groups": "op"}') == {
            "airflow admins": AdfsAuthManagerRole.ADMIN,
            "cn=ops,ou=groups": AdfsAuthManagerRole.OP,
        }

    @pytest.mark.parametrize(
        ("raw", "match"),
        [
            ("{not json", "not valid JSON"),
            ('["Airflow Admins"]', "JSON object"),
            ('{"Airflow Admins": "SUPERUSER"}', "'Airflow Admins'"),
            ('{"Airflow Admins": 3}', "'Airflow Admins'"),
            ('{"Airflow Admins": "ADMIN", "AIRFLOW ADMINS": "VIEWER"}', "'AIRFLOW ADMINS'"),
        ],
    )
    def test_invalid_mapping(self, raw, match):
        with pytest.raises(ValueError, match=match):
            parse_role_mapping(raw)


def test_get_role_by_name_rejects_unknown_role():
    with pytest.raises(ValueError, match="VIEWER, USER, OP, ADMIN"):
        get_role_by_name("SUPERUSER")


class TestResolveRole:
    MAPPING = {
        "airflow admins": AdfsAuthManagerRole.ADMIN,
        "airflow users": AdfsAuthManagerRole.USER,
    }

    @pytest.mark.parametrize(
        ("values", "default_role", "expected"),
        [
            (["Airflow Users", "Airflow Admins"], None, AdfsAuthManagerRole.ADMIN),
            (["AIRFLOW USERS"], None, AdfsAuthManagerRole.USER),
            (["Domain Users", "Airflow Users"], AdfsAuthManagerRole.OP, AdfsAuthManagerRole.USER),
            (["Domain Users"], AdfsAuthManagerRole.VIEWER, AdfsAuthManagerRole.VIEWER),
            (["Domain Users"], None, None),
            ([], None, None),
        ],
    )
    def test_resolve_role(self, values, default_role, expected):
        assert resolve_role(values, self.MAPPING, default_role) == expected


class TestParseTeamRoleMapping:
    def test_valid_mapping(self):
        assert parse_team_role_mapping(
            '{"Team A Ops": "team_a:OP", "CN=B,OU=Groups": " team_b : viewer", "Ns": "ns:x:admin"}'
        ) == {
            "team a ops": ("team_a", AdfsAuthManagerRole.OP),
            "cn=b,ou=groups": ("team_b", AdfsAuthManagerRole.VIEWER),
            "ns": ("ns:x", AdfsAuthManagerRole.ADMIN),
        }

    @pytest.mark.parametrize(
        ("raw", "match"),
        [
            ("{not json", "not valid JSON"),
            ('["Team A Ops"]', "JSON object"),
            ('{"Team A Ops": "OP"}', "'Team A Ops' must be a '<team>:<role>' string"),
            ('{"Team A Ops": " :OP"}', "'Team A Ops' must be a '<team>:<role>' string"),
            ('{"Team A Ops": 3}', "'Team A Ops' must be a '<team>:<role>' string"),
            ('{"Team A Ops": "team_a:SUPERUSER"}', "Invalid role for team_role_mapping key 'Team A Ops'"),
            ('{"Team A Ops": "team_a:"}', "Invalid role for team_role_mapping key 'Team A Ops'"),
            (
                '{"Team A Ops": "team_a:OP", "TEAM A OPS": "team_b:OP"}',
                "'TEAM A OPS' is defined more than once",
            ),
        ],
    )
    def test_invalid_mapping(self, raw, match):
        with pytest.raises(ValueError, match=match):
            parse_team_role_mapping(raw)


class TestResolveTeamRoles:
    MAPPING = {
        "team a viewers": ("team_a", AdfsAuthManagerRole.VIEWER),
        "team a ops": ("team_a", AdfsAuthManagerRole.OP),
        "team b users": ("team_b", AdfsAuthManagerRole.USER),
    }

    @pytest.mark.parametrize(
        ("values", "expected"),
        [
            (["Team A Ops", "Team A Viewers"], {"team_a": AdfsAuthManagerRole.OP}),
            (["Team A Viewers", "Team A Ops"], {"team_a": AdfsAuthManagerRole.OP}),
            (
                ["TEAM B USERS", "Domain Users", "team a viewers"],
                {"team_b": AdfsAuthManagerRole.USER, "team_a": AdfsAuthManagerRole.VIEWER},
            ),
            (["Domain Users"], {}),
            ([], {}),
        ],
    )
    def test_resolve_team_roles(self, values, expected):
        assert resolve_team_roles(values, self.MAPPING) == expected


VIEWER = AdfsAuthManagerRole.VIEWER
USER = AdfsAuthManagerRole.USER
OP = AdfsAuthManagerRole.OP
ADMIN = AdfsAuthManagerRole.ADMIN


class TestParseDagRoleMapping:
    def test_valid_mapping(self):
        raw = (
            '{"Finance Ops": [{"dags": " finance_* ", "role": "user"}, {"dags": "payroll", "role": "OP"}],'
            ' "CN=Audit,OU=Groups": [{"dags": "*", "role": "VIEWER"}]}'
        )

        assert parse_dag_role_mapping(raw, multi_team=False) == {
            "finance ops": [DagGrant("finance_*", USER, None), DagGrant("payroll", OP, None)],
            "cn=audit,ou=groups": [DagGrant("*", VIEWER, None)],
        }

    def test_valid_mapping_with_teams(self):
        raw = (
            '{"Team A Finance": [{"dags": "finance_*", "role": "ADMIN", "team": " team_a "},'
            ' {"dags": "shared", "role": "VIEWER", "team": null}]}'
        )

        assert parse_dag_role_mapping(raw, multi_team=True) == {
            "team a finance": [DagGrant("finance_*", ADMIN, "team_a"), DagGrant("shared", VIEWER, None)],
        }

    def test_empty_object(self):
        assert parse_dag_role_mapping("{}", multi_team=False) == {}

    @pytest.mark.parametrize(
        ("raw", "multi_team", "match"),
        [
            ("{not json", False, "^dag_role_mapping is not valid JSON"),
            ('[{"dags": "a", "role": "OP"}]', False, "^dag_role_mapping must be a JSON object$"),
            ('"Finance Ops"', False, "^dag_role_mapping must be a JSON object$"),
            (
                '{"Finance Ops": []}',
                False,
                "^The value of dag_role_mapping key 'Finance Ops' must be a non-empty list$",
            ),
            (
                '{"Finance Ops": {"dags": "a", "role": "OP"}}',
                False,
                "^The value of dag_role_mapping key 'Finance Ops' must be a non-empty list$",
            ),
            (
                '{"Finance Ops": "OP"}',
                False,
                "^The value of dag_role_mapping key 'Finance Ops' must be a non-empty list$",
            ),
            (
                '{"Finance Ops": [{"dags": "a", "role": "OP", "teams": "team_a"}]}',
                True,
                "^Each rule of dag_role_mapping key 'Finance Ops' must be an object with 'dags', 'role' "
                "and an optional 'team'$",
            ),
            ('{"Finance Ops": [{"role": "OP"}]}', False, "^Each rule of dag_role_mapping key 'Finance Ops'"),
            ('{"Finance Ops": [{"dags": "a"}]}', False, "^Each rule of dag_role_mapping key 'Finance Ops'"),
            ('{"Finance Ops": ["finance_*"]}', False, "^Each rule of dag_role_mapping key 'Finance Ops'"),
            (
                '{"Finance Ops": [{"dags": "  ", "role": "OP"}]}',
                False,
                "^The 'dags' of dag_role_mapping key 'Finance Ops' must be a non-empty string$",
            ),
            (
                '{"Finance Ops": [{"dags": "", "role": "OP"}]}',
                False,
                "^The 'dags' of dag_role_mapping key 'Finance Ops' must be a non-empty string$",
            ),
            (
                '{"Finance Ops": [{"dags": ["a"], "role": "OP"}]}',
                False,
                "^The 'dags' of dag_role_mapping key 'Finance Ops' must be a non-empty string$",
            ),
            (
                '{"Finance Ops": [{"dags": "a", "role": "SUPERUSER"}]}',
                False,
                "^Invalid role for dag_role_mapping key 'Finance Ops'",
            ),
            (
                '{"Finance Ops": [{"dags": "a", "role": 3}]}',
                False,
                "^The 'role' of dag_role_mapping key 'Finance Ops' must be a string$",
            ),
            (
                '{"Finance Ops": [{"dags": "a", "role": "OP", "team": "team_a"}]}',
                False,
                "^The 'team' of dag_role_mapping key 'Finance Ops' must be a team name and requires "
                "\\[core\\] multi_team$",
            ),
            (
                '{"Finance Ops": [{"dags": "a", "role": "OP", "team": " "}]}',
                True,
                "^The 'team' of dag_role_mapping key 'Finance Ops' must be a team name",
            ),
            (
                '{"Finance Ops": [{"dags": "a", "role": "OP", "team": 1}]}',
                True,
                "^The 'team' of dag_role_mapping key 'Finance Ops' must be a team name",
            ),
            (
                '{"Finance Ops": [{"dags": "a", "role": "OP"}], "FINANCE OPS": [{"dags": "b", "role": "OP"}]}',
                False,
                "^dag_role_mapping key 'FINANCE OPS' is defined more than once \\(keys are case-insensitive\\)$",
            ),
        ],
    )
    def test_invalid_mapping(self, raw, multi_team, match):
        with pytest.raises(ValueError, match=match):
            parse_dag_role_mapping(raw, multi_team=multi_team)


DAG_MAPPING = {
    "finance ops": [DagGrant("finance_*", USER, None)],
    "finance auditors": [DagGrant("finance_*", VIEWER, None), DagGrant("audit_report", VIEWER, None)],
    "payroll admins": [DagGrant("payroll_export", OP, None)],
    "team a finance": [DagGrant("finance_*", OP, "team_a")],
}


class TestResolveDagGroups:
    @pytest.mark.parametrize(
        ("values", "expected"),
        [
            (["Finance Ops"], ["finance ops"]),
            (["FINANCE OPS", "finance ops", "Finance Auditors"], ["finance auditors", "finance ops"]),
            (["Payroll Admins", "Domain Users", "Finance Ops"], ["finance ops", "payroll admins"]),
            (["Domain Users", "Airflow Admins"], []),
            ([], []),
        ],
    )
    def test_resolve_dag_groups(self, values, expected):
        assert resolve_dag_groups(values, DAG_MAPPING) == expected


class TestGetDagRole:
    @pytest.mark.parametrize(
        ("dag_groups", "dag_id", "team_name", "expected"),
        [
            (["finance ops"], "finance_daily", None, USER),
            (["finance ops"], "finance_", None, USER),
            (["finance ops"], "finance", None, None),
            (["finance ops"], "Finance_daily", None, None),
            (["finance ops"], "FINANCE_DAILY", None, None),
            (["finance ops"], "my_finance_daily", None, None),
            (["finance auditors"], "audit_report", None, VIEWER),
            (["finance auditors"], "audit_report_2", None, None),
            (["finance auditors"], "Audit_Report", None, None),
            (["payroll admins"], "payroll_export", None, OP),
            (["payroll admins"], "payroll_exports", None, None),
            (["finance ops", "finance auditors"], "finance_daily", None, USER),
            (["finance auditors", "finance ops"], "finance_daily", None, USER),
            (["finance auditors", "finance ops", "team a finance"], "finance_daily", None, USER),
            (["team a finance"], "finance_daily", "team_a", OP),
            (["team a finance"], "finance_daily", "team_b", None),
            (["team a finance"], "finance_daily", None, None),
            (["finance ops"], "finance_daily", "team_a", None),
            (["finance ops", "team a finance"], "finance_daily", "team_a", OP),
            (["unknown group"], "finance_daily", None, None),
            (["unknown group", "finance auditors"], "finance_daily", None, VIEWER),
            (["Finance Ops"], "finance_daily", None, None),
            ([], "finance_daily", None, None),
        ],
    )
    def test_get_dag_role(self, dag_groups, dag_id, team_name, expected):
        assert get_dag_role(dag_groups, DAG_MAPPING, dag_id, team_name) == expected

    @pytest.mark.parametrize(
        ("pattern", "dag_id", "expected"),
        [
            ("etl_?", "etl_1", ADMIN),
            ("etl_?", "etl_10", None),
            ("etl_[ab]", "etl_b", ADMIN),
            ("etl_[ab]", "etl_c", None),
            ("etl_[!ab]", "etl_c", ADMIN),
            ("etl.daily", "etl.daily", ADMIN),
            ("etl.daily", "etlxdaily", None),
            ("*", "anything", ADMIN),
        ],
    )
    def test_fnmatch_patterns(self, pattern, dag_id, expected):
        mapping = {"g": [DagGrant(pattern, ADMIN, None)]}

        assert get_dag_role(["g"], mapping, dag_id, None) == expected
