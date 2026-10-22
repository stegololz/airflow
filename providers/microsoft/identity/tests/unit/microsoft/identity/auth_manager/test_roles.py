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
    get_claim_values,
    get_role_by_name,
    parse_role_mapping,
    parse_team_role_mapping,
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
