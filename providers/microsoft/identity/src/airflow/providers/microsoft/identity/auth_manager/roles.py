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

"""Map AD FS claims to an Airflow user name and role."""

from __future__ import annotations

import fnmatch
import json
import logging
from collections.abc import Mapping, Sequence
from enum import IntEnum
from typing import Any, NamedTuple

from airflow.providers.microsoft.identity.auth_manager.oidc import AdfsAuthenticationError

log = logging.getLogger(__name__)


class AdfsAuthManagerRole(IntEnum):
    """
    Airflow roles of the AD FS auth manager.

    Each role grants the permissions of the roles below it.
    """

    VIEWER = 0
    USER = 1
    OP = 2
    ADMIN = 3


def get_role_by_name(name: str) -> AdfsAuthManagerRole:
    """
    Return the role with the given name, case-insensitively.

    :param name: role name, e.g. ``ADMIN``
    """
    try:
        return AdfsAuthManagerRole[name.strip().upper()]
    except KeyError:
        raise ValueError(
            f"Unknown Airflow role {name!r}, expected one of {', '.join(AdfsAuthManagerRole.__members__)}"
        ) from None


def parse_role_mapping(raw: str) -> dict[str, AdfsAuthManagerRole]:
    """
    Parse the ``role_mapping`` option.

    Keys are case-folded because Active Directory group names are case-insensitive.

    :param raw: JSON object mapping claim values to role names
    :return: mapping of case-folded claim values to roles
    """
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"role_mapping is not valid JSON: {e.msg} (position {e.pos})") from None
    if not isinstance(loaded, dict):
        raise ValueError("role_mapping must be a JSON object")
    mapping: dict[str, AdfsAuthManagerRole] = {}
    for key, role_name in loaded.items():
        if not isinstance(role_name, str):
            raise ValueError(f"The role of role_mapping key {key!r} must be a string")
        try:
            role = get_role_by_name(role_name)
        except ValueError as e:
            raise ValueError(f"Invalid role for role_mapping key {key!r}: {e}") from None
        folded_key = key.casefold()
        if folded_key in mapping:
            raise ValueError(
                f"role_mapping key {key!r} is defined more than once (keys are case-insensitive)"
            )
        mapping[folded_key] = role
    return mapping


def parse_team_role_mapping(raw: str) -> dict[str, tuple[str, AdfsAuthManagerRole]]:
    """
    Parse the ``team_role_mapping`` option.

    :param raw: JSON object mapping claim values to ``"<team>:<role>"`` strings
    :return: mapping of case-folded claim values to ``(team, role)`` tuples
    """
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"team_role_mapping is not valid JSON: {e.msg} (position {e.pos})") from None
    if not isinstance(loaded, dict):
        raise ValueError("team_role_mapping must be a JSON object")
    mapping: dict[str, tuple[str, AdfsAuthManagerRole]] = {}
    for key, value in loaded.items():
        team, _, role_name = value.rpartition(":") if isinstance(value, str) else ("", "", "")
        if not team.strip():
            raise ValueError(f"The value of team_role_mapping key {key!r} must be a '<team>:<role>' string")
        try:
            role = get_role_by_name(role_name)
        except ValueError as e:
            raise ValueError(f"Invalid role for team_role_mapping key {key!r}: {e}") from None
        folded_key = key.casefold()
        if folded_key in mapping:
            raise ValueError(
                f"team_role_mapping key {key!r} is defined more than once (keys are case-insensitive)"
            )
        mapping[folded_key] = (team.strip(), role)
    return mapping


def resolve_team_roles(
    values: Sequence[str], mapping: Mapping[str, tuple[str, AdfsAuthManagerRole]]
) -> dict[str, AdfsAuthManagerRole]:
    """
    Return the highest role of the user in each team mapped from the claim values.

    :param values: group or role claim values
    :param mapping: mapping returned by :func:`parse_team_role_mapping`
    """
    teams: dict[str, AdfsAuthManagerRole] = {}
    for value in values:
        if (team_role := mapping.get(value.casefold())) is not None:
            team, role = team_role
            teams[team] = max(role, teams.get(team, role))
    return teams


class DagGrant(NamedTuple):
    """
    Role given on the Dags whose ID matches a pattern.

    :param dags: ``fnmatch`` pattern matched case-sensitively against the Dag ID
    :param role: role given on the matching Dags
    :param team: team the matching Dags must belong to, or ``None`` for Dags of no team
    """

    dags: str
    role: AdfsAuthManagerRole
    team: str | None


_DAG_GRANT_KEYS = frozenset({"dags", "role", "team"})


def parse_dag_role_mapping(raw: str, *, multi_team: bool) -> dict[str, list[DagGrant]]:
    """
    Parse the ``dag_role_mapping`` option.

    :param raw: JSON object mapping claim values to lists of ``{"dags", "role", "team"}`` objects
    :param multi_team: whether multi-team mode is enabled; ``team`` is only allowed then
    :return: mapping of case-folded claim values to their Dag grants
    """
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"dag_role_mapping is not valid JSON: {e.msg} (position {e.pos})") from None
    if not isinstance(loaded, dict):
        raise ValueError("dag_role_mapping must be a JSON object")
    mapping: dict[str, list[DagGrant]] = {}
    for key, rules in loaded.items():
        if not isinstance(rules, list) or not rules:
            raise ValueError(f"The value of dag_role_mapping key {key!r} must be a non-empty list")
        grants = []
        for rule in rules:
            if not isinstance(rule, dict) or not {"dags", "role"} <= rule.keys() <= _DAG_GRANT_KEYS:
                raise ValueError(
                    f"Each rule of dag_role_mapping key {key!r} must be an object with 'dags', 'role' "
                    "and an optional 'team'"
                )
            dags, team = rule["dags"], rule.get("team")
            if not isinstance(dags, str) or not dags.strip():
                raise ValueError(f"The 'dags' of dag_role_mapping key {key!r} must be a non-empty string")
            if team is not None and (not multi_team or not isinstance(team, str) or not team.strip()):
                raise ValueError(
                    f"The 'team' of dag_role_mapping key {key!r} must be a team name and requires "
                    "[core] multi_team"
                )
            if not isinstance(rule["role"], str):
                raise ValueError(f"The 'role' of dag_role_mapping key {key!r} must be a string")
            try:
                role = get_role_by_name(rule["role"])
            except ValueError as e:
                raise ValueError(f"Invalid role for dag_role_mapping key {key!r}: {e}") from None
            grants.append(DagGrant(dags=dags.strip(), role=role, team=team.strip() if team else None))
        folded_key = key.casefold()
        if folded_key in mapping:
            raise ValueError(
                f"dag_role_mapping key {key!r} is defined more than once (keys are case-insensitive)"
            )
        mapping[folded_key] = grants
    return mapping


def resolve_dag_groups(values: Sequence[str], mapping: Mapping[str, list[DagGrant]]) -> list[str]:
    """
    Return the case-folded claim values that have Dag grants, sorted.

    :param values: group or role claim values
    :param mapping: mapping returned by :func:`parse_dag_role_mapping`
    """
    return sorted({value.casefold() for value in values if value.casefold() in mapping})


def get_dag_role(
    dag_groups: Sequence[str], mapping: Mapping[str, list[DagGrant]], dag_id: str, team_name: str | None
) -> AdfsAuthManagerRole | None:
    """
    Return the highest role the Dag grants of the user give on a Dag, if any.

    :param dag_groups: case-folded claim values of the user that have Dag grants
    :param mapping: mapping returned by :func:`parse_dag_role_mapping`
    :param dag_id: ID of the Dag
    :param team_name: team of the Dag, if any
    """
    roles = [
        grant.role
        for group in dag_groups
        for grant in mapping.get(group, ())
        if grant.team == team_name and fnmatch.fnmatchcase(dag_id, grant.dags)
    ]
    return max(roles) if roles else None


def resolve_username(claims: Mapping[str, Any], claim_names: Sequence[str], *, strip_domain: bool) -> str:
    r"""
    Return the user name from the first claim holding a non-blank string.

    :param claims: token claims
    :param claim_names: claims to look at, in order of preference
    :param strip_domain: whether to remove a ``DOMAIN\`` prefix. AD FS emits ``unique_name`` with or
        without the prefix depending on the claim rule.
    """
    for claim_name in claim_names:
        value = claims.get(claim_name)
        if not isinstance(value, str):
            continue
        username = value.strip()
        if strip_domain:
            username = username.rpartition("\\")[2].strip()
        if username:
            return username
    raise AdfsAuthenticationError("No user name claim found in the token")


def get_claim_values(claims: Mapping[str, Any], claim_names: Sequence[str]) -> list[str]:
    """
    Return the string values of the given claims.

    AD FS emits a multi-valued claim as a single string when it has one value and as a list
    otherwise.

    :param claims: token claims
    :param claim_names: claims to read
    """
    values: list[str] = []
    for claim_name in claim_names:
        value = claims.get(claim_name)
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, list):
            values.extend(item for item in value if isinstance(item, str))
    return values


def resolve_role(
    values: Sequence[str],
    mapping: Mapping[str, AdfsAuthManagerRole],
    default_role: AdfsAuthManagerRole | None,
) -> AdfsAuthManagerRole | None:
    """
    Return the highest role mapped from the claim values.

    :param values: group or role claim values
    :param mapping: mapping returned by :func:`parse_role_mapping`
    :param default_role: role returned when no value is mapped
    """
    roles = [role for value in values if (role := mapping.get(value.casefold())) is not None]
    if len(roles) < len(values):
        log.debug(
            "Claim values not mapped to an Airflow role: %s",
            [value for value in values if value.casefold() not in mapping],
        )
    return max(roles) if roles else default_role
