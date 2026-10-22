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

import json
import logging
from collections.abc import Mapping, Sequence
from enum import IntEnum
from typing import Any

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
