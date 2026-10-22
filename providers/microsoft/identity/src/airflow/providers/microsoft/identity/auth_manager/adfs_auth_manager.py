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

import logging
import warnings
from collections.abc import Mapping
from functools import cached_property
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode, urljoin, urlsplit

from fastapi import FastAPI

from airflow.api_fastapi.app import AUTH_MANAGER_FASTAPI_APP_PREFIX
from airflow.api_fastapi.auth.managers.base_auth_manager import BaseAuthManager
from airflow.exceptions import AirflowProviderDeprecationWarning
from airflow.providers.common.compat.sdk import conf
from airflow.providers.microsoft.identity.auth_manager.constants import (
    CONF_ACCESS_TOKEN_ISSUERS_KEY,
    CONF_CA_BUNDLE_PATH_KEY,
    CONF_CLIENT_ID_KEY,
    CONF_CLIENT_SECRET_KEY,
    CONF_DAG_ROLE_MAPPING_KEY,
    CONF_DEFAULT_ROLE_KEY,
    CONF_ISSUER_KEY,
    CONF_JWKS_CACHE_TTL_SECONDS_KEY,
    CONF_LEEWAY_SECONDS_KEY,
    CONF_REQUEST_TIMEOUT_SECONDS_KEY,
    CONF_RESOURCE_KEY,
    CONF_ROLE_MAPPING_KEY,
    CONF_ROLES_CLAIMS_KEY,
    CONF_SCOPE_KEY,
    CONF_SECTION_NAME,
    CONF_STRIP_DOMAIN_PREFIX_KEY,
    CONF_TEAM_ROLE_MAPPING_KEY,
    CONF_USERNAME_CLAIMS_KEY,
    DEFAULT_ROLES_CLAIMS,
    DEFAULT_SCOPE,
    DEFAULT_USERNAME_CLAIMS,
)
from airflow.providers.microsoft.identity.auth_manager.oidc import AdfsOidcClient
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
from airflow.providers.microsoft.identity.auth_manager.user import AdfsAuthManagerUser

if TYPE_CHECKING:
    from airflow.api_fastapi.auth.managers.base_auth_manager import ResourceMethod
    from airflow.api_fastapi.auth.managers.models.resource_details import (
        AccessView,
        AssetAliasDetails,
        AssetDetails,
        BackfillDetails,
        ConfigurationDetails,
        ConnectionDetails,
        DagAccessEntity,
        DagDetails,
        PoolDetails,
        TeamDetails,
        VariableDetails,
    )
    from airflow.api_fastapi.common.types import MenuItem

log = logging.getLogger(__name__)

# ``AccessView`` values readable by every role. Any other view, including views added in later
# Airflow versions, requires ``ADMIN``. Compared by value because older Airflow versions lack some
# members.
VIEWER_ACCESS_VIEW_NAMES = frozenset(
    {
        "CLUSTER_ACTIVITY",
        "DOCS",
        "IMPORT_ERRORS",
        "JOBS",
        "PLUGINS",
        "PROVIDERS",
        "TRIGGERS",
        "WEBSITE",
    }
)

# Menu items not listed here are shown to every role. Keyed by ``MenuItem`` value because older
# Airflow versions lack some members.
MENU_ITEM_MIN_ROLES: dict[str, AdfsAuthManagerRole] = {
    "Connections": AdfsAuthManagerRole.OP,
    "Variables": AdfsAuthManagerRole.OP,
}


def _get_team_name(details: Any) -> str | None:
    # ``team_name`` is missing from resource details in older Airflow versions.
    return getattr(details, "team_name", None)


def _get_list_option(key: str, fallback: str) -> list[str]:
    raw = conf.get(CONF_SECTION_NAME, key, fallback=fallback) or ""
    return [item.strip() for item in raw.split(",") if item.strip()]


class AdfsAuthManager(BaseAuthManager[AdfsAuthManagerUser]):
    """
    Microsoft AD FS auth manager.

    Users log in with the OpenID Connect authorization code flow. Their Airflow roles, global and per
    team, are resolved once at login from the group or role claims issued by AD FS and stored in the
    Airflow token, so authorization does not call AD FS.
    """

    def init(self) -> None:
        self._validate_config()
        super().init()

    def _validate_config(self) -> None:
        """
        Check the configuration without contacting AD FS, so that the API server starts while AD FS is down.

        :meta private:
        """
        for key in (CONF_ISSUER_KEY, CONF_CLIENT_ID_KEY):
            if not conf.get(CONF_SECTION_NAME, key, fallback=None):
                raise ValueError(f"[{CONF_SECTION_NAME}] {key} must be set")
        has_team_roles = bool(conf.get(CONF_SECTION_NAME, CONF_TEAM_ROLE_MAPPING_KEY, fallback=""))
        if has_team_roles and not conf.getboolean("core", "multi_team", fallback=False):
            raise ValueError(
                f"[{CONF_SECTION_NAME}] {CONF_TEAM_ROLE_MAPPING_KEY} requires [core] multi_team to be enabled"
            )
        if not any(
            conf.get(CONF_SECTION_NAME, key, fallback=None)
            for key in (CONF_ROLE_MAPPING_KEY, CONF_TEAM_ROLE_MAPPING_KEY, CONF_DAG_ROLE_MAPPING_KEY)
        ):
            raise ValueError(
                f"[{CONF_SECTION_NAME}] {CONF_ROLE_MAPPING_KEY}, {CONF_TEAM_ROLE_MAPPING_KEY} or "
                f"{CONF_DAG_ROLE_MAPPING_KEY} must be set"
            )
        if urlsplit(conf.get(CONF_SECTION_NAME, CONF_ISSUER_KEY)).scheme != "https":
            raise ValueError(f"[{CONF_SECTION_NAME}] {CONF_ISSUER_KEY} must be an https URL")
        if not _get_list_option(CONF_USERNAME_CLAIMS_KEY, DEFAULT_USERNAME_CLAIMS):
            raise ValueError(f"[{CONF_SECTION_NAME}] {CONF_USERNAME_CLAIMS_KEY} must not be empty")
        # Parsing the role options here makes the API server fail at start-up on an invalid value
        # rather than at the first login.
        self.get_role_mapping()
        self.get_team_role_mapping()
        self.get_dag_role_mapping()
        self.get_default_role()

    @cached_property
    def _oidc_client(self) -> AdfsOidcClient:
        return AdfsOidcClient(
            issuer=conf.get(CONF_SECTION_NAME, CONF_ISSUER_KEY),
            client_id=conf.get(CONF_SECTION_NAME, CONF_CLIENT_ID_KEY),
            client_secret=conf.get(CONF_SECTION_NAME, CONF_CLIENT_SECRET_KEY, fallback=None),
            scope=conf.get(CONF_SECTION_NAME, CONF_SCOPE_KEY, fallback=DEFAULT_SCOPE) or DEFAULT_SCOPE,
            resource=conf.get(CONF_SECTION_NAME, CONF_RESOURCE_KEY, fallback=None),
            access_token_issuers=_get_list_option(CONF_ACCESS_TOKEN_ISSUERS_KEY, ""),
            leeway_seconds=conf.getint(CONF_SECTION_NAME, CONF_LEEWAY_SECONDS_KEY, fallback=30),
            ca_bundle_path=conf.get(CONF_SECTION_NAME, CONF_CA_BUNDLE_PATH_KEY, fallback=None),
            request_timeout_seconds=conf.getint(
                CONF_SECTION_NAME, CONF_REQUEST_TIMEOUT_SECONDS_KEY, fallback=10
            ),
            jwks_cache_ttl_seconds=conf.getint(
                CONF_SECTION_NAME, CONF_JWKS_CACHE_TTL_SECONDS_KEY, fallback=300
            ),
        )

    @cached_property
    def _role_mapping(self) -> dict[str, AdfsAuthManagerRole]:
        raw = conf.get(CONF_SECTION_NAME, CONF_ROLE_MAPPING_KEY, fallback="") or ""
        return parse_role_mapping(raw) if raw else {}

    @cached_property
    def _team_role_mapping(self) -> dict[str, tuple[str, AdfsAuthManagerRole]]:
        raw = conf.get(CONF_SECTION_NAME, CONF_TEAM_ROLE_MAPPING_KEY, fallback="") or ""
        return parse_team_role_mapping(raw) if raw else {}

    @cached_property
    def _dag_role_mapping(self) -> dict[str, list[DagGrant]]:
        raw = conf.get(CONF_SECTION_NAME, CONF_DAG_ROLE_MAPPING_KEY, fallback="") or ""
        if not raw:
            return {}
        return parse_dag_role_mapping(raw, multi_team=conf.getboolean("core", "multi_team", fallback=False))

    @cached_property
    def _default_role(self) -> AdfsAuthManagerRole | None:
        default_role = conf.get(CONF_SECTION_NAME, CONF_DEFAULT_ROLE_KEY, fallback="")
        return get_role_by_name(default_role) if default_role else None

    def get_oidc_client(self) -> AdfsOidcClient:
        """Return the OpenID Connect client used to talk to AD FS."""
        return self._oidc_client

    def get_role_mapping(self) -> dict[str, AdfsAuthManagerRole]:
        """Return the mapping of case-folded group or role claim values to Airflow roles."""
        return self._role_mapping

    def get_team_role_mapping(self) -> dict[str, tuple[str, AdfsAuthManagerRole]]:
        """Return the mapping of case-folded group or role claim values to ``(team, role)`` tuples."""
        return self._team_role_mapping

    def get_dag_role_mapping(self) -> dict[str, list[DagGrant]]:
        """Return the mapping of case-folded group or role claim values to their Dag grants."""
        return self._dag_role_mapping

    def get_default_role(self) -> AdfsAuthManagerRole | None:
        """Return the role of users whose claims do not match the role mapping, if any."""
        return self._default_role

    def get_user_from_claims(self, claims: Mapping[str, Any]) -> AdfsAuthManagerUser:
        """
        Build the Airflow user from validated token claims.

        :param claims: claims of the validated AD FS tokens
        :raises AdfsAuthenticationError: if no user name claim is present
        :raises PermissionError: if the user is not mapped to any Airflow role
        """
        username = resolve_username(
            claims,
            _get_list_option(CONF_USERNAME_CLAIMS_KEY, DEFAULT_USERNAME_CLAIMS),
            strip_domain=conf.getboolean(CONF_SECTION_NAME, CONF_STRIP_DOMAIN_PREFIX_KEY, fallback=False),
        )
        values = get_claim_values(claims, _get_list_option(CONF_ROLES_CLAIMS_KEY, DEFAULT_ROLES_CLAIMS))
        role = resolve_role(values, self.get_role_mapping(), self.get_default_role())
        teams = resolve_team_roles(values, self.get_team_role_mapping())
        dag_groups = resolve_dag_groups(values, self.get_dag_role_mapping())
        if role is None and not teams and not dag_groups:
            # Logged so that a renamed or missing group in AD FS can be diagnosed.
            log.info("User %s has no Airflow role; unmapped claim values: %s", username, values)
            raise PermissionError(f"User {username} is not mapped to an Airflow role")
        return AdfsAuthManagerUser(
            user_id=username,
            name=self._get_display_name(claims, username),
            role=role,
            teams=teams,
            dag_groups=dag_groups,
        )

    @staticmethod
    def _get_display_name(claims: Mapping[str, Any], username: str) -> str:
        name = claims.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
        parts = [claims.get("given_name"), claims.get("family_name")]
        full_name = " ".join(part.strip() for part in parts if isinstance(part, str) and part.strip())
        return full_name or username

    def deserialize_user(self, token: dict[str, Any]) -> AdfsAuthManagerUser:
        role = token["role"]
        return AdfsAuthManagerUser(
            user_id=token["sub"],
            name=token["name"],
            role=AdfsAuthManagerRole[role] if role is not None else None,
            # Ignored once multi-team is turned off, so tokens issued before keep no team access.
            teams={team: AdfsAuthManagerRole[name] for team, name in token.get("teams", {}).items()}
            if conf.getboolean("core", "multi_team", fallback=False)
            else {},
            dag_groups=list(token.get("dag_groups", [])),
        )

    def serialize_user(self, user: AdfsAuthManagerUser) -> dict[str, Any]:
        return {
            "sub": user.user_id,
            "name": user.name,
            "role": user.role.name if user.role is not None else None,
            "teams": {team: role.name for team, role in user.teams.items()},
            "dag_groups": user.dag_groups,
        }

    def get_url_login(self, **kwargs) -> str:
        url = urljoin(conf.get("api", "base_url", fallback="/"), f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login")
        if next_url := kwargs.get("next_url"):
            url = f"{url}?{urlencode({'next': next_url})}"
        return url

    def get_url_logout(self) -> str | None:
        return urljoin(conf.get("api", "base_url", fallback="/"), f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/logout")

    def is_authorized_configuration(
        self,
        *,
        method: ResourceMethod,
        user: AdfsAuthManagerUser,
        details: ConfigurationDetails | None = None,
    ) -> bool:
        return self._is_authorized(
            method=method, user=user, read_role=AdfsAuthManagerRole.VIEWER, write_role=AdfsAuthManagerRole.OP
        )

    def is_authorized_connection(
        self,
        *,
        method: ResourceMethod,
        user: AdfsAuthManagerUser,
        details: ConnectionDetails | None = None,
    ) -> bool:
        return self._is_authorized(
            method=method,
            user=user,
            read_role=AdfsAuthManagerRole.OP,
            write_role=AdfsAuthManagerRole.OP,
            team_name=_get_team_name(details),
            any_team=method == "GET" and (details is None or details.conn_id is None),
        )

    def is_authorized_dag(
        self,
        *,
        method: ResourceMethod,
        user: AdfsAuthManagerUser,
        access_entity: DagAccessEntity | None = None,
        details: DagDetails | None = None,
    ) -> bool:
        team_name = _get_team_name(details)
        if details is None or details.id is None:
            # Lists are filtered per Dag by core. Writes naming no Dag are not re-checked per Dag by every
            # supported Airflow version (backfills before 3.1.8), so Dag grants never authorize them.
            role = self._get_highest_role(user, include_dag_grants=method == "GET")
        else:
            roles = [
                self._get_role(user, team_name),
                get_dag_role(user.dag_groups, self.get_dag_role_mapping(), details.id, team_name),
            ]
            role = max((r for r in roles if r is not None), default=None)
        required_role = AdfsAuthManagerRole.VIEWER if method == "GET" else AdfsAuthManagerRole.USER
        return role is not None and role >= required_role

    def is_authorized_backfill(
        self, *, method: ResourceMethod, user: AdfsAuthManagerUser, details: BackfillDetails | None = None
    ) -> bool:
        # Abstract in Airflow < 3.2.0 only. Method can be removed once the min Airflow version is >= 3.2.0.
        warnings.warn(
            "Use ``is_authorized_dag`` on ``DagAccessEntity.RUN`` instead for a dag level access control.",
            AirflowProviderDeprecationWarning,
            stacklevel=2,
        )
        return self.is_authorized_dag(method=method, user=user)

    def is_authorized_asset(
        self, *, method: ResourceMethod, user: AdfsAuthManagerUser, details: AssetDetails | None = None
    ) -> bool:
        return self._is_authorized(
            method=method, user=user, read_role=AdfsAuthManagerRole.VIEWER, write_role=AdfsAuthManagerRole.OP
        )

    def is_authorized_asset_alias(
        self,
        *,
        method: ResourceMethod,
        user: AdfsAuthManagerUser,
        details: AssetAliasDetails | None = None,
    ) -> bool:
        return self._is_authorized(
            method=method, user=user, read_role=AdfsAuthManagerRole.VIEWER, write_role=AdfsAuthManagerRole.OP
        )

    def is_authorized_pool(
        self, *, method: ResourceMethod, user: AdfsAuthManagerUser, details: PoolDetails | None = None
    ) -> bool:
        return self._is_authorized(
            method=method,
            user=user,
            read_role=AdfsAuthManagerRole.VIEWER,
            write_role=AdfsAuthManagerRole.OP,
            team_name=_get_team_name(details),
        )

    def is_authorized_team(
        self, *, method: ResourceMethod, user: AdfsAuthManagerUser, details: TeamDetails | None = None
    ) -> bool:
        if details is None:
            return False
        return self._is_authorized(
            method=method,
            user=user,
            read_role=AdfsAuthManagerRole.VIEWER,
            write_role=AdfsAuthManagerRole.OP,
            team_name=details.name,
        )

    def is_authorized_variable(
        self, *, method: ResourceMethod, user: AdfsAuthManagerUser, details: VariableDetails | None = None
    ) -> bool:
        return self._is_authorized(
            method=method,
            user=user,
            read_role=AdfsAuthManagerRole.OP,
            write_role=AdfsAuthManagerRole.OP,
            team_name=_get_team_name(details),
            any_team=method == "GET" and (details is None or details.key is None),
        )

    def is_authorized_view(
        self, *, access_view: AccessView, user: AdfsAuthManagerUser, team_name: str | None = None
    ) -> bool:
        return access_view.value in VIEWER_ACCESS_VIEW_NAMES or user.role == AdfsAuthManagerRole.ADMIN

    def is_authorized_custom_view(
        self, *, method: ResourceMethod | str, resource_name: str, user: AdfsAuthManagerUser
    ) -> bool:
        # ``method`` can be any action defined by a plugin, which may change state. Plugins are not
        # scoped to a team: any role can read them, only a global role can change state.
        return self._is_authorized(
            method=method,
            user=user,
            read_role=AdfsAuthManagerRole.VIEWER,
            write_role=AdfsAuthManagerRole.OP,
            any_team=method == "GET",
        )

    def filter_authorized_menu_items(
        self, menu_items: list[MenuItem], *, user: AdfsAuthManagerUser
    ) -> list[MenuItem]:
        role = self._get_highest_role(user, include_dag_grants=True)
        if role is None:
            return []
        return [
            menu_item
            for menu_item in menu_items
            if role >= MENU_ITEM_MIN_ROLES.get(menu_item.value, AdfsAuthManagerRole.VIEWER)
        ]

    def get_fastapi_app(self) -> FastAPI | None:
        from airflow.providers.microsoft.identity.auth_manager.routes.login import login_router

        app = FastAPI(
            title="AD FS auth manager sub application",
            description=(
                "This is the AD FS auth manager fastapi sub application. This API is only available if the "
                "auth manager used in the Airflow environment is AD FS auth manager. "
                "This sub application provides login routes."
            ),
        )
        app.include_router(login_router)
        return app

    def _get_teams(self) -> set[str]:
        dag_teams = {
            grant.team for grants in self.get_dag_role_mapping().values() for grant in grants if grant.team
        }
        return {team for team, _ in self.get_team_role_mapping().values()} | dag_teams

    @staticmethod
    def _get_role(user: AdfsAuthManagerUser, team_name: str | None) -> AdfsAuthManagerRole | None:
        """
        Return the role of the user on a resource of the given team, or on a resource of no team.

        A global ``ADMIN`` has every right. Other global roles do not apply to team resources. Members
        of a team without a global role can read resources of no team.

        :meta private:
        """
        if user.role == AdfsAuthManagerRole.ADMIN:
            return user.role
        if team_name:
            return user.teams.get(team_name)
        if user.role is not None:
            return user.role
        return AdfsAuthManagerRole.VIEWER if user.teams else None

    def _get_highest_role(
        self, user: AdfsAuthManagerUser, *, include_dag_grants: bool = False
    ) -> AdfsAuthManagerRole | None:
        """
        Return the highest role of the user, global or in a team, and optionally from Dag grants.

        :meta private:
        """
        roles = [role for role in (user.role, *user.teams.values()) if role is not None]
        if include_dag_grants:
            mapping = self.get_dag_role_mapping()
            roles.extend(grant.role for group in user.dag_groups for grant in mapping.get(group, ()))
        return max(roles) if roles else None

    def _is_authorized(
        self,
        *,
        method: ResourceMethod | str,
        user: AdfsAuthManagerUser,
        read_role: AdfsAuthManagerRole,
        write_role: AdfsAuthManagerRole,
        team_name: str | None = None,
        any_team: bool = False,
    ) -> bool:
        """
        Return whether the user's role on the resource grants the method.

        :param method: the method to perform
        :param user: the user performing the action
        :param read_role: minimal role required for ``GET``
        :param write_role: minimal role required for any other method
        :param team_name: team of the resource, if any
        :param any_team: whether the check covers resources of any team, filtered per team by core
            afterwards, in which case the highest role of the user applies
        :meta private:
        """
        role = self._get_highest_role(user) if any_team and not team_name else self._get_role(user, team_name)
        return role is not None and role >= (read_role if method == "GET" else write_role)
