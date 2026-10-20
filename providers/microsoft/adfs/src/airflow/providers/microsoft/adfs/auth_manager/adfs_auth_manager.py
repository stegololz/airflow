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
    CONF_ROLES_CLAIMS_KEY,
    CONF_SCOPE_KEY,
    CONF_SECTION_NAME,
    CONF_STRIP_DOMAIN_PREFIX_KEY,
    CONF_USERNAME_CLAIMS_KEY,
    DEFAULT_ROLES_CLAIMS,
    DEFAULT_SCOPE,
    DEFAULT_USERNAME_CLAIMS,
)
from airflow.providers.microsoft.adfs.auth_manager.oidc import AdfsOidcClient
from airflow.providers.microsoft.adfs.auth_manager.roles import (
    AdfsAuthManagerRole,
    get_claim_values,
    get_role_by_name,
    parse_role_mapping,
    resolve_role,
    resolve_username,
)
from airflow.providers.microsoft.adfs.auth_manager.user import AdfsAuthManagerUser

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


def _get_list_option(key: str, fallback: str) -> list[str]:
    raw = conf.get(CONF_SECTION_NAME, key, fallback=fallback) or ""
    return [item.strip() for item in raw.split(",") if item.strip()]


class AdfsAuthManager(BaseAuthManager[AdfsAuthManagerUser]):
    """
    Microsoft AD FS auth manager.

    Users log in with the OpenID Connect authorization code flow. Their Airflow role is resolved
    once at login from the group or role claims issued by AD FS and stored in the Airflow token,
    so authorization does not call AD FS.
    """

    def init(self) -> None:
        # The base implementation lists the teams of the auth manager in multi-team mode, which this
        # auth manager does not support.
        if conf.getboolean("core", "multi_team", fallback=False):
            raise ValueError("Multi-team mode is not supported by the AD FS auth manager")
        super().init()
        self._validate_config()

    def _validate_config(self) -> None:
        """
        Check the configuration without contacting AD FS, so that the API server starts while AD FS is down.

        :meta private:
        """
        for key in (CONF_ISSUER_KEY, CONF_CLIENT_ID_KEY, CONF_ROLE_MAPPING_KEY):
            if not conf.get(CONF_SECTION_NAME, key, fallback=None):
                raise ValueError(f"[{CONF_SECTION_NAME}] {key} must be set")
        if urlsplit(conf.get(CONF_SECTION_NAME, CONF_ISSUER_KEY)).scheme != "https":
            raise ValueError(f"[{CONF_SECTION_NAME}] {CONF_ISSUER_KEY} must be an https URL")
        if not _get_list_option(CONF_USERNAME_CLAIMS_KEY, DEFAULT_USERNAME_CLAIMS):
            raise ValueError(f"[{CONF_SECTION_NAME}] {CONF_USERNAME_CLAIMS_KEY} must not be empty")
        # Parsing the role options here makes the API server fail at start-up on an invalid value
        # rather than at the first login.
        self.get_role_mapping()
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
        return parse_role_mapping(conf.get(CONF_SECTION_NAME, CONF_ROLE_MAPPING_KEY, fallback="") or "")

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
        if role is None:
            # Logged so that a renamed or missing group in AD FS can be diagnosed.
            log.info("User %s has no Airflow role; unmapped claim values: %s", username, values)
            raise PermissionError(f"User {username} is not mapped to an Airflow role")
        return AdfsAuthManagerUser(user_id=username, name=self._get_display_name(claims, username), role=role)

    @staticmethod
    def _get_display_name(claims: Mapping[str, Any], username: str) -> str:
        name = claims.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
        parts = [claims.get("given_name"), claims.get("family_name")]
        full_name = " ".join(part.strip() for part in parts if isinstance(part, str) and part.strip())
        return full_name or username

    def deserialize_user(self, token: dict[str, Any]) -> AdfsAuthManagerUser:
        return AdfsAuthManagerUser(
            user_id=token["sub"], name=token["name"], role=AdfsAuthManagerRole[token["role"]]
        )

    def serialize_user(self, user: AdfsAuthManagerUser) -> dict[str, Any]:
        return {"sub": user.user_id, "name": user.name, "role": user.role.name}

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
            method=method, user=user, read_role=AdfsAuthManagerRole.OP, write_role=AdfsAuthManagerRole.OP
        )

    def is_authorized_dag(
        self,
        *,
        method: ResourceMethod,
        user: AdfsAuthManagerUser,
        access_entity: DagAccessEntity | None = None,
        details: DagDetails | None = None,
    ) -> bool:
        return self._is_authorized(
            method=method,
            user=user,
            read_role=AdfsAuthManagerRole.VIEWER,
            write_role=AdfsAuthManagerRole.USER,
        )

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
            method=method, user=user, read_role=AdfsAuthManagerRole.VIEWER, write_role=AdfsAuthManagerRole.OP
        )

    def is_authorized_variable(
        self, *, method: ResourceMethod, user: AdfsAuthManagerUser, details: VariableDetails | None = None
    ) -> bool:
        return self._is_authorized(
            method=method, user=user, read_role=AdfsAuthManagerRole.OP, write_role=AdfsAuthManagerRole.OP
        )

    def is_authorized_view(
        self, *, access_view: AccessView, user: AdfsAuthManagerUser, team_name: str | None = None
    ) -> bool:
        return access_view.value in VIEWER_ACCESS_VIEW_NAMES or user.role >= AdfsAuthManagerRole.ADMIN

    def is_authorized_custom_view(
        self, *, method: ResourceMethod | str, resource_name: str, user: AdfsAuthManagerUser
    ) -> bool:
        # ``method`` can be any action defined by a plugin, which may change state.
        return self._is_authorized(
            method=method, user=user, read_role=AdfsAuthManagerRole.VIEWER, write_role=AdfsAuthManagerRole.OP
        )

    def filter_authorized_menu_items(
        self, menu_items: list[MenuItem], *, user: AdfsAuthManagerUser
    ) -> list[MenuItem]:
        return [
            menu_item
            for menu_item in menu_items
            if user.role >= MENU_ITEM_MIN_ROLES.get(menu_item.value, AdfsAuthManagerRole.VIEWER)
        ]

    def get_fastapi_app(self) -> FastAPI | None:
        from airflow.providers.microsoft.adfs.auth_manager.routes.login import login_router

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

    @staticmethod
    def _is_authorized(
        *,
        method: ResourceMethod | str,
        user: AdfsAuthManagerUser,
        read_role: AdfsAuthManagerRole,
        write_role: AdfsAuthManagerRole,
    ) -> bool:
        """
        Return whether the user's role grants the method.

        :param method: the method or plugin action to perform
        :param user: the user performing the action
        :param read_role: minimal role required for ``GET``
        :param write_role: minimal role required for any other method
        :meta private:
        """
        return user.role >= (read_role if method == "GET" else write_role)
