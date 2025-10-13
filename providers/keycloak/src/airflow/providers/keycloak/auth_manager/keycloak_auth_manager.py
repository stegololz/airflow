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

import argparse
import json
import logging
import threading
import weakref
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from time import monotonic
from typing import TYPE_CHECKING, Any, NamedTuple, cast
from urllib.parse import urljoin

import requests
from fastapi import FastAPI
from keycloak import KeycloakOpenID
from sqlalchemy import select

from airflow.api_fastapi.app import AUTH_MANAGER_FASTAPI_APP_PREFIX
from airflow.api_fastapi.auth.managers.base_auth_manager import BaseAuthManager

try:
    from airflow.api_fastapi.auth.managers.base_auth_manager import ExtendedResourceMethod
except ImportError:
    from airflow.api_fastapi.auth.managers.base_auth_manager import ResourceMethod as ExtendedResourceMethod

from airflow.api_fastapi.auth.managers.models.resource_details import DagDetails
from airflow.api_fastapi.common.types import MenuItem
from airflow.cli.cli_config import CLICommand, DefaultHelpParser, GroupCommand
from airflow.configuration import conf
from airflow.exceptions import AirflowException
from airflow.models import DagModel
from airflow.models.dagbundle import DagBundleModel
from airflow.models.team import Team, dag_bundle_team_association_table
from airflow.providers.keycloak.auth_manager.cli.definition import KEYCLOAK_AUTH_MANAGER_COMMANDS
from airflow.providers.keycloak.auth_manager.constants import (
    CONF_CLIENT_ID_KEY,
    CONF_CLIENT_SECRET_KEY,
    CONF_DAG_PERMISSIONS_CACHE_TTL_KEY,
    CONF_DAG_INVENTORY_CACHE_TTL_KEY,
    CONF_REALM_KEY,
    CONF_SECTION_NAME,
    CONF_SERVER_URL_KEY,
)
from airflow.providers.keycloak.auth_manager.resources import KeycloakResource
from airflow.providers.keycloak.auth_manager.user import KeycloakAuthManagerUser
from airflow.utils.helpers import prune_dict
from airflow.utils.session import NEW_SESSION, provide_session

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
        PoolDetails,
        VariableDetails,
    )
    from sqlalchemy.orm import Session

log = logging.getLogger(__name__)

RESOURCE_ID_ATTRIBUTE_NAME = "resource_id"


class _DagPermissionCacheEntry(NamedTuple):
    expires_at: float
    allowed: bool


def get_parser() -> argparse.ArgumentParser:
    """Generate documentation; used by Sphinx argparse."""
    from airflow.cli.cli_parser import AirflowHelpFormatter, _add_command

    parser = DefaultHelpParser(prog="airflow", formatter_class=AirflowHelpFormatter)
    subparsers = parser.add_subparsers(dest="subcommand", metavar="GROUP_OR_COMMAND")
    for group_command in KeycloakAuthManager.get_cli_commands():
        _add_command(subparsers, group_command)
    return parser


class KeycloakAuthManager(BaseAuthManager[KeycloakAuthManagerUser]):
    """
    Keycloak auth manager.

    Leverages Keycloak to perform authentication and authorization in Airflow.
    """

    def __init__(self) -> None:
        super().__init__()
        self._dag_permissions_cache_ttl_seconds = conf.getint(
            CONF_SECTION_NAME,
            CONF_DAG_PERMISSIONS_CACHE_TTL_KEY,
            fallback=30,
        )
        self._dag_inventory_cache_ttl_seconds = conf.getint(
            CONF_SECTION_NAME,
            CONF_DAG_INVENTORY_CACHE_TTL_KEY,
            fallback=300,
        )
        self._dag_permissions_cache: dict[tuple[str, str, str, str | None], _DagPermissionCacheEntry] = {}
        self._dag_permissions_cache_lock = threading.RLock()
        self._dag_inventory: dict[str | None, set[str]] | None = None
        self._dag_inventory_last_refreshed: float | None = None
        self._dag_inventory_lock = threading.RLock()
        self._dag_warmup_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="keycloak-dag-warm")
        self._warmup_executor_finalizer = weakref.finalize(self, self._dag_warmup_executor.shutdown, wait=False)
        self._dag_warmup_lock = threading.RLock()
        self._dag_warmup_inflight: set[str] = set()
        self._pending_role_warmups: set[str] = set()

    def init(self) -> None:
        super().init()
        if self._dag_permissions_cache_ttl_seconds <= 0:
            return
        self._dag_warmup_executor.submit(self._prime_dag_inventory)

    def deserialize_user(self, token: dict[str, Any]) -> KeycloakAuthManagerUser:
        return KeycloakAuthManagerUser(
            user_id=token.pop("user_id"),
            name=token.pop("name"),
            access_token=token.pop("access_token"),
            refresh_token=token.pop("refresh_token"),
        )

    def serialize_user(self, user: KeycloakAuthManagerUser) -> dict[str, Any]:
        return {
            "user_id": user.get_id(),
            "name": user.get_name(),
            "access_token": user.access_token,
            "refresh_token": user.refresh_token,
        }

    def get_url_login(self, **kwargs) -> str:
        base_url = conf.get("api", "base_url", fallback="/")
        return urljoin(base_url, f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login")

    def get_url_refresh(self) -> str | None:
        base_url = conf.get("api", "base_url", fallback="/")
        return urljoin(base_url, f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/refresh")

    def is_authorized_configuration(
        self,
        *,
        method: ResourceMethod,
        user: KeycloakAuthManagerUser,
        details: ConfigurationDetails | None = None,
    ) -> bool:
        config_section = details.section if details else None
        return self._is_authorized(
            method=method,
            resource_type=KeycloakResource.CONFIGURATION,
            user=user,
            resource_id=config_section,
        )

    def is_authorized_connection(
        self,
        *,
        method: ResourceMethod,
        user: KeycloakAuthManagerUser,
        details: ConnectionDetails | None = None,
    ) -> bool:
        connection_id = details.conn_id if details else None
        return self._is_authorized(
            method=method, resource_type=KeycloakResource.CONNECTION, user=user, resource_id=connection_id
        )

    def is_authorized_dag(
        self,
        *,
        method: ResourceMethod,
        user: KeycloakAuthManagerUser,
        access_entity: DagAccessEntity | None = None,
        details: DagDetails | None = None,
    ) -> bool:
        dag_id = details.id if details else None
        access_entity_str = access_entity.value if access_entity else None
        team_name = getattr(details, "team_name", None)
        attributes: dict[str, str | None] = {"dag_entity": access_entity_str}
        if team_name:
            attributes["team_name"] = team_name
        return self._is_authorized(
            method=method,
            resource_type=KeycloakResource.DAG,
            user=user,
            resource_id=dag_id,
            attributes=attributes,
        )

    def _get_cached_dag_permission(
        self,
        cache_key: tuple[str, str, str, str | None],
        *,
        now: float,
    ) -> bool | None:
        if self._dag_permissions_cache_ttl_seconds <= 0:
            return None

        with self._dag_permissions_cache_lock:
            cached = self._dag_permissions_cache.get(cache_key)
            if not cached:
                return None
            if cached.expires_at <= now:
                self._dag_permissions_cache.pop(cache_key, None)
                return None
            return cached.allowed

    def _set_cached_dag_permission(
        self,
        cache_key: tuple[str, str, str, str | None],
        allowed: bool,
        *,
        now: float,
    ) -> None:
        if self._dag_permissions_cache_ttl_seconds <= 0:
            return

        expires_at = now + self._dag_permissions_cache_ttl_seconds
        with self._dag_permissions_cache_lock:
            self._dag_permissions_cache[cache_key] = _DagPermissionCacheEntry(expires_at, allowed)

    def _prime_dag_inventory(self) -> None:
        try:
            inventory = self._fetch_dag_inventory()
            with self._dag_inventory_lock:
                self._dag_inventory = inventory
                self._dag_inventory_last_refreshed = monotonic()
        except Exception:
            log.exception("Failed to prime DAG inventory for permissions warmup")

    def _get_dag_inventory(self) -> dict[str | None, set[str]]:
        if self._dag_inventory_cache_ttl_seconds <= 0:
            return self._fetch_dag_inventory()

        with self._dag_inventory_lock:
            inventory = self._dag_inventory
            last_refreshed = self._dag_inventory_last_refreshed

        current_time = monotonic()
        if (
            inventory is not None
            and last_refreshed is not None
            and current_time - last_refreshed < self._dag_inventory_cache_ttl_seconds
        ):
            return {team: set(dag_ids) for team, dag_ids in inventory.items()}

        inventory = self._fetch_dag_inventory()
        with self._dag_inventory_lock:
            self._dag_inventory = inventory
            self._dag_inventory_last_refreshed = monotonic()
        return inventory

    @staticmethod
    @provide_session
    def _fetch_dag_inventory(*, session: "Session" = NEW_SESSION) -> dict[str | None, set[str]]:
        stmt = (
            select(DagModel.dag_id, Team.name)
            .join(DagBundleModel, DagModel.bundle_name == DagBundleModel.name)
            .join(
                dag_bundle_team_association_table,
                DagBundleModel.name == dag_bundle_team_association_table.c.dag_bundle_name,
                isouter=True,
            )
            .join(Team, Team.id == dag_bundle_team_association_table.c.team_id, isouter=True)
        )
        rows = session.execute(stmt).all()
        dags_by_team: dict[str | None, set[str]] = defaultdict(set)
        for dag_id, team_name in rows:
            dags_by_team[team_name].add(dag_id)
        return {team: set(dag_ids) for team, dag_ids in dags_by_team.items()}

    def _warmup_user_dag_permissions(
        self,
        user: KeycloakAuthManagerUser,
        method: ResourceMethod = "GET",
    ) -> None:
        user_id = str(user.get_id())
        method_value = cast(ExtendedResourceMethod, method)
        try:
            dag_inventory = self._get_dag_inventory()
            if not dag_inventory:
                return

            for team_name, dag_ids in dag_inventory.items():
                if not dag_ids:
                    continue
                attributes = {"team_name": team_name} if team_name else None
                permissions = [(method_value, dag_id) for dag_id in dag_ids]

                try:
                    authorized_pairs = self._is_batch_authorized(
                        permissions=permissions,
                        user=user,
                        attributes=attributes,
                    )
                except Exception:
                    log.exception("Failed to warm DAG permissions for user %s and team %s", user_id, team_name)
                    continue

                authorized_lookup = {(scope, resource) for scope, resource in authorized_pairs}
                cache_time = monotonic()
                for dag_id in dag_ids:
                    allowed = (method_value, dag_id) in authorized_lookup
                    cache_key = (user_id, dag_id, method_value, team_name)
                    self._set_cached_dag_permission(cache_key, allowed, now=cache_time)
        except Exception:
            log.exception("Failed to warm DAG permissions for user %s", user_id)
        finally:
            with self._dag_warmup_lock:
                self._dag_warmup_inflight.discard(user_id)

    def _evict_user_dag_cache(self, user_id: str) -> None:
        with self._dag_permissions_cache_lock:
            keys_to_delete = [key for key in self._dag_permissions_cache if key[0] == user_id]
            for key in keys_to_delete:
                self._dag_permissions_cache.pop(key, None)

    def schedule_dag_permission_warmup(
        self,
        user: KeycloakAuthManagerUser,
        *,
        method: ResourceMethod = "GET",
    ) -> None:
        if self._dag_permissions_cache_ttl_seconds <= 0:
            return

        user_snapshot = KeycloakAuthManagerUser(
            user_id=str(user.get_id()),
            name=str(user.get_name()),
            access_token=getattr(user, "access_token", ""),
            refresh_token=getattr(user, "refresh_token", ""),
        )
        user_id = user_snapshot.get_id()
        with self._dag_warmup_lock:
            if user_id in self._dag_warmup_inflight:
                return
            self._dag_warmup_inflight.add(user_id)
            self._pending_role_warmups.discard(user_id)
        self._dag_warmup_executor.submit(self._warmup_user_dag_permissions, user_snapshot, method)

    def notify_role_change(
        self,
        *,
        user: KeycloakAuthManagerUser | None = None,
        user_id: str | None = None,
    ) -> None:
        if user is None and user_id is None:
            raise ValueError("Either user or user_id must be provided to notify role change")

        resolved_user_id = user_id or str(user.get_id())
        self._evict_user_dag_cache(resolved_user_id)
        with self._dag_warmup_lock:
            self._pending_role_warmups.add(resolved_user_id)
        if user is not None:
            self.schedule_dag_permission_warmup(user)

    def filter_authorized_dag_ids(
        self,
        *,
        dag_ids: set[str],
        user: KeycloakAuthManagerUser,
        method: ResourceMethod = "GET",
        team_name: str | None = None,
    ) -> set[str]:
        if not dag_ids:
            return set()

        user_id = str(user.get_id())
        with self._dag_warmup_lock:
            pending_warmup = user_id in self._pending_role_warmups
        if pending_warmup:
            self.schedule_dag_permission_warmup(user)

        method_value = cast(ExtendedResourceMethod, method)
        lookup_attributes: dict[str, str | None] | None = None
        if team_name:
            lookup_attributes = {"team_name": team_name}

        now = monotonic()
        authorized_dags: set[str] = set()
        dag_ids_to_check: list[tuple[str, tuple[str, str, str, str | None]]] = []
        for dag_id in dag_ids:
            cache_key = (user_id, dag_id, method_value, team_name)
            cached_permission = self._get_cached_dag_permission(cache_key, now=now)
            if cached_permission is None:
                dag_ids_to_check.append((dag_id, cache_key))
                continue
            if cached_permission:
                authorized_dags.add(dag_id)

        if dag_ids_to_check:
            permissions = [(method_value, dag_id) for dag_id, _ in dag_ids_to_check]
            authorized_pairs = self._is_batch_authorized(
                permissions=permissions,
                user=user,
                attributes=lookup_attributes,
            )
            authorized_lookup = {(scope, resource) for scope, resource in authorized_pairs}
            cache_time = monotonic()
            for dag_id, cache_key in dag_ids_to_check:
                is_authorized = (method_value, dag_id) in authorized_lookup
                if is_authorized:
                    authorized_dags.add(dag_id)
                self._set_cached_dag_permission(cache_key, is_authorized, now=cache_time)

        return authorized_dags

    def is_authorized_backfill(
        self, *, method: ResourceMethod, user: KeycloakAuthManagerUser, details: BackfillDetails | None = None
    ) -> bool:
        backfill_id = str(details.id) if details else None
        return self._is_authorized(
            method=method, resource_type=KeycloakResource.BACKFILL, user=user, resource_id=backfill_id
        )

    def is_authorized_asset(
        self, *, method: ResourceMethod, user: KeycloakAuthManagerUser, details: AssetDetails | None = None
    ) -> bool:
        asset_id = details.id if details else None
        return self._is_authorized(
            method=method, resource_type=KeycloakResource.ASSET, user=user, resource_id=asset_id
        )

    def is_authorized_asset_alias(
        self,
        *,
        method: ResourceMethod,
        user: KeycloakAuthManagerUser,
        details: AssetAliasDetails | None = None,
    ) -> bool:
        asset_alias_id = details.id if details else None
        return self._is_authorized(
            method=method,
            resource_type=KeycloakResource.ASSET_ALIAS,
            user=user,
            resource_id=asset_alias_id,
        )

    def is_authorized_variable(
        self, *, method: ResourceMethod, user: KeycloakAuthManagerUser, details: VariableDetails | None = None
    ) -> bool:
        variable_key = details.key if details else None
        return self._is_authorized(
            method=method, resource_type=KeycloakResource.VARIABLE, user=user, resource_id=variable_key
        )

    def is_authorized_pool(
        self, *, method: ResourceMethod, user: KeycloakAuthManagerUser, details: PoolDetails | None = None
    ) -> bool:
        pool_name = details.name if details else None
        return self._is_authorized(
            method=method, resource_type=KeycloakResource.POOL, user=user, resource_id=pool_name
        )

    def is_authorized_view(self, *, access_view: AccessView, user: KeycloakAuthManagerUser) -> bool:
        return self._is_authorized(
            method="GET",
            resource_type=KeycloakResource.VIEW,
            user=user,
            resource_id=access_view.value,
        )

    def is_authorized_custom_view(
        self, *, method: ResourceMethod | str, resource_name: str, user: KeycloakAuthManagerUser
    ) -> bool:
        return self._is_authorized(
            method=method, resource_type=KeycloakResource.CUSTOM, user=user, resource_id=resource_name
        )

    def filter_authorized_menu_items(
        self, menu_items: list[MenuItem], *, user: KeycloakAuthManagerUser
    ) -> list[MenuItem]:
        authorized_menus = self._is_batch_authorized(
            permissions=[("MENU", menu_item.value) for menu_item in menu_items],
            user=user,
        )
        return [MenuItem(menu[1]) for menu in authorized_menus]

    def get_fastapi_app(self) -> FastAPI | None:
        from airflow.providers.keycloak.auth_manager.routes.login import login_router
        from airflow.providers.keycloak.auth_manager.routes.token import token_router

        app = FastAPI(
            title="Keycloak auth manager sub application",
            description=(
                "This is the Keycloak auth manager fastapi sub application. This API is only available if the "
                "auth manager used in the Airflow environment is Keycloak auth manager. "
                "This sub application provides login routes."
            ),
        )
        app.include_router(login_router)
        app.include_router(token_router)

        return app

    @staticmethod
    def get_cli_commands() -> list[CLICommand]:
        """Vends CLI commands to be included in Airflow CLI."""
        return [
            GroupCommand(
                name="keycloak-auth-manager",
                help="Manage resources used by Keycloak auth manager",
                subcommands=KEYCLOAK_AUTH_MANAGER_COMMANDS,
            ),
        ]

    @staticmethod
    def get_keycloak_client() -> KeycloakOpenID:
        client_id = conf.get(CONF_SECTION_NAME, CONF_CLIENT_ID_KEY)
        client_secret = conf.get(CONF_SECTION_NAME, CONF_CLIENT_SECRET_KEY)
        realm = conf.get(CONF_SECTION_NAME, CONF_REALM_KEY)
        server_url = conf.get(CONF_SECTION_NAME, CONF_SERVER_URL_KEY)

        return KeycloakOpenID(
            server_url=server_url,
            client_id=client_id,
            client_secret_key=client_secret,
            realm_name=realm,
        )

    def _is_authorized(
        self,
        *,
        method: ResourceMethod | str,
        resource_type: KeycloakResource,
        user: KeycloakAuthManagerUser,
        resource_id: str | None = None,
        attributes: dict[str, str | None] | None = None,
    ) -> bool:
        client_id = conf.get(CONF_SECTION_NAME, CONF_CLIENT_ID_KEY)
        realm = conf.get(CONF_SECTION_NAME, CONF_REALM_KEY)
        server_url = conf.get(CONF_SECTION_NAME, CONF_SERVER_URL_KEY)

        context_attributes = prune_dict(attributes or {})
        if resource_id:
            context_attributes[RESOURCE_ID_ATTRIBUTE_NAME] = resource_id
        elif method == "GET":
            method = "LIST"

        resp = requests.post(
            self._get_token_url(server_url, realm),
            data=self._get_payload(client_id, f"{resource_type.value}#{method}", context_attributes),
            headers=self._get_headers(user.access_token),
        )

        if resp.status_code == 200:
            return True
        if resp.status_code == 403:
            return False
        if resp.status_code == 400:
            error = json.loads(resp.text)
            raise AirflowException(
                f"Request not recognized by Keycloak. {error.get('error')}. {error.get('error_description')}"
            )
        raise AirflowException(f"Unexpected error: {resp.status_code} - {resp.text}")

    def _is_batch_authorized(
        self,
        *,
        permissions: list[tuple[ExtendedResourceMethod, str]],
        user: KeycloakAuthManagerUser,
        attributes: dict[str, str | None] | None = None,
    ) -> set[tuple[str, str]]:
        client_id = conf.get(CONF_SECTION_NAME, CONF_CLIENT_ID_KEY)
        realm = conf.get(CONF_SECTION_NAME, CONF_REALM_KEY)
        server_url = conf.get(CONF_SECTION_NAME, CONF_SERVER_URL_KEY)

        resp = requests.post(
            self._get_token_url(server_url, realm),
            data=self._get_batch_payload(client_id, permissions, attributes),
            headers=self._get_headers(user.access_token),
        )

        if resp.status_code == 200:
            return {(perm["scopes"][0], perm["rsname"]) for perm in resp.json()}
        if resp.status_code == 403:
            return set()
        if resp.status_code == 400:
            error = json.loads(resp.text)
            raise AirflowException(
                f"Request not recognized by Keycloak. {error.get('error')}. {error.get('error_description')}"
            )
        raise AirflowException(f"Unexpected error: {resp.status_code} - {resp.text}")

    @staticmethod
    def _get_token_url(server_url, realm):
        return f"{server_url}/realms/{realm}/protocol/openid-connect/token"

    @staticmethod
    def _get_payload(client_id: str, permission: str, attributes: dict[str, str] | None = None):
        payload: dict[str, Any] = {
            "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
            "audience": client_id,
            "permission": permission,
        }
        if attributes:
            payload["context"] = {"attributes": attributes}

        return payload

    @staticmethod
    def _get_batch_payload(
        client_id: str,
        permissions: list[tuple[ExtendedResourceMethod, str]],
        attributes: dict[str, str | None] | None = None,
    ):
        payload: dict[str, Any] = {
            "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
            "audience": client_id,
            "permission": [f"{permission[1]}#{permission[0]}" for permission in permissions],
            "response_mode": "permissions",
        }
        if attributes:
            payload["context"] = {"attributes": prune_dict(attributes)}

        return payload

    @staticmethod
    def _get_headers(access_token):
        return {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/x-www-form-urlencoded",
        }
