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
from unittest.mock import Mock, patch

import pytest

from airflow.api_fastapi.app import AUTH_MANAGER_FASTAPI_APP_PREFIX
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
from airflow.exceptions import AirflowException
from airflow.providers.keycloak.auth_manager.constants import (
    CONF_CLIENT_ID_KEY,
    CONF_REALM_KEY,
    CONF_SECTION_NAME,
    CONF_SERVER_URL_KEY,
)
from airflow.providers.keycloak.auth_manager.keycloak_auth_manager import (
    RESOURCE_ID_ATTRIBUTE_NAME,
    KeycloakAuthManager,
    _DagPermissionCacheEntry,
)
from airflow.providers.keycloak.auth_manager.user import KeycloakAuthManagerUser

from tests_common.test_utils.config import conf_vars


@pytest.fixture
def auth_manager():
    with conf_vars(
        {
            (CONF_SECTION_NAME, CONF_CLIENT_ID_KEY): "client_id",
            (CONF_SECTION_NAME, CONF_REALM_KEY): "realm",
            (CONF_SECTION_NAME, CONF_SERVER_URL_KEY): "server_url",
        }
    ):
        yield KeycloakAuthManager()


@pytest.fixture
def user():
    user = Mock()
    user.access_token = "access_token"
    user.refresh_token = "refresh_token"
    user.get_id.return_value = "user_id"
    user.get_name.return_value = "user_name"
    return user


class TestKeycloakAuthManager:
    def test_deserialize_user(self, auth_manager):
        result = auth_manager.deserialize_user(
            {
                "user_id": "user_id",
                "name": "name",
                "access_token": "access_token",
                "refresh_token": "refresh_token",
            }
        )
        assert result.user_id == "user_id"
        assert result.name == "name"
        assert result.access_token == "access_token"
        assert result.refresh_token == "refresh_token"

    def test_serialize_user(self, auth_manager):
        result = auth_manager.serialize_user(
            KeycloakAuthManagerUser(
                user_id="user_id", name="name", access_token="access_token", refresh_token="refresh_token"
            )
        )
        assert result == {
            "user_id": "user_id",
            "name": "name",
            "access_token": "access_token",
            "refresh_token": "refresh_token",
        }

    def test_get_url_login(self, auth_manager):
        result = auth_manager.get_url_login()
        assert result == f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login"

    @pytest.mark.parametrize(
        "function, method, details, permission, attributes",
        [
            [
                "is_authorized_configuration",
                "GET",
                ConfigurationDetails(section="test"),
                "Configuration#GET",
                {RESOURCE_ID_ATTRIBUTE_NAME: "test"},
            ],
            ["is_authorized_configuration", "GET", None, "Configuration#LIST", None],
            [
                "is_authorized_configuration",
                "PUT",
                ConfigurationDetails(section="test"),
                "Configuration#PUT",
                {RESOURCE_ID_ATTRIBUTE_NAME: "test"},
            ],
            [
                "is_authorized_connection",
                "DELETE",
                ConnectionDetails(conn_id="test"),
                "Connection#DELETE",
                {RESOURCE_ID_ATTRIBUTE_NAME: "test"},
            ],
            ["is_authorized_connection", "GET", None, "Connection#LIST", {}],
            [
                "is_authorized_backfill",
                "POST",
                BackfillDetails(id=1),
                "Backfill#POST",
                {RESOURCE_ID_ATTRIBUTE_NAME: "1"},
            ],
            ["is_authorized_backfill", "GET", None, "Backfill#LIST", {}],
            [
                "is_authorized_asset",
                "GET",
                AssetDetails(id="test"),
                "Asset#GET",
                {RESOURCE_ID_ATTRIBUTE_NAME: "test"},
            ],
            ["is_authorized_asset", "GET", None, "Asset#LIST", {}],
            [
                "is_authorized_asset_alias",
                "GET",
                AssetAliasDetails(id="test"),
                "AssetAlias#GET",
                {RESOURCE_ID_ATTRIBUTE_NAME: "test"},
            ],
            ["is_authorized_asset_alias", "GET", None, "AssetAlias#LIST", {}],
            [
                "is_authorized_variable",
                "PUT",
                VariableDetails(key="test"),
                "Variable#PUT",
                {RESOURCE_ID_ATTRIBUTE_NAME: "test"},
            ],
            ["is_authorized_variable", "GET", None, "Variable#LIST", {}],
            [
                "is_authorized_pool",
                "POST",
                PoolDetails(name="test"),
                "Pool#POST",
                {RESOURCE_ID_ATTRIBUTE_NAME: "test"},
            ],
            ["is_authorized_pool", "GET", None, "Pool#LIST", {}],
        ],
    )
    @pytest.mark.parametrize(
        "status_code, expected",
        [
            [200, True],
            [403, False],
        ],
    )
    @patch("airflow.providers.keycloak.auth_manager.keycloak_auth_manager.requests")
    def test_is_authorized(
        self,
        mock_requests,
        function,
        method,
        details,
        permission,
        attributes,
        status_code,
        expected,
        auth_manager,
        user,
    ):
        mock_requests.post.return_value.status_code = status_code

        result = getattr(auth_manager, function)(method=method, user=user, details=details)

        token_url = auth_manager._get_token_url("server_url", "realm")
        payload = auth_manager._get_payload("client_id", permission, attributes)
        headers = auth_manager._get_headers("access_token")
        mock_requests.post.assert_called_once_with(token_url, data=payload, headers=headers)
        assert result == expected

    @pytest.mark.parametrize(
        "function",
        [
            "is_authorized_configuration",
            "is_authorized_connection",
            "is_authorized_dag",
            "is_authorized_backfill",
            "is_authorized_asset",
            "is_authorized_asset_alias",
            "is_authorized_variable",
            "is_authorized_pool",
        ],
    )
    @patch("airflow.providers.keycloak.auth_manager.keycloak_auth_manager.requests")
    def test_is_authorized_failure(self, mock_requests, function, auth_manager, user):
        resp = Mock()
        resp.status_code = 500
        mock_requests.post.return_value = resp

        with pytest.raises(AirflowException) as e:
            getattr(auth_manager, function)(method="GET", user=user)

        assert "Unexpected error" in str(e.value)

    @pytest.mark.parametrize(
        "function",
        [
            "is_authorized_configuration",
            "is_authorized_connection",
            "is_authorized_dag",
            "is_authorized_backfill",
            "is_authorized_asset",
            "is_authorized_asset_alias",
            "is_authorized_variable",
            "is_authorized_pool",
        ],
    )
    @patch("airflow.providers.keycloak.auth_manager.keycloak_auth_manager.requests")
    def test_is_authorized_invalid_request(self, mock_requests, function, auth_manager, user):
        resp = Mock()
        resp.status_code = 400
        resp.text = json.dumps({"error": "invalid_scope", "error_description": "Invalid scopes: GET"})
        mock_requests.post.return_value = resp

        with pytest.raises(AirflowException) as e:
            getattr(auth_manager, function)(method="GET", user=user)

        assert "Request not recognized by Keycloak. invalid_scope. Invalid scopes: GET" in str(e.value)

    @pytest.mark.parametrize(
        "method, access_entity, details, permission, attributes",
        [
            [
                "GET",
                None,
                None,
                "Dag#LIST",
                {},
            ],
            [
                "GET",
                DagAccessEntity.TASK_INSTANCE,
                DagDetails(id="test"),
                "Dag#GET",
                {RESOURCE_ID_ATTRIBUTE_NAME: "test", "dag_entity": "TASK_INSTANCE"},
            ],
            [
                "GET",
                None,
                DagDetails(id="test"),
                "Dag#GET",
                {RESOURCE_ID_ATTRIBUTE_NAME: "test"},
            ],
            [
                "GET",
                DagAccessEntity.TASK_INSTANCE,
                None,
                "Dag#LIST",
                {"dag_entity": "TASK_INSTANCE"},
            ],
        ],
    )
    @pytest.mark.parametrize(
        "status_code, expected",
        [
            [200, True],
            [403, False],
        ],
    )
    @patch("airflow.providers.keycloak.auth_manager.keycloak_auth_manager.requests")
    def test_is_authorized_dag(
        self,
        mock_requests,
        method,
        access_entity,
        details,
        permission,
        attributes,
        status_code,
        expected,
        auth_manager,
        user,
    ):
        mock_requests.post.return_value.status_code = status_code

        result = auth_manager.is_authorized_dag(
            method=method, user=user, access_entity=access_entity, details=details
        )

        token_url = auth_manager._get_token_url("server_url", "realm")
        payload = auth_manager._get_payload("client_id", permission, attributes)
        headers = auth_manager._get_headers("access_token")
        mock_requests.post.assert_called_once_with(token_url, data=payload, headers=headers)
        assert result == expected

    @pytest.mark.parametrize(
        "status_code, expected",
        [
            [200, True],
            [403, False],
        ],
    )
    @patch("airflow.providers.keycloak.auth_manager.keycloak_auth_manager.requests")
    def test_is_authorized_view(
        self,
        mock_requests,
        status_code,
        expected,
        auth_manager,
        user,
    ):
        mock_requests.post.return_value.status_code = status_code

        result = auth_manager.is_authorized_view(access_view=AccessView.CLUSTER_ACTIVITY, user=user)

        token_url = auth_manager._get_token_url("server_url", "realm")
        payload = auth_manager._get_payload(
            "client_id", "View#GET", {RESOURCE_ID_ATTRIBUTE_NAME: "CLUSTER_ACTIVITY"}
        )
        headers = auth_manager._get_headers("access_token")
        mock_requests.post.assert_called_once_with(token_url, data=payload, headers=headers)
        assert result == expected

    @pytest.mark.parametrize(
        "status_code, expected",
        [
            [200, True],
            [403, False],
        ],
    )
    @patch("airflow.providers.keycloak.auth_manager.keycloak_auth_manager.requests")
    def test_is_authorized_custom_view(
        self,
        mock_requests,
        status_code,
        expected,
        auth_manager,
        user,
    ):
        mock_requests.post.return_value.status_code = status_code

        result = auth_manager.is_authorized_custom_view(method="GET", resource_name="test", user=user)

        token_url = auth_manager._get_token_url("server_url", "realm")
        payload = auth_manager._get_payload("client_id", "Custom#GET", {RESOURCE_ID_ATTRIBUTE_NAME: "test"})
        headers = auth_manager._get_headers("access_token")
        mock_requests.post.assert_called_once_with(token_url, data=payload, headers=headers)
        assert result == expected

    @pytest.mark.parametrize(
        "status_code, response, expected",
        [
            [
                200,
                [{"scopes": ["MENU"], "rsname": "Assets"}, {"scopes": ["MENU"], "rsname": "Connections"}],
                {MenuItem.ASSETS, MenuItem.CONNECTIONS},
            ],
            [200, [{"scopes": ["MENU"], "rsname": "Assets"}], {MenuItem.ASSETS}],
            [200, [], set()],
            [403, [{"scopes": ["MENU"], "rsname": "Assets"}], set()],
        ],
    )
    @patch("airflow.providers.keycloak.auth_manager.keycloak_auth_manager.requests")
    def test_filter_authorized_menu_items(
        self, mock_requests, status_code, response, expected, auth_manager, user
    ):
        mock_requests.post.return_value.status_code = status_code
        mock_requests.post.return_value.json.return_value = response
        menu_items = [MenuItem.ASSETS, MenuItem.CONNECTIONS]

        result = auth_manager.filter_authorized_menu_items(menu_items, user=user)

        token_url = auth_manager._get_token_url("server_url", "realm")
        payload = auth_manager._get_batch_payload(
            "client_id", [("MENU", MenuItem.ASSETS.value), ("MENU", MenuItem.CONNECTIONS.value)]
        )
        headers = auth_manager._get_headers("access_token")
        mock_requests.post.assert_called_once_with(token_url, data=payload, headers=headers)
        assert set(result) == expected

    @pytest.mark.parametrize(
        "status_code",
        [400, 500],
    )
    @patch("airflow.providers.keycloak.auth_manager.keycloak_auth_manager.requests")
    def test_filter_authorized_menu_items_with_failure(self, mock_requests, status_code, auth_manager, user):
        resp = Mock()
        resp.status_code = status_code
        resp.text = json.dumps({})
        mock_requests.post.return_value = resp

        menu_items = [MenuItem.ASSETS, MenuItem.CONNECTIONS]

        with pytest.raises(AirflowException):
            auth_manager.filter_authorized_menu_items(menu_items, user=user)

        token_url = auth_manager._get_token_url("server_url", "realm")
        payload = auth_manager._get_batch_payload(
            "client_id", [("MENU", MenuItem.ASSETS.value), ("MENU", MenuItem.CONNECTIONS.value)]
        )
        headers = auth_manager._get_headers("access_token")
        mock_requests.post.assert_called_once_with(token_url, data=payload, headers=headers)

    def test_get_cli_commands_return_cli_commands(self, auth_manager):
        assert len(auth_manager.get_cli_commands()) == 1

    @patch.object(KeycloakAuthManager, "_is_batch_authorized")
    def test_filter_authorized_dag_ids_uses_batch_permissions(
        self, mock_is_batch_authorized, auth_manager, user
    ):
        dag_ids = {"dag_a", "dag_b", "dag_c"}
        mock_is_batch_authorized.return_value = {("GET", "dag_a"), ("GET", "dag_c")}

        result = auth_manager.filter_authorized_dag_ids(
            dag_ids=dag_ids,
            user=user,
            method="GET",
            team_name="team-blue",
        )

        assert result == {"dag_a", "dag_c"}
        assert mock_is_batch_authorized.call_count == 1
        call_kwargs = mock_is_batch_authorized.call_args.kwargs
        assert call_kwargs["user"] is user
        assert call_kwargs["attributes"] == {"team_name": "team-blue"}
        assert set(call_kwargs["permissions"]) == {("GET", "dag_a"), ("GET", "dag_b"), ("GET", "dag_c")}

    @patch.object(KeycloakAuthManager, "_is_batch_authorized")
    @patch("airflow.providers.keycloak.auth_manager.keycloak_auth_manager.monotonic")
    def test_filter_authorized_dag_ids_uses_cache(
        self,
        mock_monotonic,
        mock_is_batch_authorized,
        auth_manager,
        user,
    ):
        mock_monotonic.side_effect = [1.0, 1.1, 2.0]
        mock_is_batch_authorized.return_value = {("GET", "dag_a")}
        auth_manager._dag_permissions_cache_ttl_seconds = 30

        dag_ids = {"dag_a", "dag_b"}

        first = auth_manager.filter_authorized_dag_ids(
            dag_ids=dag_ids,
            user=user,
            method="GET",
            team_name=None,
        )
        second = auth_manager.filter_authorized_dag_ids(
            dag_ids=dag_ids,
            user=user,
            method="GET",
            team_name=None,
        )

        assert first == {"dag_a"}
        assert second == {"dag_a"}
        assert mock_is_batch_authorized.call_count == 1

    @patch.object(KeycloakAuthManager, "_is_batch_authorized")
    @patch("airflow.providers.keycloak.auth_manager.keycloak_auth_manager.monotonic")
    def test_filter_authorized_dag_ids_cache_expires(
        self,
        mock_monotonic,
        mock_is_batch_authorized,
        auth_manager,
        user,
    ):
        mock_monotonic.side_effect = [1.0, 1.1, 10.0, 10.1]
        mock_is_batch_authorized.side_effect = [
            {("GET", "dag_a")},
            {("GET", "dag_a")},
        ]
        auth_manager._dag_permissions_cache_ttl_seconds = 5

        dag_ids = {"dag_a"}

        first = auth_manager.filter_authorized_dag_ids(
            dag_ids=dag_ids,
            user=user,
            method="GET",
            team_name=None,
        )
        second = auth_manager.filter_authorized_dag_ids(
            dag_ids=dag_ids,
            user=user,
            method="GET",
            team_name=None,
        )

        assert first == {"dag_a"}
        assert second == {"dag_a"}
        assert mock_is_batch_authorized.call_count == 2

    def test_schedule_dag_permission_warmup_submits_task(self, auth_manager, user):
        auth_manager._dag_permissions_cache_ttl_seconds = 30
        submit_mock = Mock()
        auth_manager._dag_warmup_executor.submit = submit_mock

        auth_manager.schedule_dag_permission_warmup(user)
        auth_manager.schedule_dag_permission_warmup(user)

        submit_mock.assert_called_once()
        scheduled_callable, scheduled_user, scheduled_method = submit_mock.call_args.args
        assert scheduled_callable == auth_manager._warmup_user_dag_permissions
        assert scheduled_user.get_id() == user.get_id()
        assert scheduled_method == "GET"

    def test_schedule_dag_permission_warmup_skipped_when_ttl_disabled(self, auth_manager, user):
        auth_manager._dag_permissions_cache_ttl_seconds = 0
        submit_mock = Mock()
        auth_manager._dag_warmup_executor.submit = submit_mock

        auth_manager.schedule_dag_permission_warmup(user)

        submit_mock.assert_not_called()

    def test_notify_role_change_marks_pending_and_clears_cache(self, auth_manager, user):
        auth_manager._dag_permissions_cache[("user_id", "dag_a", "GET", None)] = _DagPermissionCacheEntry(
            expires_at=10.0, allowed=True
        )

        auth_manager.notify_role_change(user_id="user_id")

        assert ("user_id", "dag_a", "GET", None) not in auth_manager._dag_permissions_cache
        assert "user_id" in auth_manager._pending_role_warmups

    def test_notify_role_change_with_user_schedules_warmup(self, auth_manager):
        auth_manager._dag_permissions_cache_ttl_seconds = 30
        submit_mock = Mock()
        auth_manager._dag_warmup_executor.submit = submit_mock
        user = KeycloakAuthManagerUser(
            user_id="user-id",
            name="username",
            access_token="token",
            refresh_token="refresh",
        )

        auth_manager.notify_role_change(user=user)

        submit_mock.assert_called_once()
