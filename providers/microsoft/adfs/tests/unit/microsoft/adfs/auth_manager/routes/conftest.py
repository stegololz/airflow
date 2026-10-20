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

from unittest.mock import Mock, patch

import pytest
from fastapi.testclient import TestClient

from airflow.api_fastapi.app import create_app
from airflow.providers.microsoft.adfs.auth_manager.adfs_auth_manager import AdfsAuthManager
from airflow.providers.microsoft.adfs.auth_manager.oidc import AdfsOidcClient

from tests_common.test_utils.config import conf_vars
from unit.microsoft.adfs.auth_manager.adfs_fixtures import AUTH_MANAGER_CONF, BASE_URL, CLIENT_ID, METADATA


@pytest.fixture
def oidc_client():
    client = Mock(spec=AdfsOidcClient)
    client.client_id = CLIENT_ID
    client.resource = None
    client.end_session_endpoint = METADATA["end_session_endpoint"]
    client.build_authorization_url.return_value = (
        f"{METADATA['authorization_endpoint']}?client_id={CLIENT_ID}"
    )
    return client


@pytest.fixture
def client(oidc_client):
    with conf_vars(
        {
            (
                "core",
                "auth_manager",
            ): "airflow.providers.microsoft.adfs.auth_manager.adfs_auth_manager.AdfsAuthManager",
            ("api", "base_url"): BASE_URL,
            **AUTH_MANAGER_CONF,
        }
    ):
        with patch.object(AdfsAuthManager, "get_oidc_client", autospec=True, return_value=oidc_client):
            yield TestClient(create_app())
