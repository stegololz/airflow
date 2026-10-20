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

from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from airflow.providers.microsoft.adfs.auth_manager.adfs_auth_manager import AdfsAuthManager

from tests_common.test_utils.config import conf_vars
from unit.microsoft.adfs.auth_manager.adfs_fixtures import (
    ACCESS_TOKEN_ISSUER,
    AUTH_MANAGER_CONF,
    CLIENT_ID,
    ISSUER,
    NONCE,
    NOW,
    RESOURCE,
    build_jwk,
)


@pytest.fixture(scope="session")
def signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def jwks(signing_key) -> dict[str, Any]:
    return {"keys": [build_jwk(signing_key, "key-1")]}


@pytest.fixture
def make_token(signing_key):
    def _make_token(claims: dict[str, Any], *, kid: str | None = "key-1", key: Any = None, algorithm="RS256"):
        headers = {"kid": kid} if kid else None
        return jwt.encode(claims, signing_key if key is None else key, algorithm=algorithm, headers=headers)

    return _make_token


@pytest.fixture
def id_token_claims() -> dict[str, Any]:
    return {
        "aud": CLIENT_ID,
        "iss": ISSUER,
        "iat": NOW,
        "nbf": NOW,
        "exp": NOW + 3600,
        "auth_time": NOW,
        "nonce": NONCE,
        # AD FS issues an opaque, per-client value in ``sub``.
        "sub": "Qm9ndXNPcGFxdWVQZXJDbGllbnQ=",
        "upn": "jdoe@example.com",
        "unique_name": "EXAMPLE\\jdoe",
        "sid": "S-1-5-21-1111111111-2222222222-3333333333-1001",
    }


@pytest.fixture
def access_token_claims() -> dict[str, Any]:
    # AD FS access tokens may carry neither ``sub`` nor ``upn``, and a single role as a string.
    return {
        "aud": RESOURCE,
        "iss": ACCESS_TOKEN_ISSUER,
        "iat": NOW,
        "nbf": NOW,
        "exp": NOW + 3600,
        "unique_name": "EXAMPLE\\jdoe",
        "role": "Airflow Operators",
        "scp": "openid",
        "appid": CLIENT_ID,
        "apptype": "Confidential",
    }


@pytest.fixture
def auth_manager():
    with conf_vars(AUTH_MANAGER_CONF):
        yield AdfsAuthManager()
