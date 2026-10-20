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

"""Test data modelled on the tokens and discovery document issued by AD FS."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from jwt.algorithms import RSAAlgorithm

from airflow.providers.microsoft.adfs.auth_manager.constants import (
    CONF_CLIENT_ID_KEY,
    CONF_ISSUER_KEY,
    CONF_ROLE_MAPPING_KEY,
    CONF_SECTION_NAME,
)

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = "https://adfs.example.com/adfs"
# AD FS stamps access tokens with this issuer, which differs from the OpenID Connect issuer.
ACCESS_TOKEN_ISSUER = "http://adfs.example.com/adfs/services/trust"
CLIENT_ID = "8a6f0c1e-1d2b-4c3a-9e8f-0123456789ab"
RESOURCE = "https://airflow.example.com/api"
BASE_URL = "https://airflow.example.com"
JWKS_URI = "https://adfs.example.com/adfs/discovery/keys"
NONCE = "nonce-from-login"
NOW = 1_800_000_000

METADATA: dict[str, Any] = {
    "issuer": ISSUER,
    "authorization_endpoint": "https://adfs.example.com/adfs/oauth2/authorize/",
    "token_endpoint": "https://adfs.example.com/adfs/oauth2/token/",
    "jwks_uri": JWKS_URI,
    "end_session_endpoint": "https://adfs.example.com/adfs/oauth2/logout",
    "userinfo_endpoint": "https://adfs.example.com/adfs/userinfo",
    "access_token_issuer": ACCESS_TOKEN_ISSUER,
}

ROLE_MAPPING = json.dumps(
    {
        "Airflow Admins": "ADMIN",
        "Airflow Operators": "OP",
        "Airflow Users": "USER",
        "Airflow Viewers": "VIEWER",
    }
)

AUTH_MANAGER_CONF = {
    (CONF_SECTION_NAME, CONF_ISSUER_KEY): ISSUER,
    (CONF_SECTION_NAME, CONF_CLIENT_ID_KEY): CLIENT_ID,
    (CONF_SECTION_NAME, CONF_ROLE_MAPPING_KEY): ROLE_MAPPING,
}


def build_jwk(private_key: rsa.RSAPrivateKey, kid: str) -> dict[str, Any]:
    jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    # AD FS publishes both ``kid`` and ``x5t`` (the certificate thumbprint) for each key.
    jwk.update(kid=kid, x5t=kid, use="sig", alg="RS256")
    return jwk
