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

CONF_SECTION_NAME = "adfs_auth_manager"
CONF_ISSUER_KEY = "issuer"
CONF_CLIENT_ID_KEY = "client_id"
CONF_CLIENT_SECRET_KEY = "client_secret"
CONF_SCOPE_KEY = "scope"
CONF_RESOURCE_KEY = "resource"
CONF_ACCESS_TOKEN_ISSUERS_KEY = "access_token_issuers"
CONF_USERNAME_CLAIMS_KEY = "username_claims"
CONF_STRIP_DOMAIN_PREFIX_KEY = "strip_domain_prefix"
CONF_ROLES_CLAIMS_KEY = "roles_claims"
CONF_ROLE_MAPPING_KEY = "role_mapping"
CONF_DEFAULT_ROLE_KEY = "default_role"
CONF_TEAM_ROLE_MAPPING_KEY = "team_role_mapping"
CONF_LEEWAY_SECONDS_KEY = "leeway_seconds"
CONF_CA_BUNDLE_PATH_KEY = "ca_bundle_path"
CONF_REQUEST_TIMEOUT_SECONDS_KEY = "request_timeout_seconds"
CONF_JWKS_CACHE_TTL_SECONDS_KEY = "jwks_cache_ttl_seconds"
CONF_LOGOUT_FROM_ADFS_KEY = "logout_from_adfs"

DEFAULT_SCOPE = "openid profile email allatclaims"
DEFAULT_USERNAME_CLAIMS = "upn,unique_name,email,sub"
DEFAULT_ROLES_CLAIMS = "role,roles,group,groups,http://schemas.microsoft.com/ws/2008/06/identity/claims/role"

COOKIE_NAME_AUTH_REQUEST = "_adfs_auth_request"
COOKIE_NAME_ID_TOKEN = "_adfs_id_token"
AUTH_REQUEST_COOKIE_MAX_AGE = 300
# Browsers drop cookies larger than 4096 bytes (name, value and attributes included). An ID token
# carrying many group claims can exceed that, in which case logout proceeds without ``id_token_hint``.
MAX_ID_TOKEN_COOKIE_LENGTH = 3800
