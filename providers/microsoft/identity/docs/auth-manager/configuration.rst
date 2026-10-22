 .. Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

 ..   http://www.apache.org/licenses/LICENSE-2.0

 .. Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.

===============================================
Configure Airflow to use the AD FS auth manager
===============================================

.. note::
  These configuration options must be set on the hosts running the Airflow API server.

.. code-block:: ini

  [core]
  auth_manager = airflow.providers.microsoft.identity.auth_manager.adfs_auth_manager.AdfsAuthManager

or

.. code-block:: bash

  export AIRFLOW__CORE__AUTH_MANAGER='airflow.providers.microsoft.identity.auth_manager.adfs_auth_manager.AdfsAuthManager'

The options of the auth manager are set in the ``[adfs_auth_manager]`` section, or with environment
variables named ``AIRFLOW__ADFS_AUTH_MANAGER__<OPTION_NAME>``. All options are described in the
:doc:`configuration reference <../configurations-ref>`.

Required options
----------------

* ``issuer``: the AD FS issuer, ``https://<AD FS host>/adfs``. It must be the ``issuer`` value of
  ``https://<AD FS host>/adfs/.well-known/openid-configuration``.
* ``client_id``: the identifier of the server or native application registered in AD FS.
* ``role_mapping``: a JSON object mapping group or role claim values to Airflow roles, see
  :doc:`permissions`. It is optional when ``team_role_mapping`` (multi-team mode) or
  ``resource_role_mapping`` is set.

``[api] base_url`` must also be set to the public URL of Airflow. The redirect URIs sent to AD FS are
built from it and must match the URIs registered in AD FS exactly.

Example
-------

.. code-block:: ini

  [api]
  base_url = https://airflow.example.com

  [adfs_auth_manager]
  issuer = https://adfs.example.com/adfs
  client_id = 2f1c9d4e-0000-4000-8000-000000000000
  # Set for a server application, leave empty for a native application.
  client_secret = <secret>
  resource = https://airflow.example.com/api
  role_mapping = {"Airflow Admins": "ADMIN", "Airflow Operators": "OP", "Airflow Users": "USER", "Airflow Viewers": "VIEWER"}

Other options
-------------

* ``client_secret``: secret of the server application. Leave it empty for a native application.
* ``resource``: identifier of the Web API whose issuance transform rules issue the claims used by
  Airflow. When set, the access token is validated and its claims are used in addition to the ID token
  claims.
* ``access_token_issuers``: accepted issuers of access tokens. AD FS issues access tokens with
  ``http://<AD FS host>/adfs/services/trust`` and publishes this value as ``access_token_issuer`` in its
  discovery document, which is accepted by default.
* ``username_claims``: claims used for the Airflow user name, in order of preference. Defaults to
  ``upn,unique_name,email,sub``. ``sub`` comes last because AD FS issues an opaque value in it.
* ``strip_domain_prefix``: remove the ``DOMAIN\`` prefix of the user name. Enable it only if user names
  are unique across the domains trusted by AD FS.
* ``roles_claims``: claims holding the values matched against ``role_mapping``, ``team_role_mapping``
  and ``resource_role_mapping``.
* ``resource_role_mapping``: a JSON object mapping group or role claim values to roles on some Dags,
  connections, variables or pools, see :ref:`resource grants <adfs-resource-grants>`.
* ``team_role_mapping``: in multi-team mode, a JSON object mapping group or role claim values to a
  role in a team, see :ref:`multi-team <adfs-multi-team>`.
* ``default_role``: role given to users matching no entry of ``role_mapping``. When empty, they are
  denied access.
* ``leeway_seconds``: clock skew tolerated when validating token timestamps. Defaults to 30 seconds.
* ``ca_bundle_path``: CA bundle used to verify the AD FS certificate when it is issued by an internal
  certificate authority. TLS verification cannot be disabled.
* ``request_timeout_seconds`` and ``jwks_cache_ttl_seconds``: timeout of the requests to AD FS and
  cache duration of the AD FS signing keys. Keys are fetched again as soon as a token is signed with an
  unknown key, so automatic certificate rollover in AD FS needs no action.
* ``logout_from_adfs``: whether logging out of Airflow also logs the user out of AD FS.
