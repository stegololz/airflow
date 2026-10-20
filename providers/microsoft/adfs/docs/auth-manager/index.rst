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

==================
AD FS auth manager
==================

.. warning::
  The AD FS auth manager is in incubation. Its behaviour and configuration may change without warning
  until version 1.0.0 of the provider.

The AD FS auth manager logs users in to Airflow with Microsoft Active Directory Federation Services
(AD FS) and gives them an Airflow role based on the groups or roles that AD FS issues for them.
It requires AD FS on Windows Server 2016 or later.

**Getting started**

.. toctree::
    :maxdepth: 2

    setup-adfs
    configuration
    permissions

How it works
------------

* The API server runs the OpenID Connect authorization code flow with PKCE, a ``state`` value bound to
  the browser and a ``nonce``. The authorization code is redeemed by the API server, so the AD FS token
  endpoint does not need to allow cross-origin requests.
* The ID token returned by AD FS is validated: RS256 signature against the AD FS signing keys, issuer,
  audience (``client_id``), expiry and nonce. When ``resource`` is configured, the access token is
  validated as well (its audience must be ``resource``) and its claims are used too.
* The user name and the Airflow role are read from the validated token claims. The AD FS user
  information endpoint is not used, because it only returns ``sub``.
* The role is resolved once, at login, and stored in the Airflow token. Authorization decisions do not
  call AD FS.
* At logout, the user is redirected to the AD FS logout endpoint, which also ends the AD FS single
  sign-on session (unless ``logout_from_adfs`` is disabled).

Limitations
-----------

* Changes to the groups of a user in Active Directory apply at the next login. The Airflow token stays
  valid for ``[api_auth] jwt_expiration_time`` (24 hours by default); lower it to apply such changes
  sooner.
* Before Airflow 3.2, logging out deletes the Airflow token cookie but does not revoke the token,
  which stays valid until it expires.
* Multi-team mode (``[core] multi_team``) is not supported.
* There is no endpoint to exchange AD FS credentials or tokens for an Airflow API token yet.
