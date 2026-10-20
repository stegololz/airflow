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

=========================
Register Airflow in AD FS
=========================

Airflow is registered in AD FS as an application group. The steps below use the AD FS PowerShell
module; the same settings can be made in the AD FS management console.

In the examples, Airflow is served at ``https://airflow.example.com`` (the value of ``[api] base_url``)
and AD FS at ``https://adfs.example.com``.

Application group and client
----------------------------

Create an application group, then register Airflow in it either as a server application (confidential
client, with a secret) or as a native application (public client, without a secret). PKCE is used in
both cases. A server application is recommended.

.. code-block:: powershell

  New-AdfsApplicationGroup -Name "Airflow"

  # Confidential client: note the generated secret, it is shown only once.
  Add-AdfsServerApplication -Name "Airflow - Server" -ApplicationGroupIdentifier "Airflow" `
    -Identifier "<client id>" -GenerateClientSecret `
    -RedirectUri "https://airflow.example.com/auth/login_callback",
      "https://airflow.example.com/auth/logout_callback"

  # Or a public client:
  Add-AdfsNativeClientApplication -Name "Airflow - Native" -ApplicationGroupIdentifier "Airflow" `
    -Identifier "<client id>" `
    -RedirectUri "https://airflow.example.com/auth/login_callback",
      "https://airflow.example.com/auth/logout_callback"

AD FS compares redirect URIs exactly. Register both redirect URIs built from ``[api] base_url``:

* ``<base_url>/auth/login_callback``, where AD FS sends the user after login
* ``<base_url>/auth/logout_callback``, where AD FS sends the user after logout. AD FS only redirects
  there when the logout request carries the ID token of the user, see the size limit below.

Web API and claims
------------------

AD FS decides which claims it issues with the issuance transform rules of a Web API, not with the
requested scopes. Add a Web API to the application group, configure its rules, and set its identifier
as ``[adfs_auth_manager] resource``. Requesting the ``allatclaims`` scope makes AD FS copy the claims
of these rules into the ID token as well.

.. code-block:: powershell

  Add-AdfsWebApiApplication -Name "Airflow - API" -ApplicationGroupIdentifier "Airflow" `
    -Identifier "https://airflow.example.com/api" `
    -AccessControlPolicyName "Permit everyone" `
    -IssuanceTransformRules $rules

  Grant-AdfsApplicationPermission -ClientRoleIdentifier "<client id>" `
    -ServerRoleIdentifier "https://airflow.example.com/api" `
    -ScopeNames openid, profile, email, allatclaims

The rules must issue:

* a user name claim, for example ``upn`` (``user@example.com``) or ``unique_name``
  (``EXAMPLE\jdoe`` or ``jdoe`` depending on the rule). The claims used are set by
  ``username_claims``.
* the groups that grant access to Airflow, for example with the "Send Group Membership as a Claim"
  template, or an LDAP attribute rule sending ``Token-Groups - Unqualified Names`` as ``Role``.
  AD FS issues the role claim as ``role``. The claims used are set by ``roles_claims``.
* optionally ``given_name`` and ``family_name`` (``Given-Name`` sent as ``Given Name`` and ``Surname``
  as ``Surname``), used as the display name. AD FS issues the ``Name`` claim type as ``unique_name``,
  which is a user name claim: do not send a display name as ``Name``.

Issue only the groups used in ``role_mapping``. Airflow keeps the ID token in a cookie to send it back
to AD FS at logout, and does not keep an ID token longer than 3800 characters, which is reached with
about 60 group names. AD FS then does not redirect the user back to Airflow after logout, and a warning
is logged at login.

Example of rules sending the user principal name and the groups whose name starts with ``Airflow``
as roles:

.. code-block:: powershell

  $rules = @'
  @RuleTemplate = "LdapClaims"
  @RuleName = "User name and groups"
  c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
   => issue(store = "Active Directory",
            types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"),
            query = ";userPrincipalName;{0}", param = c.Value);

  @RuleName = "Groups, read"
  c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
   => add(store = "Active Directory", types = ("urn:airflow:group"),
          query = ";tokenGroups;{0}", param = c.Value);

  @RuleName = "Airflow groups"
  c:[Type == "urn:airflow:group", Value =~ "^Airflow "]
   => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", Value = c.Value);
  '@

AD FS issues a claim holding a single value as a string and a claim holding several values as a list;
both forms are accepted.
