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

===========
Permissions
===========

Each user has a global Airflow role and, in :ref:`multi-team <adfs-multi-team>` mode, a role per team,
and optionally roles on some Dags, connections, variables and pools, resolved at login from the group
or role claims issued by AD FS.

Role mapping
------------

``[adfs_auth_manager] role_mapping`` maps claim values to Airflow roles:

.. code-block:: json

  {
    "Airflow Admins": "ADMIN",
    "Airflow Operators": "OP",
    "Airflow Users": "USER",
    "Airflow Viewers": "VIEWER"
  }

* Values of all the claims listed in ``roles_claims`` are matched against the keys of the mapping.
* Keys are matched case-insensitively, like Active Directory group names. Two keys differing only by
  case are rejected.
* When several values match, the highest role is used.
* When no value matches, the user gets ``default_role``, or is denied access if ``default_role`` is
  empty. The unmatched values are logged at the ``INFO`` level, which helps to diagnose a renamed group.

Roles
-----

Each role grants the permissions of the roles below it.

=================================================  ===========  =============================
Resource                                           Read (GET)   Create, update, delete
=================================================  ===========  =============================
Dags, Dag runs, task instances and other Dag data  ``VIEWER``   ``USER``
Assets and asset aliases                           ``VIEWER``   ``OP``
Pools                                              ``VIEWER``   ``OP``
Configuration                                      ``VIEWER``   ``OP``
Connections                                        ``OP``       ``OP``
Variables                                          ``OP``       ``OP``
Plugin views                                       ``VIEWER``   ``OP``
=================================================  ===========  =============================

The cluster activity, documentation, import errors, jobs, plugins, providers, triggers and website
views are available to every role. Any other view requires ``ADMIN``. Up to Airflow 3.3, audit log
entries and import errors that are not tied to a Dag are shown to every role, users with only Dag
grants included; later versions require ``ADMIN`` for them. The Connections and Variables menu entries
are shown to ``OP`` and ``ADMIN``, and to users with grants on connections or variables.

.. _adfs-resource-grants:

Resource grants
---------------

``[adfs_auth_manager] resource_role_mapping`` gives users a role on some Dags, connections, variables
or pools only. It maps claim values to lists of grants. Each grant names one kind of resource with
``dags``, ``connections``, ``variables`` or ``pools`` (an ID, or an ``fnmatch`` pattern such as
``finance_*``), and a ``role``:

.. code-block:: json

  {
    "Finance Ops": [
      {"dags": "finance_*", "role": "USER"},
      {"connections": "finance_*", "role": "OP"},
      {"variables": "finance_*", "role": "OP"},
      {"pools": "finance", "role": "OP"}
    ],
    "Finance Auditors": [{"dags": "finance_*", "role": "VIEWER"}]
  }

* The role on a resource is the highest of the global role, the team role and the matching grants of
  that kind. Grants only add access. Give users with grants no global role, or they see every Dag of
  no team. The permissions of each role are the ones in the table above: connections and variables
  need ``OP``, so their grants must have the ``OP`` or ``ADMIN`` role.
* Grants let users read, change and delete the matching resources, and create them through the bulk
  endpoints, which name each resource. In multi-team mode, the bulk endpoints check a new resource
  as a resource of no team, so only grants without ``team`` can create through them. Requests that do
  not name the resource, such as creating a single connection, variable or pool, and triggering a
  backfill before Airflow 3.1.8, are only allowed by the global and team roles. Lists show the matching
  resources only.
* Grants on connections, variables and pools require Airflow 3.2.0 or later: earlier versions do not
  filter these lists per resource, and the API server refuses to start with such grants.
* Users with only grants see the matching resources and their menu entries, the views available to
  every role (cluster activity, documentation, import errors, jobs, plugins, providers, triggers and
  website) and, before Airflow 3.4, the audit log entries not tied to a Dag. Jobs and triggers are not
  filtered per Dag. They get no assets, configuration, plugin actions or other connections, variables
  and pools.
* Patterns match the Dag ID, connection ID, variable key or pool name, case-sensitively. On MySQL,
  connection IDs, variable keys and pool names are looked up with the database collation, which is
  often case-insensitive: a pattern then also covers names that differ from a match only by case.
* In multi-team mode, add ``"team"`` to a grant: it then only applies to that team's resources, so a
  resource added by another team cannot match it. A grant without ``team`` applies to resources of no
  team only.
* Before Airflow 3.3.0, with ``[core] multi_team`` enabled, the bulk endpoints of connections, variables
  and pools do not check the team of an existing resource they create over, or the destination team.
  A grant without ``team`` can then reach another team's resource whose ID matches its pattern: bind
  grants to a team, or use Airflow 3.3.0 or later. A grant can also move a matching resource to
  another team, which only Airflow 3.3.0 or later prevents.
* On every Airflow version, with ``[core] multi_team`` enabled, a bulk update, or a bulk create that
  overwrites, which sets ``team_name`` to ``null`` is only checked against the current team of the
  resource. A grant bound to a team, like a role in that team, can thus move the team's matching
  connections, variables and pools to no team, where every team can use them.
* Grants are checked in memory, without calling AD FS, against the configuration loaded when the API
  server starts. After a restart, changed or removed grants apply to every session, current ones
  included. A claim value the user did not have when logging in, such as a group they were just added
  to, only counts after their next login, and a removed group membership after their token expires.

.. _adfs-multi-team:

Multi-team
----------

With ``[core] multi_team`` enabled, ``[adfs_auth_manager] team_role_mapping`` gives users a role in a
team. It maps claim values to ``"<team>:<role>"`` strings:

.. code-block:: json

  {
    "Airflow team-a Operators": "team-a:OP",
    "Airflow team-a Viewers": "team-a:VIEWER",
    "Airflow team-b Users": "team-b:USER"
  }

A user can have a role in several teams; when several values match the same team, the highest role is
used. ``role_mapping`` stays optional and gives the global role.

* Dags, connections, pools and variables of a team are authorized with the user's role in that team.
  A global ``ADMIN`` can access every team; other global roles do not apply to team resources.
* Resources of no team (shared Dags, connections, pools and variables, assets, configuration) are
  authorized with the global role. Members of a team without a global role can read them as
  ``VIEWER``.
* Menu entries, list pages and plugin views use the highest role of the user, global or in a team;
  the rows listed are still filtered per team. Grants add the menu entries of their kind (see
  :ref:`resource grants <adfs-resource-grants>`). Plugin actions that change state need a global role.
* Team members can read their team's plugin APIs; changing state through them needs ``OP`` in the
  team.
* The teams named in ``team_role_mapping`` and ``resource_role_mapping`` must exist in Airflow
  (``airflow teams create``). From Airflow 3.2, the API server compares them with the teams in the
  database when it starts. Depending on the Airflow version, a team missing from the database stops
  the API server or is reported as a warning.
