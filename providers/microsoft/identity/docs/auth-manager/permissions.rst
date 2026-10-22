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
resolved at login from the group or role claims issued by AD FS.

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
views are available to every role. Any other view, such as the audit log, import errors and reparsing
of files not tied to a Dag, requires ``ADMIN``. The Connections and Variables menu entries are shown
to ``OP`` and ``ADMIN`` only.

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
  the rows listed are still filtered per team. Plugin actions that change state need a global role.
* Team members can read their team's plugin APIs; changing state through them needs ``OP`` in the
  team.
* The teams listed in ``team_role_mapping`` must exist in Airflow (``airflow teams create``).
  Differences are logged as warnings when the API server starts.
