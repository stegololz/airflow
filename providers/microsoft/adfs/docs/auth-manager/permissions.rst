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

Each user has one Airflow role, resolved at login from the group or role claims issued by AD FS.

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
