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

.. include:: /../../../../devel-common/src/sphinx_exts/includes/security.rst


Securing the AD FS auth manager
===============================

* ``[adfs_auth_manager] client_secret`` is a sensitive option. Provide it through a secrets backend
  or the ``AIRFLOW__ADFS_AUTH_MANAGER__CLIENT_SECRET`` environment variable rather than in
  ``airflow.cfg``.
* TLS verification of the connections to AD FS cannot be disabled. When the AD FS certificate is
  issued by an internal certificate authority, set ``[adfs_auth_manager] ca_bundle_path`` to a CA
  bundle containing that authority.
* Set ``[api] base_url`` to the public URL of Airflow. The redirect URIs sent to AD FS are built from
  it rather than from the ``Host`` header of the request.

See :doc:`auth-manager/index` for how tokens issued by AD FS are validated.
