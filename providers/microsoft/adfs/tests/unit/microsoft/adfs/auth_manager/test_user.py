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

from airflow.providers.microsoft.adfs.auth_manager.roles import AdfsAuthManagerRole
from airflow.providers.microsoft.adfs.auth_manager.user import AdfsAuthManagerUser


class TestAdfsAuthManagerUser:
    def test_user(self):
        user = AdfsAuthManagerUser(user_id="jdoe@example.com", name="John Doe", role=AdfsAuthManagerRole.OP)

        assert user.get_id() == "jdoe@example.com"
        assert user.get_name() == "jdoe@example.com"
        assert user.get_display_name() == "John Doe"
