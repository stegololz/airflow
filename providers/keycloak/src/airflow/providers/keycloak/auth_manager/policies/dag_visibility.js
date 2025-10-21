/*!
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/**
 * Keycloak JavaScript policy for batch DAG authorization decisions.
 *
 * Airflow sends all candidate DAG ids in the UMA ticket context attribute
 * ``dag_ids`` (comma separated). This policy inspects each id and adds
 * allowed DAG ids back to the permission as individual scopes so that the
 * Airflow auth manager can map the results efficiently.
 *
 * Customize ``isDagAllowedForUser`` to match your organisation's access model.
 */
var context = $evaluation.getContext();
var attributes = context.getAttributes();

var dagIdsAttr = attributes.getValue("dag_ids");
if (!dagIdsAttr || dagIdsAttr.isEmpty()) {
    $evaluation.deny();
    quit();
}

var dagIds = dagIdsAttr.get(0).split(/\s*,\s*/);

var identity = context.getIdentity();

var teamNameAttr = attributes.getValue("team_name");
var teamName = teamNameAttr && !teamNameAttr.isEmpty() ? teamNameAttr.get(0) : null;

var ALLOW_ATTRIBUTE = "airflow_dag_allow";
var allowedIds = collectAllowedIds(identity);

function collectAllowedIds(user) {
    var attrValues = user.getAttributes().getValue(ALLOW_ATTRIBUTE);
    if (!attrValues || attrValues.isEmpty()) {
        return [];
    }
    var aggregated = "";
    for (var i = 0; i < attrValues.size(); i++) {
        var value = attrValues.get(i);
        if (value) {
            if (aggregated.length > 0) {
                aggregated += ",";
            }
            aggregated += value;
        }
    }
    if (!aggregated) {
        return [];
    }
    var entries = aggregated.split(/\s*,\s*/);
    var clean = [];
    for (var j = 0; j < entries.length; j++) {
        if (entries[j]) {
            clean.push(entries[j]);
        }
    }
    return clean;
}

function isDagAllowedForUser(dagId, user, team) {
    for (var i = 0; i < allowedIds.length; i++) {
        if (allowedIds[i] === dagId) {
            return true;
        }
    }
    return false;
}

var permission = $evaluation.getPermission();
var granted = false;

for (var i = 0; i < dagIds.length; i++) {
    var dagId = dagIds[i];
    if (!dagId) {
        continue;
    }

    if (isDagAllowedForUser(dagId, identity, teamName)) {
        permission.addScope(dagId);
        granted = true;
    }
}

if (granted) {
    $evaluation.grant();
} else {
    $evaluation.deny();
}
