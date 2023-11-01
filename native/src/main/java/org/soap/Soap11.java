// Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com) All Rights Reserved.
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package org.soap;

import io.ballerina.runtime.api.Environment;
import io.ballerina.runtime.api.Future;
import io.ballerina.runtime.api.PredefinedTypes;
import io.ballerina.runtime.api.async.StrandMetadata;
import io.ballerina.runtime.api.creators.TypeCreator;
import io.ballerina.runtime.api.types.UnionType;
import io.ballerina.runtime.api.values.BMap;
import io.ballerina.runtime.api.values.BObject;
import io.ballerina.runtime.api.values.BString;
import io.ballerina.runtime.api.values.BTypedesc;

import static org.wssec.ModuleUtils.getModule;


public class Soap11 {
    private static final String REMOTE_FUNCTION = "generateResponse";
    public static final StrandMetadata REMOTE_EXECUTION_STRAND = new StrandMetadata(
            getModule().getOrg(),
            getModule().getName(),
            getModule().getMajorVersion(),
            REMOTE_FUNCTION);

    public static Object sendReceive(Environment env, BObject soap11, Object body, BString action,
                                     BMap<BString, BString[]> headers, BString path, BTypedesc typeParam) {
        Future future = env.markAsync();
        ExecutionCallback executionCallback = new ExecutionCallback(future);
        UnionType typeUnion = TypeCreator.createUnionType(PredefinedTypes.TYPE_XML, PredefinedTypes.TYPE_JSON_ARRAY,
                                                          PredefinedTypes.TYPE_ERROR);
        Object[] arguments = new Object[]{body, true, action, true, headers, true, path, true};
        env.getRuntime().invokeMethodAsyncConcurrently(soap11, REMOTE_FUNCTION, null, REMOTE_EXECUTION_STRAND,
                                                       executionCallback, null, typeUnion, arguments);
        return null;
    }
}
