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

package io.ballerina.lib.soap;

import io.ballerina.runtime.api.Environment;
import io.ballerina.runtime.api.values.BError;
import io.ballerina.runtime.api.values.BMap;
import io.ballerina.runtime.api.values.BObject;
import io.ballerina.runtime.api.values.BString;
import io.ballerina.runtime.api.values.BTypedesc;

public class Soap {
    private static final String REMOTE_FUNCTION = "generateResponse";

    public static Object sendReceive11(Environment env, BObject soap11, Object body, BString action,
                                       BMap<BString, BString[]> headers, BString path, BTypedesc typeDesc) {
        return env.yieldAndRun(() -> {
            try {
                Object[] arguments = new Object[]{body, action, headers, path};
                Object result = env.getRuntime().callMethod(soap11, REMOTE_FUNCTION, null, arguments);
                if (result instanceof BError) {
                    ((BError) result).printStackTrace();
                }
                return result;
            } catch (BError bError) {
                bError.printStackTrace();
                System.exit(1);
            }
            return null;
        });
    }

    public static Object sendReceive12(Environment env, BObject soap12, Object body, Object action,
                                       BMap<BString, BString[]> headers, BString path, BTypedesc typeDesc) {
        return env.yieldAndRun(() -> {
            try {
                Object[] arguments = new Object[]{body, action, headers, path};
                return env.getRuntime().callMethod(soap12, REMOTE_FUNCTION, null, arguments);
            } catch (BError bError) {
                bError.printStackTrace();
                System.exit(1);
            }
            return null;
        });
    }
}
