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

package org.wssec;

import io.ballerina.runtime.api.creators.ValueCreator;
import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BArray;
import io.ballerina.runtime.api.values.BHandle;
import io.ballerina.runtime.api.values.BObject;
import io.ballerina.runtime.api.values.BString;

import static org.wssec.Constants.NATIVE_SIGNATURE;

public class Signature {

    private String signatureAlgorithm;
    private byte[] signatureValue;

    public static void setSignatureAlgorithm(BObject sign, BString signatureAlgorithm) {
        BHandle handle = (BHandle) sign.get(StringUtils.fromString(NATIVE_SIGNATURE));
        Signature signature = (Signature) handle.getValue();
        signature.setSignatureAlgorithm(signatureAlgorithm.getValue());
    }

    public static void setSignatureValue(BObject sign, BArray signatureValue) {
        BHandle handle = (BHandle) sign.get(StringUtils.fromString(NATIVE_SIGNATURE));
        Signature signature = (Signature) handle.getValue();
        signature.setSignatureValue(signatureValue.getByteArray());
    }

    public static BArray getSignatureValue(BObject sign) {
        BHandle handle = (BHandle) sign.get(StringUtils.fromString(NATIVE_SIGNATURE));
        Signature signature = (Signature) handle.getValue();
        return ValueCreator.createArrayValue(signature.getSignatureValue());
    }

    protected String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    protected void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    protected byte[] getSignatureValue() {
        return signatureValue;
    }

    protected void setSignatureValue(byte[] signatureValue) {
        this.signatureValue = signatureValue;
    }
}
