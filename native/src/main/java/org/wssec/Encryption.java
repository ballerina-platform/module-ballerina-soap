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

import static org.wssec.Constants.NATIVE_ENCRYPTION;
import static org.wssec.Utils.createError;

public class Encryption {

    private String encryptionAlgorithm;
    private byte[] encryptedData;

    public static void setEncryptionAlgorithm(BObject encrypt, BString encryptionAlgorithm) {
        BHandle handle = (BHandle) encrypt.get(StringUtils.fromString(NATIVE_ENCRYPTION));
        Encryption encryption = (Encryption) handle.getValue();
        encryption.setEncryptionAlgorithm(encryptionAlgorithm.getValue());
    }

    public static void setEncryptedData(BObject encrypt, BArray encryptedData) {
        BHandle handle = (BHandle) encrypt.get(StringUtils.fromString(NATIVE_ENCRYPTION));
        Encryption encryption = (Encryption) handle.getValue();
        encryption.setEncryptedData(encryptedData.getByteArray());
    }

    public static BArray getEncryptedData(BObject encrypt) {
        BHandle handle = (BHandle) encrypt.get(StringUtils.fromString(NATIVE_ENCRYPTION));
        Encryption encryption = (Encryption) handle.getValue();
        return ValueCreator.createArrayValue(encryption.getEncryptedData());
    }

    public static Object getEncryptedKeyElements(BArray encryptedData) {
        try {
            return WsSecurityUtils.getEncryptedKeyElement(encryptedData.getByteArray());
        } catch (Exception e) {
            return createError(e.getMessage());
        }
    }

    protected String getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    protected byte[] getEncryptedData() {
        return encryptedData;
    }

    protected void setEncryptionAlgorithm(String encryptionAlgorithm) {
        this.encryptionAlgorithm = encryptionAlgorithm;
    }

    protected void setEncryptedData(byte[] encryptedData) {
        this.encryptedData = encryptedData;
    }
}
