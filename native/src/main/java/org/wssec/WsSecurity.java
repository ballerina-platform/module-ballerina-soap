// Copyright (c) 2023, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
//
// WSO2 Inc. licenses this file to you under the Apache License,
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

import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BHandle;
import io.ballerina.runtime.api.values.BObject;
import io.ballerina.runtime.api.values.BString;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.UsernameTokenUtil;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.WSSecDKEncrypt;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.message.WSSecTimestamp;
import org.apache.wss4j.dom.message.WSSecUsernameToken;
import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.JCEMapper;
import org.w3c.dom.Document;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.apache.wss4j.common.WSS4JConstants.AES_128_GCM;
import static org.apache.wss4j.common.WSS4JConstants.HMAC_SHA1;
import static org.apache.wss4j.dom.WSConstants.CUSTOM_KEY_IDENTIFIER;
import static org.apache.wss4j.dom.WSConstants.X509_KEY_IDENTIFIER;
import static org.wssec.Constants.DERIVED_KEY_DIGEST;
import static org.wssec.Constants.DERIVED_KEY_TEXT;
import static org.wssec.Constants.ITERATION;
import static org.wssec.Constants.NATIVE_ENCRYPTION;
import static org.wssec.Constants.NATIVE_SEC_HEADER;
import static org.wssec.Constants.NATIVE_SIGNATURE;
import static org.wssec.Constants.X509;
import static org.wssec.Utils.createError;
import static org.wssec.WsSecurityUtils.convertDocumentToString;
import static org.wssec.WsSecurityUtils.setUTChildElements;

public class WsSecurity {

    public static Object applyUsernameTokenPolicy(BObject wsSecHeader, BString username,
                                                  BString password, BString passwordType) {
        BHandle handle = (BHandle) wsSecHeader.get(StringUtils.fromString(NATIVE_SEC_HEADER));
        WsSecurityHeader wsSecurityHeader = (WsSecurityHeader) handle.getValue();
        WSSecUsernameToken usernameToken = new WSSecUsernameToken(wsSecurityHeader.getWsSecHeader());
        setUTChildElements(usernameToken, passwordType.getValue(), username.getValue(), password.getValue());
        Document xmlDocument;
        switch (passwordType.getValue()) {
            case DERIVED_KEY_TEXT, DERIVED_KEY_DIGEST -> {
                usernameToken.addDerivedKey(Constants.ITERATION);
                xmlDocument = usernameToken.build(UsernameTokenUtil.generateSalt(true));
            }
            default -> xmlDocument = usernameToken.build();
        }
        try {
            return convertDocumentToString(xmlDocument);
        } catch (Exception e) {
            return createError(e.getMessage());
        }
    }

}
