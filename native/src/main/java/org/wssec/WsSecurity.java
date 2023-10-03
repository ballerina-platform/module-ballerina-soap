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

    public static Object applyTimestampPolicy(BObject wsSecHeader, int timeToLive) {
        BHandle handle = (BHandle) wsSecHeader.get(StringUtils.fromString(NATIVE_SEC_HEADER));
        WsSecurityHeader wsSecurityHeader = (WsSecurityHeader) handle.getValue();
        WSSecTimestamp timestamp = new WSSecTimestamp(wsSecurityHeader.getWsSecHeader());
        timestamp.setTimeToLive(timeToLive);
        try {
            return convertDocumentToString(timestamp.build());
        } catch (Exception e) {
            return createError(e.getMessage());
        }
    }

    public static Object applySignatureOnlyPolicy(BObject wsSecHeader, BObject balSignature, Object x509FilePath) {
        BHandle handle = (BHandle) wsSecHeader.get(StringUtils.fromString(NATIVE_SEC_HEADER));
        WsSecurityHeader wsSecurityHeader = (WsSecurityHeader) handle.getValue();
        handle = (BHandle) balSignature.get(StringUtils.fromString(NATIVE_SIGNATURE));
        Signature signature = (Signature) handle.getValue();
        try {
            Document xmlDocument = createSignatureTags(wsSecurityHeader, x509FilePath);
            WsSecurityUtils.setSignatureValue(xmlDocument, signature.getSignatureValue(),
                    signature.getSignatureAlgorithm());
            return convertDocumentToString(xmlDocument);
        } catch (Exception e) {
            return createError(e.getMessage());
        }
    }

    public static Object applyEncryptionOnlyPolicy(BObject wsSecHeader, BObject balEncryption) {
        BHandle handle = (BHandle) wsSecHeader.get(StringUtils.fromString(NATIVE_SEC_HEADER));
        WsSecurityHeader wsSecurityHeader = (WsSecurityHeader) handle.getValue();
        handle = (BHandle) balEncryption.get(StringUtils.fromString(NATIVE_ENCRYPTION));
        Encryption encryption = (Encryption) handle.getValue();
        try {
            byte[] key = UsernameTokenUtil.generateDerivedKey("password",
                    UsernameTokenUtil.generateSalt(true), ITERATION);
            Document xmlDocument = encryptEnvelope(wsSecurityHeader, key);
            WsSecurityUtils.setEncryptedData(xmlDocument, encryption.getEncryptedData(),
                                             encryption.getEncryptionAlgorithm());
            return convertDocumentToString(xmlDocument);
        } catch (Exception e) {
            return createError(e.getMessage());
        }
    }

    public static Document encryptEnvelope(WsSecurityHeader wsSecurityHeader, byte[] rawKey)
            throws WSSecurityException {
        Init.init();
        JCEMapper.registerDefaultAlgorithms();
        WSSecDKEncrypt encryptionBuilder = new WSSecDKEncrypt(wsSecurityHeader.getWsSecHeader());
        encryptionBuilder.setSymmetricEncAlgorithm(AES_128_GCM);
        return encryptionBuilder.build(rawKey);
    }

    public static Document createSignatureTags(WsSecurityHeader wsSecurityHeader,
                                               Object x509FilePath) throws Exception {
        RequestData reqData = new RequestData();
        reqData.setSecHeader(wsSecurityHeader.getWsSecHeader());
        reqData.setWssConfig(WSSConfig.getNewInstance());
        reqData.setWsDocInfo(new WSDocInfo(wsSecurityHeader.getDocument()));
        WSSecSignature wsSecSignature = prepareSignature(reqData, x509FilePath);
        WsSecurityUtils.buildSignature(reqData, wsSecSignature);
        return wsSecSignature.build(null);
    }

    public static WSSecSignature prepareSignature(RequestData reqData, Object x509FilePath) {
        WSSecSignature sign = new WSSecSignature(reqData.getSecHeader());
        try {
            byte[] key = UsernameTokenUtil.generateDerivedKey("password",
                    UsernameTokenUtil.generateSalt(true), ITERATION);
            sign.setSecretKey(key);
            sign.setWsDocInfo(reqData.getWsDocInfo());
            sign.setSignatureAlgorithm(HMAC_SHA1);
            sign.setKeyIdentifierType(CUSTOM_KEY_IDENTIFIER);
            if (x509FilePath != null) {
                    FileInputStream fis = new FileInputStream(x509FilePath.toString());
                    CertificateFactory certificateFactory = CertificateFactory.getInstance(X509);
                    X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(fis);
                    sign.setKeyIdentifierType(X509_KEY_IDENTIFIER);
                    sign.setX509Certificate(x509Certificate);
                    fis.close();
            }
        sign.prepare(null);
        } catch (CertificateException | WSSecurityException | IOException e) {
            throw createError(e.getMessage());
        }
        return sign;
    }
}
