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

import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BHandle;
import io.ballerina.runtime.api.values.BMap;
import io.ballerina.runtime.api.values.BObject;
import io.ballerina.runtime.api.values.BString;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.UsernameTokenUtil;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.WSSecDKEncrypt;
import org.apache.wss4j.dom.message.WSSecEncrypt;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.message.WSSecTimestamp;
import org.apache.wss4j.dom.message.WSSecUsernameToken;
import org.apache.wss4j.dom.processor.EncryptedKeyProcessor;
import org.apache.wss4j.dom.processor.Processor;
import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.JCEMapper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Properties;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;

import static org.apache.wss4j.common.WSS4JConstants.AES_128_GCM;
import static org.apache.wss4j.common.WSS4JConstants.ELEM_HEADER;
import static org.apache.wss4j.common.WSS4JConstants.HMAC_SHA1;
import static org.apache.wss4j.dom.WSConstants.CUSTOM_KEY_IDENTIFIER;
import static org.apache.wss4j.dom.WSConstants.X509_KEY_IDENTIFIER;
import static org.wssec.Constants.AES;
import static org.wssec.Constants.CANONICALIZATION_ALGORITHM;
import static org.wssec.Constants.CRYPTO_PROVIDER_FIELD;
import static org.wssec.Constants.CRYPTO_PROVIDER_VALUE;
import static org.wssec.Constants.DECRYPT_KEYSTORE;
import static org.wssec.Constants.DERIVED_KEY_DIGEST;
import static org.wssec.Constants.DERIVED_KEY_TEXT;
import static org.wssec.Constants.DIGEST_ALGORITHM;
import static org.wssec.Constants.ENCRYPTION_ALGORITHM;
import static org.wssec.Constants.ITERATION;
import static org.wssec.Constants.KEYSTORE;
import static org.wssec.Constants.KEYSTORE_PASSWORD_FIELD;
import static org.wssec.Constants.KEYSTORE_PATH_FIELD;
import static org.wssec.Constants.NATIVE_DOCUMENT;
import static org.wssec.Constants.NATIVE_ENCRYPTION;
import static org.wssec.Constants.NATIVE_SEC_HEADER;
import static org.wssec.Constants.NATIVE_SIGNATURE;
import static org.wssec.Constants.PASSWORD;
import static org.wssec.Constants.PATH;
import static org.wssec.Constants.PRIVATE_KEY_ALIAS;
import static org.wssec.Constants.PRIVATE_KEY_PASSWORD;
import static org.wssec.Constants.PUBLIC_KEY_ALIAS;
import static org.wssec.Constants.SIGNATURE_ALGORITHM;
import static org.wssec.Constants.SIGNATURE_KEYSTORE;
import static org.wssec.Constants.X509;
import static org.wssec.Utils.createError;
import static org.wssec.WsSecurityUtils.convertDocumentToString;
import static org.wssec.WsSecurityUtils.setUTChildElements;

public final class WsSecurity {

    private WsSecurity() {}

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
            byte[] key = UsernameTokenUtil.generateDerivedKey(PASSWORD,
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
            byte[] key = UsernameTokenUtil.generateDerivedKey(PASSWORD,
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

    public static BMap getReadOnlyClientConfig(BMap securityConfig) {
        securityConfig.freezeDirect();
        return securityConfig;
    }

    public static Object applySignatureOnly(BObject documentBuilder, Boolean soap12, BMap<BString,
                                            Object> signatureConfig) {
        Document document = (Document) documentBuilder.getNativeData(NATIVE_DOCUMENT);
        BMap<BString, BString> keyStore = (BMap<BString, BString>) signatureConfig
                .getMapValue(StringUtils.fromString(KEYSTORE));
        String path = keyStore.get(StringUtils.fromString(PATH)).toString();
        String password = keyStore.get(StringUtils.fromString(PASSWORD)).toString();
        String digestAlgorithm = signatureConfig.get(StringUtils.fromString(DIGEST_ALGORITHM)).toString();
        String canonicalizationAlgorithm = signatureConfig
                .get(StringUtils.fromString(CANONICALIZATION_ALGORITHM)).toString();
        String signatureAlgorithm = signatureConfig.get(StringUtils.fromString(SIGNATURE_ALGORITHM)).toString();
        String privateKeyPassword = signatureConfig.get(StringUtils.fromString(PRIVATE_KEY_PASSWORD)).toString();
        String privateKeyAlias = signatureConfig.get(StringUtils.fromString(PRIVATE_KEY_ALIAS)).toString();
        try {
            validateSoapHeader(soap12, document);
            WSSecHeader secHeader = new WSSecHeader(document);
            secHeader.insertSecurityHeader();
            Crypto crypto = getCryptoInstance(path, password);
            generateSignature(privateKeyPassword, privateKeyAlias, digestAlgorithm,
                              canonicalizationAlgorithm, signatureAlgorithm, crypto, secHeader);
            return convertDocumentToString(document);
        } catch (Exception e) {
            return createError(e.getMessage());
        }
    }

    private static Crypto getCryptoInstance(String path, String password) throws WSSecurityException {
        Properties properties = new Properties();
        properties.put(CRYPTO_PROVIDER_FIELD, CRYPTO_PROVIDER_VALUE);
        properties.put(KEYSTORE_PATH_FIELD, path);
        properties.put(KEYSTORE_PASSWORD_FIELD, password);
        return CryptoFactory.getInstance(properties);
    }

    private static void validateSoapHeader(Boolean soap12, Document document) {
        Init.init();
        String namespace = soap12 ? WSConstants.URI_SOAP12_ENV : WSConstants.URI_SOAP11_ENV;
        Element header = (Element) document.getElementsByTagNameNS(namespace, ELEM_HEADER).item(0);
        if (header == null) {
            throw new IllegalStateException("SOAP Envelope must have a Header");
        }
    }

    public static Object verifySignature(BObject documentBuilder,
                                         BMap<BString, Object> config) {
        Document document = (Document) documentBuilder.getNativeData(NATIVE_DOCUMENT);
        BMap<BString, BString> keyStore = (BMap<BString, BString>) config
                .getMapValue(StringUtils.fromString(SIGNATURE_KEYSTORE));
        String path = keyStore.get(StringUtils.fromString(PATH)).toString();
        String password = keyStore.get(StringUtils.fromString(PASSWORD)).toString();
        try {
            WSSecurityEngine secEngine = new WSSecurityEngine();
            RequestData requestData = new RequestData();
            Crypto crypto = getCryptoInstance(path, password);
            requestData.setSigVerCrypto(crypto);
            CallbackHandler passwordCallbackHandler = callbacks -> {
                for (Callback callback: callbacks) {
                    ((WSPasswordCallback) callback).setPassword(PASSWORD);
                }
            };
            requestData.setCallbackHandler(passwordCallbackHandler);
            WSSConfig wssConfig = WSSConfig.getNewInstance();
            secEngine.setWssConfig(wssConfig);
            Processor processor = (elem, data) -> {
                if (WSConstants.ENC_KEY_LN.equals(elem.getLocalName())) {
                    return new ArrayList<>();
                }
                return new EncryptedKeyProcessor().handleToken(elem, data);
            };
            wssConfig.setProcessor(new QName(WSConstants.ENC_NS, WSConstants.ENC_KEY_LN), processor);
            secEngine.processSecurityHeader(document, requestData);
            return true;
        } catch (WSSecurityException e) {
            return createError(e.getMessage());
        }
    }

    public static Object decryptEnvelope(BObject documentBuilder, BMap<BString, Object> config) {
        Document encryptedDocument = (Document) documentBuilder.getNativeData(NATIVE_DOCUMENT);
        BMap<BString, BString> keyStore = (BMap<BString, BString>) config
                .getMapValue(StringUtils.fromString(DECRYPT_KEYSTORE));
        String path = keyStore.get(StringUtils.fromString(PATH)).toString();
        String password = keyStore.get(StringUtils.fromString(PASSWORD)).toString();
        WSSecHeader secHeader = new WSSecHeader(encryptedDocument);
        WSSecurityEngine secEngine = new WSSecurityEngine();
        RequestData requestData = new RequestData();
        try {
            Crypto crypto = getCryptoInstance(path, password);
            requestData.setSigVerCrypto(crypto);
            requestData.setDecCrypto(crypto);
            requestData.setSecHeader(secHeader);
            CallbackHandler passwordCallbackHandler = callbacks -> {
                for (Callback callback: callbacks) {
                    ((WSPasswordCallback) callback).setPassword(password);
                }
            };
            requestData.setCallbackHandler(passwordCallbackHandler);
            secEngine.processSecurityHeader(encryptedDocument, requestData);
            documentBuilder.addNativeData(NATIVE_DOCUMENT, encryptedDocument);
            return documentBuilder;
        } catch (Exception e) {
            return createError(e.getMessage());
        }
    }

    public static Object applyEncryptionOnly(BObject documentBuilder, Boolean soap12,
                                             BMap<BString, Object> config) {
        try {
            Document document = (Document) documentBuilder.getNativeData(NATIVE_DOCUMENT);
            BMap<BString, BString> keyStore = (BMap<BString, BString>) config
                    .getMapValue(StringUtils.fromString(KEYSTORE));
            String path = keyStore.get(StringUtils.fromString(PATH)).toString();
            String password = keyStore.get(StringUtils.fromString(PASSWORD)).toString();
            String publicKeyAlias = config.get(StringUtils.fromString(PUBLIC_KEY_ALIAS)).toString();
            String encryptionAlgorithm = config.get(StringUtils.fromString(ENCRYPTION_ALGORITHM)).toString();
            validateSoapHeader(soap12, document);
            Crypto crypto = getCryptoInstance(path, password);
            WSSecHeader secHeader = new WSSecHeader(document);
            secHeader.insertSecurityHeader();
            generateEncryption(publicKeyAlias, crypto, secHeader, encryptionAlgorithm);
            return convertDocumentToString(document);
        } catch (Exception e) {
            return createError(e.getMessage());
        }
    }

    public static Object applySignatureAndEncryption(BObject documentBuilder, Boolean soap12,
                                                     BMap<BString, Object> signatureConfig,
                                                     BMap<BString, Object> encryptionConfig) {
        try {
            Document document = (Document) documentBuilder.getNativeData(NATIVE_DOCUMENT);
            BMap<BString, BString> keyStore = (BMap<BString, BString>) signatureConfig
                    .getMapValue(StringUtils.fromString(KEYSTORE));
            String path = keyStore.get(StringUtils.fromString(PATH)).toString();
            String password = keyStore.get(StringUtils.fromString(PASSWORD)).toString();
            String publicKeyAlias = encryptionConfig.get(StringUtils.fromString(PUBLIC_KEY_ALIAS)).toString();
            String privateKeyPassword = signatureConfig.get(StringUtils.fromString(PRIVATE_KEY_PASSWORD)).toString();
            String privateKeyAlias = signatureConfig.get(StringUtils.fromString(PRIVATE_KEY_ALIAS)).toString();
            String digestAlgorithm = signatureConfig.get(StringUtils.fromString(DIGEST_ALGORITHM)).toString();
            String canonicalizationAlgorithm = signatureConfig
                    .get(StringUtils.fromString(CANONICALIZATION_ALGORITHM)).toString();
            String signatureAlgorithm = signatureConfig.get(StringUtils.fromString(SIGNATURE_ALGORITHM)).toString();
            String encryptionAlgorithm = encryptionConfig.get(StringUtils.fromString(ENCRYPTION_ALGORITHM)).toString();
            validateSoapHeader(soap12, document);
            Crypto crypto = getCryptoInstance(path, password);
            WSSecHeader secHeader = new WSSecHeader(document);
            secHeader.insertSecurityHeader();
            generateSignature(privateKeyPassword, privateKeyAlias, digestAlgorithm,
                              canonicalizationAlgorithm, signatureAlgorithm, crypto, secHeader);
            generateEncryption(publicKeyAlias, crypto, secHeader, encryptionAlgorithm);
            return convertDocumentToString(document);
        } catch (Exception e) {
            return createError(e.getMessage());
        }
    }

    private static void generateEncryption(String publicKeyAlias, Crypto crypto,
                                           WSSecHeader secHeader, String encryptionAlgorithm) throws Exception {
        WSSecEncrypt encrypt = new WSSecEncrypt(secHeader);
        encrypt.setUserInfo(publicKeyAlias);
        encrypt.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
        encrypt.setSymmetricEncAlgorithm(encryptionAlgorithm);
        encrypt.setKeyEncAlgo(WSConstants.KEYTRANSPORT_RSAOAEP);
        SecretKey symmetricKey = generateSymmetricKey();
        encrypt.build(crypto, symmetricKey);
    }

    private static void generateSignature(String privateKeyPassword, String privateKeyAlias, String digestAlgorithm,
                                          String canonicalizationAlgorithm, String signatureAlgorithm, Crypto crypto,
                                          WSSecHeader secHeader) throws WSSecurityException {
        WSSecSignature signature = new WSSecSignature(secHeader);
        signature.setUserInfo(privateKeyAlias, privateKeyPassword);
        signature.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
        signature.setSigCanonicalization(canonicalizationAlgorithm);
        signature.setDigestAlgo(digestAlgorithm);
        signature.setSignatureAlgorithm(signatureAlgorithm);
        signature.build(crypto);
    }

    public static SecretKey generateSymmetricKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES);
        keyGen.init(128);
        return keyGen.generateKey();
    }
}
