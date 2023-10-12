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

import io.ballerina.runtime.api.creators.ErrorCreator;
import io.ballerina.runtime.api.utils.StringUtils;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.message.WSSecUsernameToken;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.xml.crypto.dsig.Reference;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import static org.apache.wss4j.common.WSS4JConstants.ENC_NS;
import static org.apache.wss4j.common.WSS4JConstants.KEYTRANSPORT_RSA15;
import static org.apache.wss4j.common.WSS4JConstants.PASSWORD_DIGEST;
import static org.apache.wss4j.common.WSS4JConstants.PASSWORD_TEXT;
import static org.apache.wss4j.common.WSS4JConstants.SIG_NS;
import static org.wssec.Constants.ALGORITHM;
import static org.wssec.Constants.CIPHER_DATA_TAG;
import static org.wssec.Constants.CIPHER_VALUE_TAG;
import static org.wssec.Constants.DERIVED_KEY_DIGEST;
import static org.wssec.Constants.DIGEST;
import static org.wssec.Constants.EMPTY_XML_DOCUMENT_ERROR;
import static org.wssec.Constants.ENCRYPTED_KEY_TAG;
import static org.wssec.Constants.ENCRYPTION_METHOD_TAG;
import static org.wssec.Constants.KEY_INFO_TAG;
import static org.wssec.Constants.NAMESPACE_URI_ENC;
import static org.wssec.Constants.SIGNATURE_METHOD_TAG;
import static org.wssec.Constants.SIGNATURE_VALUE_TAG;
import static org.wssec.Constants.XML_DS_NS;
import static org.wssec.Constants.XML_ENC_NS;

public class WsSecurityUtils {

    public static void buildSignature(RequestData reqData, WSSecSignature sign) throws Exception {
        List<WSEncryptionPart> parts;
        parts = new ArrayList<>(1);
        Document doc = reqData.getSecHeader().getSecurityHeaderElement().getOwnerDocument();
        parts.add(WSSecurityUtil.getDefaultEncryptionPart(doc));
        List<Reference> referenceList = sign.addReferencesToSign(parts);
        sign.computeSignature(referenceList);
        reqData.getSignatureValues().add(sign.getSignatureValue());
    }

    public static void setSignatureValue(Document doc, byte[] signature, String algorithm) {
        doc.getElementsByTagName(SIGNATURE_METHOD_TAG)
                .item(0).getAttributes().item(0).setNodeValue(algorithm);
        NodeList digestValueList = doc.getElementsByTagName(SIGNATURE_VALUE_TAG);
        digestValueList.item(0).getFirstChild().setNodeValue(Base64.getEncoder().encodeToString(signature));
    }

    public static byte[] getSignatureValue(Document doc) {
        String signature = doc.getElementsByTagName(SIGNATURE_VALUE_TAG).item(0).getFirstChild().getNodeValue();
        return Base64.getDecoder().decode(signature);
    }

    public static void setEncryptedData(Document doc, byte[] encryptedData, String algorithm) {
        Element cipherDataElement = (Element) doc
                .getElementsByTagNameNS(NAMESPACE_URI_ENC, CIPHER_VALUE_TAG).item(0);
        cipherDataElement.getFirstChild().setNodeValue(Base64.getEncoder().encodeToString(encryptedData));
        doc.getElementsByTagName(ENCRYPTION_METHOD_TAG).item(0).getAttributes().item(0)
                .setNodeValue(algorithm);
    }

    public static byte[] getEncryptedData(Document document) {
        String encryptedText = document
                .getElementsByTagNameNS(NAMESPACE_URI_ENC, CIPHER_VALUE_TAG).item(0)
                .getFirstChild().getNodeValue();
        return Base64.getDecoder().decode(encryptedText);
    }

    public static Object getEncryptedKeyElement(byte[] encryptKey) throws Exception {
        Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
        Element encryptedKey = document.createElement(ENCRYPTED_KEY_TAG);
        encryptedKey.setAttribute(XML_ENC_NS, ENC_NS);
        Element encryptionMethod = document.createElement(ENCRYPTION_METHOD_TAG);
        encryptionMethod.setAttribute(ALGORITHM, KEYTRANSPORT_RSA15);
        encryptedKey.appendChild(encryptionMethod);
        Element keyInfo = document.createElement(KEY_INFO_TAG);
        keyInfo.setAttribute(XML_DS_NS, SIG_NS);
        encryptedKey.appendChild(keyInfo);
        Element cipherData = document.createElement(CIPHER_DATA_TAG);
        cipherData.appendChild(document.createTextNode(Base64.getEncoder().encodeToString(encryptKey)));
        encryptedKey.appendChild(cipherData);
        document.appendChild(encryptedKey);
        return convertDocumentToString(document);
    }

    public static void setUTChildElements(WSSecUsernameToken usernameToken, String passwordType,
                                          String username, String password) {
        if (DIGEST.equals(passwordType) || DERIVED_KEY_DIGEST.equals(passwordType)) {
            usernameToken.setPasswordType(PASSWORD_DIGEST);
            usernameToken.setUserInfo(username, password);
            usernameToken.addCreated();
            usernameToken.addNonce();
        } else {
            usernameToken.setPasswordType(PASSWORD_TEXT);
            usernameToken.setUserInfo(username, password);
        }
    }

    public static Object convertDocumentToString(Document document) throws Exception {
        if (document == null) {
            return ErrorCreator.createError(StringUtils.fromString(EMPTY_XML_DOCUMENT_ERROR));
        }
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(document), new StreamResult(writer));
        return StringUtils.fromString(writer.toString());
    }
}
