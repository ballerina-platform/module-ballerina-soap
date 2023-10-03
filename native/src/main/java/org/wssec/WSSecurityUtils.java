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
import org.w3c.dom.Text;

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

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

    public static void setUTChildElements(WSSecUsernameToken usernameToken, String passwordType,
                                          String username, String password) {
        if (Objects.equals(passwordType, DIGEST)
                || Objects.equals(passwordType, DERIVED_KEY_DIGEST)) {
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
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(document), new StreamResult(writer));
        return StringUtils.fromString(writer.toString());
    }
}
