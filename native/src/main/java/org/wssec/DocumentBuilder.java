// Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com) All Rights Reserved.
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

import io.ballerina.runtime.api.creators.ValueCreator;
import io.ballerina.runtime.api.values.BArray;
import io.ballerina.runtime.api.values.BObject;
import io.ballerina.runtime.api.values.BXml;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import java.io.StringReader;

import javax.xml.parsers.DocumentBuilderFactory;

import static org.wssec.Constants.NATIVE_DOCUMENT;

public class DocumentBuilder {

    private final Document document;

    public DocumentBuilder(BObject documentBuilder, BXml xmlPayload) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        this.document = factory.newDocumentBuilder().parse(new InputSource(new StringReader(xmlPayload.toString())));
        documentBuilder.addNativeData(NATIVE_DOCUMENT, this.document);
    }

    protected DocumentBuilder(Document document) {
        this.document = document;
    }

    public static BArray getSignatureData(BObject document) {
        Document nativeDocument = (Document) document.getNativeData().get(NATIVE_DOCUMENT);
        return ValueCreator.createArrayValue(WsSecurityUtils.getSignatureValue(nativeDocument));
    }

    public static BArray getEncryptedData(BObject document) {
        Document nativeDocument = (Document) document.getNativeData().get(NATIVE_DOCUMENT);
        return ValueCreator.createArrayValue(WsSecurityUtils.getEncryptedData(nativeDocument));
    }

    protected Document getNativeDocument() {
        return this.document;
    }
}
