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
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.w3c.dom.Document;

import static org.wssec.Constants.NATIVE_DOCUMENT;
import static org.wssec.Constants.NATIVE_SEC_HEADER;
import static org.wssec.Utils.createError;

public class WsSecurityHeader {

    private final WSSecHeader wsSecHeader;
    private final Document document;

    public WsSecurityHeader(BObject documentBuilder) {
        BHandle handle = (BHandle) documentBuilder.get(StringUtils.fromString(NATIVE_DOCUMENT));
        DocumentBuilder docBuilder = (DocumentBuilder) handle.getValue();
        this.wsSecHeader = new WSSecHeader(docBuilder.getNativeDocument());
        this.document = docBuilder.getNativeDocument();
    }

    protected Document getDocument() {
        return document;
    }

    protected WSSecHeader getWsSecHeader() {
        return wsSecHeader;
    }

    public static void insertSecHeader(BObject secHeader) {
        BHandle handle = (BHandle) secHeader.get(StringUtils.fromString(NATIVE_SEC_HEADER));
        WsSecurityHeader wsSecurityHeader = (WsSecurityHeader) handle.getValue();
        try {
            wsSecurityHeader.getWsSecHeader().insertSecurityHeader();
        } catch (WSSecurityException e) {
            throw createError(e.getMessage());
        }
    }
}
