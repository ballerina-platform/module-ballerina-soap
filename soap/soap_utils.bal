// Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import ballerina/http;
import ballerina/io;
import ballerina/mime;
import ballerina/time;

# Provides the namespace for the given SOAP version.
#
# + soapVersion - The SOAP version of the request
# + return - The namespace for the given SOAP version
function getNamespace(SoapVersion soapVersion) returns string {
    if (soapVersion == SOAP11) {
        return SOAP11_NAMESPACE;
    }
    return SOAP12_NAMESPACE;
}

# Provides the encoding style for the given SOAP version.
#
# + soapVersion - The SOAP version of the request
# + return - The encoding style for the given SOAP version
function getEncodingStyle(SoapVersion soapVersion) returns string {
    if (soapVersion == SOAP11) {
        return SOAP11_ENCODING_STYLE;
    }
    return SOAP12_ENCODING_STYLE;
}

# Provides an empty SOAP envelope for the given SOAP version.
#
# + soapVersion - The SOAP version of the request
# + return - XML with the empty SOAP envelope
function createSoapEnvelop(SoapVersion soapVersion) returns xml {
    string namespace = getNamespace(soapVersion);
    string encodingStyle = getEncodingStyle(soapVersion);
    return xml `<soap:Envelope
                     xmlns:soap="{{namespace}}"
                     soap:encodingStyle="{{encodingStyle}}">
                     </soap:Envelope>`;
}

# Provides the WS addressing header.
#
# + request - The request to be sent
# + return - XML with the WS addressing header
function getWSAddressingHeaders(SoapRequest request) returns xml {
    xmlns "https://www.w3.org/2005/08/addressing" as wsa;

    xml toElement = xml `<wsa:To>{{request.to}}</wsa:To>`;
    xml actionElement = xml `<wsa:Action>{{request.wsaAction}}</wsa:Action>`;
    xml headerElement = toElement + actionElement;

    if (request.relatesTo != EMPTY_STRING) {
        xml relatesToElement = xml `<wsa:RelatesTo>{{request.relatesTo}}</wsa:RelatesTo>`;
        if (request.relationshipType != EMPTY_STRING) {
            relatesToElement@["RelationshipType"] = request.relationshipType;
        }
        headerElement += relatesToElement;
    }

    if (request.^"from" != EMPTY_STRING) {
        string requestFrom = request.^"from";
        xml fromElement = xml `<wsa:From>{{requestFrom}}</wsa:From>`;
        headerElement += fromElement;
    }

    if (request.replyTo != EMPTY_STRING) {
        if (request.messageId != EMPTY_STRING) {
            xml messageIDElement = xml `<wsa:MessageID>{{request.messageId}}</wsa:MessageID>`;
            headerElement += messageIDElement;
        } else {
            error err = error(SOAP_ERROR_CODE, { message: "If ReplyTo element is present, wsa:MessageID MUST be present"
            });
            panic err;
        }
        xml replyToElement = xml `<wsa:ReplyTo><wsa:Address>{{request.replyTo}}</wsa:Address></wsa:ReplyTo>`;
        headerElement += replyToElement;
    }

    if (request.faultTo != EMPTY_STRING) {
        xml faultToElement = xml `<wsa:FaultTo>{{request.faultTo}}</wsa:FaultTo>`;
        headerElement += faultToElement;
    }

    return headerElement;
}

# Provides the WS secure username token headers.
#
# + request - The request to be sent
# + return - XML with the WS secure username token headers
function getWSSecreUsernameTokenHeaders(SoapRequest request) returns xml {
    xmlns "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" as wsse;
    xmlns "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" as wsu;

    xml securityRoot = xml `<wsse:Security></wsse:Security>`;
    xml usernameTokenRoot = xml `<wsse:UsernameToken> </wsse:UsernameToken>`;
    xml usernameElement = xml `<wsse:Username>{{request.username}}</wsse:Username>`;
    xml passwordElement = xml `<wsse:Password>{{request.password}}</wsse:Password>`;

    if (request.passwordType != EMPTY_STRING) {
        passwordElement@["Type"] = request.passwordType;
    }

    xml headerElement = usernameElement + passwordElement;
    usernameTokenRoot.setChildren(headerElement);
    time:Time time = time:currentTime();
    xml timestampElement = xml `<wsu:Timestamp><wsu:Created>{{time.toString()}}</wsu:Created></wsu:Timestamp>`;
    usernameTokenRoot = usernameTokenRoot + timestampElement;
    securityRoot.setChildren(usernameTokenRoot);
    return securityRoot;
}

# Provides the SOAP headers in the request as XML.
#
# + request - The request to be sent
# + soapVersion - The SOAP version of the request
# + return - XML with the empty SOAP header
function createSoapHeader(SoapRequest request, SoapVersion soapVersion) returns xml {
    string namespace = getNamespace(soapVersion);
    xml headersRoot = xml `<soap:Header xmlns:soap="{{namespace}}"></soap:Header>`;
    xml? headerElement = ();
    xml[] headers = request.headers;
    if (headers.length() != 0) {
        int i = 1;
        xml headersXML = headers[0];
        while (i < headers.length()) {
            headersXML = headersXML + headers[i];
            i = i + 1;
        }
        headerElement = headersXML;
    }

    if (headerElement is xml) {
        if (request.to != EMPTY_STRING) {
            headerElement += getWSAddressingHeaders(request);
        }

        if (request.username != EMPTY_STRING) {
            headerElement += getWSSecreUsernameTokenHeaders(request);
        }

        if (!headerElement.isEmpty()) {
            headersRoot.setChildren(headerElement);
        }
    }
    return headersRoot;
}

# Provides the SOAP body in the request as XML.
#
# + payload - The payload to be sent
# + soapVersion - The SOAP version of the request
# + return - XML with the empty SOAP body
function createSoapBody(xml payload, SoapVersion soapVersion) returns xml {
    string namespace = getNamespace(soapVersion);
    xml bodyRoot = xml `<soap:Body xmlns:soap="{{namespace}}"></soap:Body>`;
    bodyRoot.setChildren(payload);
    return bodyRoot;
}

# Prepare a SOAP envelope with the XML to be sent.
#
# + request - The request to be sent
# + soapVersion - The SOAP version of the request
# + return - The SOAP Request as `http:Request` with the SOAP envelope
function fillSOAPEnvelope(SoapRequest request, SoapVersion soapVersion) returns http:Request {
    xml soapPayload = createSoapHeader(request, soapVersion);
    xml requestPayload = request.payload;
    if (!requestPayload.isEmpty()) {
        xml body = createSoapBody(requestPayload, soapVersion);
        soapPayload += body;
    }

    xml soapEnv = createSoapEnvelop(soapVersion);
    soapEnv.setChildren(soapPayload);
    http:Request req = new;
    req.setXmlPayload(soapEnv);
    if (soapVersion == SOAP11) {
        req.setHeader(mime:CONTENT_TYPE, mime:TEXT_XML);
        req.addHeader("SOAPAction", request.soapAction);
    } else {
        req.setHeader(mime:CONTENT_TYPE, mime:APPLICATION_SOAP_XML);
    }
    return req;
}

# Creates the SOAP response from the HTTP Response.
#
# + response - The request to be sent
# + soapVersion - The SOAP version of the request
# + return - The SOAP response created from the `http:Response` or `error` object when reading the payload
function createSOAPResponse(http:Response response, SoapVersion soapVersion) returns SoapResponse|error {
    var payload = response.getXmlPayload();
    if (payload is xml) {
        xml soapHeaders = payload["Header"].*;
        xml[] soapResponseHeaders = [];

        if (!soapHeaders.isEmpty()) {
            int i = 0;
            xml[] headersXML = [];
            while (i < soapHeaders.length()) {
                headersXML[i] = soapHeaders[i];
                i += 1;
            }
            soapResponseHeaders = headersXML;
        }
        xml soapResponsePayload = payload["Body"].*;

        SoapResponse soapResponse = {
            headers: soapResponseHeaders,
            payload: soapResponsePayload,
            soapVersion: soapVersion
        };
        return soapResponse;
    } else {
        return payload;
    }
}
