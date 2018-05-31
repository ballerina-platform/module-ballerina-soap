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
// under the License.package soap;

import ballerina/io;
import ballerina/http;
import ballerina/time;

////@Description { value:"Provides the namespace for the given soap version." }
////@Param { value:"soapVersion: The soap version of the request" }
////@Return { value:"string: The namespace for the given soap version" }
function getNamespace(SoapVersion soapVersion) returns string {
    if (soapVersion == SOAP11) {
        return SOAP11_NAMESPACE;
    }
    return SOAP12_NAMESPACE;
}

//@Description { value:"Provides the encoding style for the given soap version" }
//@Param { value:"soapVersion: The soap version of the request" }
//@Return { value:"string: the encoding style for the given soap version" }
function getEncodingStyle(SoapVersion soapVersion) returns string {
    if (soapVersion == SOAP11) {
        return SOAP11_ENCODING_STYLE;
    }
    return SOAP12_ENCODING_STYLE;
}

//@Description { value:"Provides an empty soap envelope for the given soap version" }
//@Param { value:"soapVersion: The soap version of the request" }
//@Return { value:"xml: xml with the empty soap envelope" }
function createSoapEnvelop(SoapVersion soapVersion) returns xml {
    string namespace = getNamespace(soapVersion);
    string encodingStyle = getEncodingStyle(soapVersion);
    return xml `<soap:Envelope
                     xmlns:soap="{{namespace}}"
                     soap:encodingStyle="{{encodingStyle}}">
                     </soap:Envelope>`;
}

//@Description { value:"Provides the WS addressing header" }
//@Param { value:"request: Request to be sent" }
//@Return { value:"xml: xml with the WS addressing header" }
function getWSAddressingHeaders(Request request) returns xml {
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
            error err = { message: "If ReplyTo element is present, wsa:MessageID MUST be present" };
            throw err;
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

//@Description { value:"Provides the WS Secure Username Token Headers" }
//@Param { value:"request: Request to be sent" }
//@Return { value:"xml: xml with the WS Secure Username Token Headers" }
function getWSSecreUsernameTokenHeaders(Request request) returns xml {
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

//@Description { value:"Provides the soap headers in the request as xml" }
//@Param { value:"request: Request to be sent" }
//@Param { value:"soapVersion: The soap version of the request" }
//@Return { value:"xml: xml with the empty soap header" }
function createSoapHeader(Request request, SoapVersion soapVersion) returns xml {
    string namespace = getNamespace(soapVersion);
    xml headersRoot = xml `<soap:Header xmlns:soap="{{namespace}}"></soap:Header>`;
    xml headerElement;
    xml[] headers = request.headers;
    if (lengthof headers != 0) {
        xml[] headers = request.headers;
        int i = 1;
        xml headersXML = headers[0];
        while (i < lengthof headers) {
            headersXML = headersXML + headers[i];
            i = i + 1;
        }
        headerElement = headersXML;
    }

    if (request.to != EMPTY_STRING) {
        headerElement += getWSAddressingHeaders(request);
    }

    if (request.username != EMPTY_STRING) {
        headerElement += getWSSecreUsernameTokenHeaders(request);
    }

    if (!headerElement.isEmpty()) {
        headersRoot.setChildren(headerElement);
    }

    return headersRoot;
}

//@Description { value:"Provides the soap body in the request as xml" }
//@Param { value:"request: Request to be sent" }
//@Param { value:"soapVersion: The soap version of the request" }
//@Return { value:"xml: xml with the empty soap body" }
function createSoapBody(xml payload, SoapVersion soapVersion) returns xml {
    string namespace = getNamespace(soapVersion);
    xml bodyRoot = xml `<soap:Body xmlns:soap="{{namespace}}"></soap:Body>`;
    bodyRoot.setChildren(payload);
    return bodyRoot;
}

//@Description { value:"Prepare a SOAP envelope with the xml to be sent." }
//@Param { value:"request: The request to be sent" }
//@Param { value:"soapVersion: The soap version of the request" }
//@Return { value:"http:Request: Returns the soap Request as http:Request with the soap envelope" }
function fillSOAPEnvelope(Request request, SoapVersion soapVersion) returns http:Request {
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
        req.setHeader("Content-Type", "text/xml");
        req.addHeader("SOAPAction", request.soapAction);
    } else {
        req.setHeader("Content-Type", "application/soap+xml");
    }
    return req;
}

//@Description { value:"Creates the soap response from the http Response" }
//@Param { value:"resp: The http response" }
//@Param { value:"soapVersion: The soap version of the request" }
//@Return { value:"Response: The soap response created from the http response" }
function createSOAPResponse(http:Response resp, SoapVersion soapVersion) returns (Response|error) {
    Response response = {};
    response.soapVersion = soapVersion;
    xml payload = check resp.getXmlPayload();
    xml soapHeaders = payload["Header"].*;
    if (!soapHeaders.isEmpty()) {
        int i = 0;
        xml[] headersXML = [];
        while (i < lengthof soapHeaders) {
            headersXML[i] = soapHeaders[i];
            i++;
        }
        response.headers = headersXML;
    }
    payload = check resp.getXmlPayload();
    response.payload = payload["Body"].*;
    return response;
}
