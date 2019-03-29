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

import ballerina/crypto;
import ballerina/encoding;
import ballerina/http;
import ballerina/io;
import ballerina/mime;
import ballerina/system;
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
# + options - Soap options to be sent
# + return - XML with the WS addressing header
function getWSAddressingHeaders(Options options) returns xml {
    xmlns "https://www.w3.org/2005/08/addressing" as wsa;

    // This `requestTo` parameter is already validated as a `xml` before calling this method.
    string requestTo = options.wsAddressing["requestTo"] ?: "";
    var wsaAction = options.wsAddressing["wsaAction"];

    xml headerElement = xml `<wsa:To>{{requestTo}}</wsa:To>`;
    if (wsaAction is string) {
        headerElement += xml `<wsa:Action>{{wsaAction}}</wsa:Action>`;
    }

    var relatesTo = options["relatesTo"];
    if (relatesTo is string) {
        xml relatesToElement = xml `<wsa:RelatesTo>{{relatesTo}}</wsa:RelatesTo>`;
        var relationshipType = options.wsAddressing["relationshipType"];
        if (relationshipType is string) {
            relatesToElement@["RelationshipType"] = relationshipType;
        }
        headerElement += relatesToElement;
    }

    var requestFrom = options.wsAddressing["requestFrom"];
    if (requestFrom is string) {
        xml fromElement = xml `<wsa:From>{{requestFrom}}</wsa:From>`;
        headerElement += fromElement;
    }

    var replyTo = options.wsAddressing["replyTo"];
    if (replyTo is string) {
        var messageId = options["messageId"];
        if (messageId is string) {
            xml messageIDElement = xml `<wsa:MessageID>{{messageId}}</wsa:MessageID>`;
            headerElement += messageIDElement;
        } else {
            error err = error(SOAP_ERROR_CODE,
                { message: "If ReplyTo element is present, wsa:MessageID MUST be present" });
            panic err;
        }
        xml replyToElement = xml `<wsa:ReplyTo><wsa:Address>{{replyTo}}</wsa:Address></wsa:ReplyTo>`;
        headerElement += replyToElement;
    }

    var faultTo = options.wsAddressing["faultTo"];
    if (faultTo is string) {
        xml faultToElement = xml `<wsa:FaultTo>{{faultTo}}</wsa:FaultTo>`;
        headerElement += faultToElement;
    }

    return headerElement;
}

# Provides the WS secure username token headers.
#
# + options - Soap options to be sent
# + return - XML with the WS secure username token headers
function getWSSecreUsernameTokenHeaders(Options options) returns xml {
    xmlns "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" as wsse;
    xmlns "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" as wsu;

    string username = options.usernameToken["username"] ?: "";
    string password = options.usernameToken["password"] ?: "";

    xml securityRoot = xml `<wsse:Security></wsse:Security>`;
    xml usernameTokenRoot = xml `<wsse:UsernameToken> </wsse:UsernameToken>`;
    xml usernameElement = xml `<wsse:Username>{{username}}</wsse:Username>`;
    xml passwordElement;

    time:Time time = time:currentTime();
    xml timestampElement = xml `<wsu:Timestamp><wsu:Created>{{time:toString(time)}}</wsu:Created></wsu:Timestamp>`;

    var passwordType = options.usernameToken["passwordType"];
    if (passwordType is ()) {
        passwordType = "PasswordText";
    }
    string pwdType = <string> passwordType;
    if (pwdType.equalsIgnoreCase("PasswordDigest")) {
        string nonce = system:uuid();
        string encodedNonce = encoding:encodeBase64(nonce.toByteArray("UTF-8"));
        string createdTime = time:toString(time);
        password = createDigestPassword(nonce, password, createdTime);
        xml passwordDigest = xml `<wsse:Password Type="{{PWD_DIGEST}}">{{password}}</wsse:Password>`;
        xml nonceElement = xml `<wsse:Nonce EncodingType="{{BASE64ENCODED}}">{{encodedNonce}}</wsse:Nonce>`;
        xml createdTimeElement = xml `<wsu:Created>{{createdTime}}</wsu:Created>`;
        passwordElement = passwordDigest + nonceElement + createdTimeElement;
    } else {
        passwordElement = xml `<wsse:Password Type="{{PWD_TEXT}}">{{password}}</wsse:Password>`;
    }

    xml headerElement = usernameElement + passwordElement;
    usernameTokenRoot.setChildren(headerElement);
    usernameTokenRoot = usernameTokenRoot + timestampElement;
    securityRoot.setChildren(usernameTokenRoot);
    return securityRoot;
}

# Provides the SOAP headers in the request as XML.
#
# + options - Soap options to be sent
# + soapVersion - The SOAP version of the request
# + return - XML with the empty SOAP header
function createSoapHeader(Options? options = (), SoapVersion soapVersion) returns xml {
    string namespace = getNamespace(soapVersion);
    xml headersRoot = xml `<soap:Header xmlns:soap="{{namespace}}"></soap:Header>`;
    xml? headerElement = ();
    if (options is Options) {
        xml[] headers = options["headers"] ?: [];
        if (headers.length() != 0) {
            int i = 1;
            xml headersXML = headers[0];
            while (i < headers.length()) {
                headersXML = headersXML + headers[i];
                i = i + 1;
            }
            headerElement = headersXML;
        }
        if (options["requestTo"] is string) {
            if (headerElement is ()) {
                headerElement = getWSAddressingHeaders(options);
            } else {
                headerElement = headerElement + getWSAddressingHeaders(options);
            }
        }
        if (options["usernameToken"]["username"] is string) {
            if (headerElement is ()) {
                headerElement = getWSSecreUsernameTokenHeaders(options);
            } else {
                headerElement = headerElement + getWSSecreUsernameTokenHeaders(options);
            }
        }
        if (headerElement is xml && !headerElement.isEmpty()) {
            headersRoot.setChildren(headerElement);
        }
    }
    return headersRoot;
}

# Provides the SOAP body in the request as XML.
#
# + payload - The payload to be sent
# + soapVersion - The SOAP version of the request
# + return - XML with the SOAP body
function createSoapBody(xml payload, SoapVersion soapVersion) returns xml {
    string namespace = getNamespace(soapVersion);
    xml bodyRoot = xml `<soap:Body xmlns:soap="{{namespace}}"></soap:Body>`;
    bodyRoot.setChildren(payload);
    return bodyRoot;
}

# Prepare a SOAP envelope with the XML to be sent.
#
# + soapAction - SOAP action
# + body - SOAP request body
# + options - The Soap options to be sent
# + soapVersion - The SOAP version of the request
# + return - The SOAP Request as `http:Request` with the SOAP envelope
function fillSOAPEnvelope(string? soapAction = (), xml body, Options? options = (), SoapVersion soapVersion)
        returns http:Request {
    xml soapPayload = createSoapHeader(options = options, soapVersion);
    var requestPayload = body;
    xml bodyPayload = createSoapBody(requestPayload, soapVersion);
    soapPayload += bodyPayload;

    xml soapEnv = createSoapEnvelop(soapVersion);
    soapEnv.setChildren(soapPayload);
    http:Request req = new;
    req.setXmlPayload(soapEnv);
    if (soapVersion == SOAP11) {
        req.setHeader(mime:CONTENT_TYPE, mime:TEXT_XML);
        if (soapAction is string) {
            req.addHeader("SOAPAction", soapAction);
        }
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
    xml payload = check response.getXmlPayload();
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
}

# Creates the password used in password digest usernameToken WS-Security.
#
# + nonce - The nonce string
# + password - The password in plain text
# + createdTime - The created timestamp
# + return - The digest password in string format
function createDigestPassword(string nonce, string password, string createdTime) returns string {
    string concatenatedDigest = nonce+createdTime+password;
    byte[] SHA1hashedDigest = crypto:hashSha1(concatenatedDigest.toByteArray("UTF-8"));
    string base64EncodedDigest = encoding:encodeBase64(SHA1hashedDigest);
    return base64EncodedDigest;
}

function sendReceive(string path, string? soapAction = (), xml body, Options? options = (), http:Client httpClient,
        SoapVersion soapVersion) returns SoapResponse|error {
    http:Request req = fillSOAPEnvelope(options = options, soapAction = soapAction, body, soapVersion);
    var response = httpClient->post(path, req);
    if (response is http:Response) {
        return createSOAPResponse(response, soapVersion);
    } else {
        return response;
    }
}

function sendRobust(string path, string? soapAction = (), xml body, Options? options = (), http:Client httpClient,
        SoapVersion soapVersion) returns error? {
    http:Request req = fillSOAPEnvelope(options = options, soapAction = soapAction, body, soapVersion);
    var response = httpClient->post(path, req);
    if (response is error) {
        return response;
    }
}

function fireAndForget(string path, string? soapAction = (), xml body, Options? options = (), http:Client httpClient,
        SoapVersion soapVersion) {
    http:Request req = fillSOAPEnvelope(options = options, soapAction = soapAction, body, SOAP11);
    var response = httpClient->post(path, req);
}

public type SoapConfiguration record {
    http:ClientEndpointConfig clientConfig;
};
