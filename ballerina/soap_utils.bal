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
import ballerina/lang.'xml as xmllib;
import ballerina/mime;

# Provides an empty SOAP envelope for the given SOAP version.
#
# + soapVersion - The SOAP version of the request
# + return - XML with the empty SOAP envelope
function createSoapEnvelop(SoapVersion soapVersion) returns xmllib:Element {
    if soapVersion == SOAP11 {
        return <xmllib:Element> xml `<soap:Envelope
        xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
        soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                </soap:Envelope>`;
    } else {
        return <xmllib:Element> xml `<soap:Envelope
        xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
        soap:encodingStyle="http://www.w3.org/2003/05/soap-encoding">
                </soap:Envelope>`;
    }
}

# Provides the SOAP headers in the request as XML.
#
# + soapVersion - The SOAP version of the request
# + return - XML with the empty SOAP header
function createSoapHeader(SoapVersion soapVersion) returns xml {
    xmllib:Element headersRoot;
    if soapVersion == SOAP11 {
        headersRoot = <xmllib:Element> xml `<soap:Header xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"></soap:Header>`;
    } else {
        headersRoot = <xmllib:Element> xml `<soap:Header xmlns:soap="http://www.w3.org/2003/05/soap-envelope"></soap:Header>`;
    }
    return headersRoot;
}

# Provides the SOAP body in the request as XML.
#
# + payload - The payload to be sent
# + soapVersion - The SOAP version of the request
# + return - XML with the SOAP body
function createSoapBody(xml payload, SoapVersion soapVersion) returns xml {
    xmllib:Element bodyRoot;
    if soapVersion == SOAP11 {
        bodyRoot = <xmllib:Element> xml `<soap:Body xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"></soap:Body>`;
    } else {
        bodyRoot = <xmllib:Element> xml `<soap:Body xmlns:soap="http://www.w3.org/2003/05/soap-envelope"></soap:Body>`;
    }
    bodyRoot.setChildren(payload);
    return bodyRoot;
}

# Prepares a SOAP envelope with the XML to be sent.
#
# + soapAction - SOAP action
# + body - SOAP request body as an `XML` or `mime:Entity[]` to work with soap attachments
# + soapVersion - The SOAP version of the request
# + return - The SOAP Request sent as `http:Request` with the SOAP envelope
function fillSoapEnvelope(SoapVersion soapVersion, xml | mime:Entity[] body, string? soapAction = ())
returns http:Request {
    xml soapPayload = createSoapHeader(soapVersion);
    http:Request req = new;
    var requestPayload = body;
    if requestPayload is xml {
        xml bodyPayload = createSoapBody(requestPayload, soapVersion);
        soapPayload = soapPayload + bodyPayload;

        xmllib:Element soapEnv = createSoapEnvelop(soapVersion);
        soapEnv.setChildren(soapPayload);
        req.setXmlPayload(soapEnv);
    } else {
        req.setBodyParts(requestPayload);
    }
    if soapVersion == SOAP11 {
        req.setHeader(mime:CONTENT_TYPE, mime:TEXT_XML);
        if soapAction is string {
            req.addHeader("SOAPAction", soapAction);
        }
    } else {
        if soapAction is string {
            map<string> stringMap = {};
            stringMap["action"] = "\"" + soapAction + "\"";
            var mediaType = mime:getMediaType(mime:APPLICATION_SOAP_XML);
            if mediaType is mime:MediaType {
                mediaType.parameters = stringMap;
                req.setHeader(mime:CONTENT_TYPE, mediaType.toString());
            }
        } else {
            req.setHeader(mime:CONTENT_TYPE, mime:APPLICATION_SOAP_XML);
        }
    }
    return req;
}

# Creates the SOAP response from the HTTP Response.
#
# + response - The request to be sent
# + soapVersion - The SOAP version of the request
# + return - The SOAP response created from the `http:Response` or the `error` object when reading the payload
function createSOAPResponse(http:Response response, SoapVersion soapVersion) returns xml | error {
    xml payload = check response.getXmlPayload();
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap11;
    xmlns "http://www.w3.org/2003/05/soap-envelope" as soap12;

    xml soapResponsePayload;
    if soapVersion == SOAP11 {
        soapResponsePayload = payload/<soap11:Body>;
    } else {
        soapResponsePayload = payload/<soap12:Body>;
    }
    return soapResponsePayload;
}

string path = "";

function sendReceive(SoapVersion soapVersion, xml|mime:Entity[] body, http:Client httpClient, string? soapAction = ()) returns xml|error {
    http:Request req = fillSoapEnvelope(soapVersion, body, soapAction = soapAction);
    http:Response response = check httpClient->post(path, req);
    return createSOAPResponse(response, soapVersion);
}
function sendOnly(SoapVersion soapVersion, xml|mime:Entity[] body, http:Client httpClient, string? soapAction = ()) returns error? {
    http:Request req = fillSoapEnvelope(SOAP11, body, soapAction = soapAction);
    http:Response _ = check httpClient->post(path, req);
}
