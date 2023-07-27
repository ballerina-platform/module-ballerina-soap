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

# Provides the SOAP body in the request as XML.
#
# + payload - The payload to be sent
# + return - XML with the SOAP body
function createSoapBody(xml payload) returns xml {
    xmllib:Element bodyRoot = <xmllib:Element> xml `<soap:Body xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"></soap:Body>`;

    bodyRoot.setChildren(payload);
    return bodyRoot;
}

# Prepares a SOAP envelope with the XML to be sent.
#
# + body - SOAP request body as an `XML` or `mime:Entity[]` to work with soap attachments
# + return - The SOAP Request sent as `http:Request` with the SOAP envelope
function fillSoapEnvelope(xml | mime:Entity[] body)
returns http:Request {
    xml soapPayload = <xmllib:Element> xml `<soap:Header xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"></soap:Header>`;
    http:Request req = new;
    var requestPayload = body;
    if requestPayload is xml {
        xml bodyPayload = createSoapBody(requestPayload);
        soapPayload = soapPayload + bodyPayload;

        xmllib:Element soapEnv = <xmllib:Element> xml `<soap:Envelope
        xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
        soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                </soap:Envelope>`;
        soapEnv.setChildren(soapPayload);
        req.setXmlPayload(soapEnv);
    } else {
        req.setBodyParts(requestPayload);
    }
    req.setHeader(mime:CONTENT_TYPE, mime:TEXT_XML);
    return req;
}

function createSoapResponse(http:Response response) returns xml | error {
    xml payload = check response.getXmlPayload();
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;

    xml soapResponsePayload = payload/<soap:Body>;

    return soapResponsePayload;
}

string path = "";

function sendReceive(xml|mime:Entity[] body, http:Client httpClient) returns xml|error {
    http:Request req = fillSoapEnvelope(body);
    http:Response response = check httpClient->post(path, req);
    return createSoapResponse(response);
}

function sendOnly(xml|mime:Entity[] body, http:Client httpClient) returns error? {
    http:Request req = fillSoapEnvelope(body);
    http:Response _ = check httpClient->post(path, req);
}
