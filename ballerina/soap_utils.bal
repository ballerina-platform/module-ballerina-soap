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
import ballerina/mime;

# Creates a SOAP Request as an `http:Request`
#
# + soapAction - SOAP action
# + body - SOAP request body as an `XML` or `mime:Entity[]` to work with soap attachments
# + soapVersion - The SOAP version of the request
# + headers - SOAP headers as a `map<string|string[]>`
# + return - The SOAP Request sent as `http:Request`
function createHttpRequest(SoapVersion soapVersion, xml|mime:Entity[] body,
                           string? soapAction, map<string|string[]> headers = {}) returns http:Request {
    http:Request req = new;
    if body is xml {
        req.setXmlPayload(body);
    } else {
        req.setBodyParts(body);
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
    foreach string key in headers.keys() {
        req.addHeader(key, headers[key].toBalString());
    }
    return req;
}

# Creates the SOAP response from the HTTP Response.
#
# + response - The request to be sent
# + soapVersion - The SOAP version of the request
# + return - The SOAP response created from the `http:Response` or the `error` object when reading the payload
function createSoapResponse(http:Response response, SoapVersion soapVersion) returns xml|error {
    xml payload = check response.getXmlPayload();
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap11;
    xmlns "http://www.w3.org/2003/05/soap-envelope" as soap12;

    return soapVersion == SOAP11 ? payload/<soap11:Body> : payload/<soap12:Body>;
}

string path = "";

function sendReceive(SoapVersion soapVersion, xml|mime:Entity[] body, http:Client httpClient,
                     string? soapAction = (), map<string|string[]> headers = {}) returns xml|Error {
    http:Request req = createHttpRequest(soapVersion, body, soapAction, headers);
    http:Response response;
    do {
        response = check httpClient->post(path, req);
    } on fail var err {
        return error Error("Failed to receive soap response", err);
    }
    do {
        return check createSoapResponse(response, soapVersion);
    } on fail var err {
        return error Error("Failed to create soap response", err);
    }
}

function sendOnly(SoapVersion soapVersion, xml|mime:Entity[] body, http:Client httpClient,
                  string? soapAction = (), map<string|string[]> headers = {}) returns Error? {
    http:Request req = createHttpRequest(SOAP11, body, soapAction, headers);
    do {
        http:Response _ = check httpClient->post(path, req);
    } on fail var err {
        return error Error("Failed to create soap response", err);
    }
}

function retrieveHttpClientConfig(ClientConfiguration config) returns http:ClientConfiguration {
    return {
        httpVersion: config.httpVersion,
        http1Settings: config.http1Settings,
        http2Settings: config.http2Settings,
        timeout: config.timeout,
        poolConfig: config?.poolConfig,
        auth: config?.auth,
        retryConfig: config?.retryConfig,
        responseLimits: config.responseLimits,
        secureSocket: config?.secureSocket,
        circuitBreaker: config?.circuitBreaker
    };
}
