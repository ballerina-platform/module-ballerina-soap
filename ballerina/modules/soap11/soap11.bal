// Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com) All Rights Reserved.
//
// WSO2 LLC. licenses this file to you under the Apache License,
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

import soap;

import ballerina/http;
import ballerina/mime;
import ballerina/jballerina.java;
import soap.wssec;

# Object for the basic SOAP 1.1 client endpoint.
public isolated client class Client {
    private final http:Client soapClient;
    private final readonly & soap:OutboundSecurityConfig|soap:OutboundSecurityConfig[] outboundSecurity;
    private final readonly & soap:InboundSecurityConfig inboundSecurity;

    # Gets invoked during object initialization.
    #
    # + url - URL endpoint
    # + config - Configurations for SOAP client
    # + return - `error` in case of errors or `()` otherwise
    public isolated function init(string url, *soap:ClientConfig config) returns Error? {
        do {
            check soap:validateTransportBindingPolicy(config);
            self.soapClient = check new (url, config.httpConfig);
            readonly & soap:ClientConfig readonlyConfig = soap:getReadOnlyClientConfig(config);
            self.inboundSecurity = readonlyConfig.inboundSecurity;
            self.outboundSecurity = readonlyConfig.outboundSecurity;
        } on fail var err {
            return error Error(SOAP_CLIENT_ERROR, err);
        }
    }

    # Sends SOAP request and expects a response.
    # ```ballerina
    # xml response = check soapClient->sendReceive(body, action);
    #      -- OR --
    # mime:Entity[] response = check soapClient->sendReceive(body, action);
    # ```
    #
    # + body - SOAP request body as an `XML` or `mime:Entity[]` to work with SOAP attachments
    # + action - SOAP action as a `string`
    # + headers - SOAP headers as a `map<string|string[]>`
    # + path - The resource path
    # + T - Default parameter use to infer the user specified type (`xml` or `mime:Entity[]`)
    # + return - If successful, returns the response. Else, returns an error
    remote isolated function sendReceive(xml|mime:Entity[] body, string action, map<string|string[]> headers = {},
                                         string path = "", typedesc<xml|mime:Entity[]> T = <>)
        returns T|Error = @java:Method {
            'class: "io.ballerina.lib.soap.Soap",
            name: "sendReceive11"
    } external;

    isolated function generateResponse(xml|mime:Entity[] body, string action,
                                       map<string|string[]> headers = {}, string path = "")
        returns xml|mime:Entity[]|Error {
        do {
            xml securedBody;
            xml mimeEntity = body is xml ? body : check body[0].getXml();
            lock {
                xml envelope = body is xml ? body.clone() : mimeEntity.clone();
                securedBody = check soap:applySecurityPolicies(self.outboundSecurity.clone(), envelope.clone(), false);
            }
            xml|mime:Entity[] response;
            if body is mime:Entity[] {
                body[0].setXml(securedBody);
                response = check soap:sendReceive(body, self.soapClient, action, headers, path, false);
            } else {
                response = check soap:sendReceive(securedBody, self.soapClient, action, headers, path, false);
            }
            lock {
                wssec:InboundConfig? inboundSecurity = self.inboundSecurity.clone();
                do {
                    if inboundSecurity is wssec:InboundConfig && inboundSecurity != {} {
                        if response is xml {
                            return check soap:applyInboundConfig(inboundSecurity.clone(), response.clone(), false);
                        } else {
                            return check soap:applyInboundConfig(inboundSecurity.clone(), 
                                                                  check response[0].getXml().clone(), false);
                        }
                    }
                } on fail error soapError {
                    return error Error(INVALID_OUTBOUND_SECURITY_ERROR, soapError);
                }
                return response;
            }
        } on fail error soapError {
            return error Error(SOAP_ERROR, soapError);
        }
    }

    # Fires and forgets requests. Sends the request without the possibility of any response from the
    # service (even an error).
    # ```ballerina
    # check soapClient->sendOnly(body, action);
    # ```
    #
    # + body - SOAP request body as an `XML` or `mime:Entity[]` to work with SOAP attachments
    # + action - SOAP action as a `string`
    # + headers - SOAP headers as a `map<string|string[]>`
    # + path - The resource path
    # + return - If successful, returns `nil`. Else, returns an error
    remote isolated function sendOnly(xml|mime:Entity[] body, string action,
                                      map<string|string[]> headers = {}, string path = "") returns Error? {
        do {
            xml securedBody;
            xml mimeEntity = body is xml ? body : check body[0].getXml();
            lock {
                xml envelope = body is xml ? body.clone() : mimeEntity.clone();
                securedBody = check soap:applySecurityPolicies(self.outboundSecurity.clone(), envelope.clone(), false);
            }
            return check soap:sendOnly(securedBody, self.soapClient, action, headers, path, false);
        } on fail error soapError {
            return error Error(SOAP_ERROR, soapError);
        }
    }
}
