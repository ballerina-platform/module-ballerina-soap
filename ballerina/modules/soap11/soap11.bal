// Copyright (c) 2023, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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
import soap.common;
import soap.wssec;

import ballerina/http;
import ballerina/mime;

xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;

# Object for the basic SOAP client endpoint.
public client class Client {
    private final http:Client soapClient;
    private wssec:InboundSecurityConfig|wssec:InboundSecurityConfig[] inboundSecurity;
    private wssec:OutboundSecurityConfig? outboundSecurity;

    # Gets invoked during object initialization.
    #
    # + url - URL endpoint
    # + config - Configurations for SOAP client
    # + return - `error` in case of errors or `()` otherwise
    public function init(string url, *common:ClientConfig config) returns Error? {
        do {
            check common:validateTransportBindingPolicy(config);
            self.soapClient = check new (url, common:retrieveHttpClientConfig(config));
            self.inboundSecurity = config.inboundSecurity;
            self.outboundSecurity = config.outboundSecurity;
        } on fail var err {
            return error Error(SOAP_CLIENT_ERROR, err);
        }
    }

    # Sends SOAP request and expects a response.
    # ```ballerina
    # xml|mime:Entity[] response = check soapClient->sendReceive(body);
    # ```
    #
    # + body - SOAP request body as an `XML` or `mime:Entity[]` to work with SOAP attachments
    # + action - SOAP action as a `string`
    # + headers - SOAP headers as a `map<string|string[]>`
    # + return - If successful, returns the response. Else, returns an error
    remote function sendReceive(xml|mime:Entity[] body, string action,
                                map<string|string[]> headers = {}) returns xml|mime:Entity[]|Error {
        do {
            if body is xml {
                xml applySecurityPoliciesResult = check common:applySecurityPolicies(self.inboundSecurity, body);
                xml response = check common:sendReceive(applySecurityPoliciesResult, self.soapClient,
                                                        action, headers, false);
                wssec:OutboundSecurityConfig? outboundSecurity = self.outboundSecurity;
                do {
                    if outboundSecurity !is () {
                        return check common:applyOutboundConfig(outboundSecurity, response);
                    }
                } on fail var e {
                    return error Error("Outbound security configurations do not match with the SOAP response. ", e.cause());
                }
            }
            return check common:sendReceive(body, self.soapClient, action, headers, false);
        } on fail var e {
            return error Error(e.message());
        }
    }

    # Fires and forgets requests. Sends the request without the possibility of any response from the
    # service (even an error).
    # ```ballerina
    # check soapClient->sendOnly(body);
    # ```
    #
    # + body - SOAP request body as an `XML` or `mime:Entity[]` to work with SOAP attachments
    # + action - SOAP action as a `string`
    # + headers - SOAP headers as a `map<string|string[]>`
    # + return - If successful, returns `nil`. Else, returns an error
    remote function sendOnly(xml|mime:Entity[] body, string action,
            map<string|string[]> headers = {}) returns Error? {
        if body is xml {
            do {
                xml applySecurityPoliciesResult = check common:applySecurityPolicies(self.inboundSecurity, body);
                return check common:sendOnly(applySecurityPoliciesResult, self.soapClient, action, headers, false);
            } on fail var e {
                return error Error(e.message());
            }
        }
        do {
            return check common:sendOnly(body, self.soapClient, action, headers, false);
        } on fail var e {
            return error Error(e.message());
        }
    }
}
