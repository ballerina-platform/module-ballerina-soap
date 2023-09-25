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

import ballerina/http;
import ballerina/mime;

# Soap client configurations.
#
public type ClientConfiguration record {|
    *http:ClientConfiguration;
|};

# Object for the basic SOAP client endpoint.
public isolated client class Client {
    private final http:Client soapClient;

    # Gets invoked during object initialization.
    #
    # + url - URL endpoint
    # + config - Configurations for SOAP client
    # + return - `error` in case of errors or `()` otherwise
    public function init(string url, *ClientConfiguration config) returns Error? {
        do {
            self.soapClient = check new (url, retrieveHttpClientConfig(config));
        } on fail var err {
            return error Error("Failed to initialize soap client", err);
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
    remote function sendReceive(xml|mime:Entity[] body, string? action = (),
                                map<string|string[]> headers = {}) returns xml|mime:Entity[]|Error {
        return sendReceive(body, self.soapClient, action, headers);
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
    remote function sendOnly(xml|mime:Entity[] body, string? action = (),
                             map<string|string[]> headers = {}) returns Error? {
        return sendOnly(body, self.soapClient, action, headers);
    }
}
