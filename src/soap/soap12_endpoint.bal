// Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

# Object for the SOAP 1.2 client endpoint.
#
# + soap12Client - The HTTP client created to send SOAP 1.2 requests.
public type Soap12Client client object {

    private http:Client soap12Client;

    public function __init(string url, http:ClientConfiguration? config = ()) {
        self.soap12Client = new (url, config = config);
    }

    # Sends SOAP 1.2 request and expects a response.
    #
    # + soapAction - SOAP action
    # + body - SOAP request body as an `XML` or `mime:Entity[]` to work with SOAP attachments
    # + options - SOAP options. E.g., headers, WS-addressing parameters, usernameToken parameters
    # + return - If successful, returns the response object. Else, returns an error.
    public remote function sendReceive(xml | mime:Entity[] body, string? soapAction = (), Options? options = ())
    returns @tainted SoapResponse | error {
        return sendReceive(SOAP12, body, self.soap12Client, soapAction = soapAction, options = options);
    }

    # Sends robust SOAP 1.2 requests and possibly receives an error.
    #
    # + soapAction - SOAP action
    # + body - SOAP request body as an `XML` or `mime:Entity[]` to work with SOAP attachments
    # + options - SOAP options. E.g., headers, WS-addressing parameters, usernameToken parameters
    # + return - If successful, returns `nil`. Else, returns an error.
    public remote function sendRobust(xml | mime:Entity[] body, string? soapAction = (), Options? options = ())
    returns error? {
        return sendRobust(SOAP12, body, self.soap12Client, soapAction = soapAction, options = options);
    }

    # Fire and forget requests. Sends the request without the possibility of any response from the
    # service (even an error).
    #
    # + soapAction - SOAP action
    # + body - SOAP request body as an `XML` or `mime:Entity[]` to work with SOAP attachments
    # + options - SOAP options. E.g., headers, WS-addressing parameters, usernameToken parameters
    public remote function sendOnly(xml | mime:Entity[] body, string? soapAction = (), Options? options = ()) {
        sendOnly(SOAP12, body, self.soap12Client, soapAction = soapAction, options = options);
    }
};
