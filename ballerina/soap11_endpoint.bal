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

# Object for the SOAP 1.1 client endpoint.
public client class Soap11Client {

    http:Client soap11Client;

    public function init(string url, http:ClientConfiguration? config = ()) returns error? {
        if (config is http:ClientConfiguration) {
            self.soap11Client = check new (url, config = config);
        } else {
            self.soap11Client = check new (url);
        }
    }

    # Sends SOAP 1.1 request and expects a response.
    #
    # + body - SOAP request body as an `XML` or `mime:Entity[]` to work with SOAP attachments
    # + soapAction - SOAP action
    # + options - SOAP options. E.g., headers, WS-addressing parameters, usernameToken parameters
    # + return - If successful, returns the response object. Else, returns an error
    remote function sendReceive(xml|mime:Entity[] body, string soapAction, Options? options = ())
                                        returns @tainted SoapResponse|error {
        return sendReceive(SOAP11, body, self.soap11Client, soapAction = soapAction, options = options);
    }

    # Sends Robust SOAP 1.1 requests and possibly receives an error.
    #
    # + body - SOAP request body as an `XML` or `mime:Entity[]` to work with SOAP attachments
    # + soapAction - SOAP action
    # + options - SOAP options. E.g., headers, WS-addressing parameters, usernameToken parameters
    # + return - If successful, returns `nil`. Else, returns an error.
    remote function sendRobust(xml|mime:Entity[] body, string soapAction, Options? options = ()) 
                                      returns error? {
        return sendRobust(SOAP11, body, self.soap11Client, soapAction = soapAction, options = options);
    }

    # Fire and forget requests. Sends the request without the possibility of any response from the
    # service (even an error).
    #
    # + body - SOAP request body as an `XML` or `mime:Entity[]` to work with SOAP attachments
    # + soapAction - SOAP action
    # + options - SOAP options. E.g., headers, WS-addressing parameters, usernameToken parameters
    # + return - If successful, returns `nil`. Else, returns an error.
    remote function sendOnly(xml|mime:Entity[] body, string soapAction, Options? options = ()) returns error? {
        var _ = check sendOnly(SOAP11, body, self.soap11Client, soapAction = soapAction, options = options);
    }
};
