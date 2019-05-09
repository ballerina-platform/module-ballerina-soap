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

# Object for SOAP 1.1 client endpoint.
#
# + soap11Client - Http client created to send SOAP 1.1 requests.
public type Soap11Client client object {

    private http:Client soap11Client;

    public function __init(string url, SoapClientEndpointConfig? config = ()) {
        self.soap11Client = new(url, config = config.clientConfig);
    }

    # Sends SOAP 1.1 request and expects a response.
    #
    # + soapAction - SOAP action
    # + body - SOAP payload
    # + options - SOAP options. Ex: Headers, Ws-addressing parameters, usernameToken parameters
    # + return - If a success, returns the response object, else returns `SoapError` object
    public remote function sendReceive(string soapAction, xml body, Options? options = ())
            returns SoapResponse|error {
        return sendReceive(soapAction = soapAction, body, options = options, self.soap11Client, SOAP11);
    }

    # Send Robust SOAP 1.1 requests.Sends the request and possibly receives an error.
    #
    # + options - SOAP options. Ex: Headers, Ws-addressing parameters, usernameToken parameters
    # + return - If a success, returns `nil`, else returns `SoapError` object
    public remote function sendRobust(string soapAction, xml body, Options? options = ()) returns error? {
        return sendRobust(soapAction = soapAction, body, options = options, self.soap11Client, SOAP11);
    }

    # Fire and forget requests. Sends the request without the possibility of any response from the
    # service(even an error).
    #
    # + options - SOAP options. Ex: Headers, Ws-addressing parameters, usernameToken parameters
    public remote function sendOnly(string soapAction, xml body, Options? options = ()) {
        sendOnly(soapAction = soapAction, body, options = options, self.soap11Client, SOAP11);
    }
};
