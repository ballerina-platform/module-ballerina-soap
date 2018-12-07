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

# Object for SOAP client endpoint.
#
# + soapConnector - Reference to `SoapConnector` type
public type Client client object {

    public SoapConnector soapConnector;

    public function __init(string url, SoapConfiguration? soapConfig = ()) {
        self.soapConnector = new(url, soapConfig.clientConfig);
    }

    # Sends request and expects a response.
    #
    # + path - Resource path
    # + request - Request to be sent
    # + return - If success, returns the response object, else returns `SoapError` object
    public remote function sendReceive(string path, SoapRequest request) returns SoapResponse|error {
        return self.soapConnector->sendReceive(path, request);
    }

    # Send Robust requests.Sends the request and possibly receives an error.
    #
    # + path - Resource path
    # + request - Request to be sent
    # + return - If success, returns `nil`, else returns `SoapError` object
    public remote function sendRobust(string path, SoapRequest request) returns error? {
        return self.soapConnector->sendRobust(path, request);
    }

    # Fire and forget requests. Sends the request without the possibility of any response from the service (even an error).
    #
    # + path - Resource path
    # + request - Request to be sent
    public remote function fireAndForget(string path, SoapRequest request) {
        return self.soapConnector->fireAndForget(path, request);
    }
};

public type SoapConfiguration record {
    http:ClientEndpointConfig clientConfig;
};
