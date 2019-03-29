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

# SOAP 1.2 client connector.
#
# + soap12Client - HTTP client endpoint
public type Soap12Connector client object {

    public http:Client soap12Client;

    public function __init(string url, http:ClientEndpointConfig? config) {
        self.soap12Client = new(url, config = config);
    }

    remote function sendReceive(string path, string? soapAction = (), xml body, Options? options = ())
            returns SoapResponse|error;

    remote function sendRobust(string path, string? soapAction = (), xml body, Options? options = ()) returns error?;

    remote function fireAndForget(string path, string? soapAction = (), xml body, Options? options = ());
};

remote function Soap12Connector.sendReceive(string path, string? soapAction = (), xml body, Options? options = ())
        returns SoapResponse|error {
    http:Client httpClient = self.soap12Client;
    return sendReceive(path, soapAction = soapAction, body, options = options, httpClient, SOAP12);
}

remote function Soap12Connector.sendRobust(string path, string? soapAction = (), xml body, Options? options = ())
        returns error? {
    http:Client httpClient = self.soap12Client;
    return sendRobust(path, soapAction = soapAction, body, options = options, httpClient, SOAP12);
}

remote function Soap12Connector.fireAndForget(string path, string? soapAction = (), xml body, Options? options = ()) {
    http:Client httpClient = self.soap12Client;
    return fireAndForget(path, soapAction = soapAction, body, options = options, httpClient, SOAP12);
}

