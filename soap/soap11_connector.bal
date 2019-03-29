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

# SOAP 1.1 client connector.
#
# + soap11Client - HTTP client endpoint for SOAP 1.1 client
public type Soap11Connector client object {

    public http:Client soap11Client;

    public function __init(string url, http:ClientEndpointConfig? config) {
        self.soap11Client = new(url, config = config);
    }

    remote function sendReceive(string path, string soapAction, xml body, Options? options = ())
            returns SoapResponse|error;

    remote function sendRobust(string path, string soapAction, xml body, Options? options = ()) returns error?;

    remote function fireAndForget(string path, string soapAction, xml body, Options? options = ());
};

remote function Soap11Connector.sendReceive(string path, string soapAction, xml body, Options? options = ())
        returns SoapResponse|error {
    http:Client httpClient = self.soap11Client;
    return sendReceive(path, soapAction = soapAction, body, options = options, httpClient, SOAP11);
}

remote function Soap11Connector.sendRobust(string path, string soapAction, xml body, Options? options = ())
        returns error? {
    http:Client httpClient = self.soap11Client;
    return sendRobust(path, soapAction = soapAction, body, options = options, httpClient, SOAP11);
}

remote function Soap11Connector.fireAndForget(string path, string soapAction, xml body, Options? options = ()) {
    http:Client httpClient = self.soap11Client;
    return fireAndForget(path, soapAction = soapAction, body, options = options, httpClient, SOAP11);
}
