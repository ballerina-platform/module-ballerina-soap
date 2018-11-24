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

# SOAP client connector.
#
# + soapClient - HTTP client endpoint
public type SoapConnector client object {

    public http:Client soapClient;

    public function __init(http:ClientEndpointConfig config) {
        self.soapClient = new(config);
    }

    remote function sendReceive(string path, SoapRequest request) returns SoapResponse|error;

    remote function sendRobust(string path, SoapRequest request) returns error?;

    remote function fireAndForget(string path, SoapRequest request);
};

remote function SoapConnector.sendReceive(string path, SoapRequest request) returns SoapResponse|error {
    http:Client httpClient = self.soapClient;
    http:Request req = fillSOAPEnvelope(request, request.soapVersion);
    var response = httpClient->post(path, req);
    if (response is http:Response) {
        return createSOAPResponse(response, request.soapVersion);
    } else {
        return response;
    }
}

remote function SoapConnector.sendRobust(string path, SoapRequest request) returns error? {
    http:Client httpClient = self.soapClient;
    http:Request req = fillSOAPEnvelope(request, request.soapVersion);
    var response = httpClient->post(path, req);
    match response {
        http:Response httpResponse => {
            return ();
        }
        error err => {
            return err;
        }
    }
}

remote function SoapConnector.fireAndForget(string path, SoapRequest request) {
    http:Client httpClient = self.soapClient;
    http:Request req = fillSOAPEnvelope(request, request.soapVersion);
    var response = httpClient->post(path, req);
}
