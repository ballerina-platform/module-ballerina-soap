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
// under the License.package soap;

import ballerina/http;

# SOAP client connector.
#
# + clientEP - HTTP client endpoint
public type SoapConnector object {

    public http:Client clientEP;

    # Sends request and expects a response.
    #
    # + path - Resource path
    # + request - Request to be sent
    # + return - If success, returns the response object, else returns `SoapError` object
    public function sendReceive(string path, SoapRequest request) returns SoapResponse|SoapError;

    # Send Robust requests.Sends the request and possibly receives an error.
    #
    # + path - Resource path
    # + request - Request to be sent
    # + return - If success, returns `nil`, else returns `SoapError` object
    public function sendRobust(string path, SoapRequest request) returns SoapError?;

    # Fire and forget requests. Sends the request without the possibility of any response from the service (even an error).
    #
    # + path - Resource path
    # + request - Request to be sent
    public function fireAndForget(string path, SoapRequest request);

};

function SoapConnector::sendReceive(string path, SoapRequest request) returns SoapResponse|SoapError {
    endpoint http:Client httpClient = self.clientEP;
    http:Request req = fillSOAPEnvelope(request, request.soapVersion);
    var response = httpClient->post(path, req);
    match response {
        http:Response httpResponse => {
            return createSOAPResponse(httpResponse, request.soapVersion);
        }
        error err => {
            return err;
        }
    }
}

function SoapConnector::sendRobust(string path, SoapRequest request) returns SoapError? {
    endpoint http:Client httpClient = self.clientEP;
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

function SoapConnector::fireAndForget(string path, SoapRequest request) {
    endpoint http:Client httpClient = self.clientEP;
    http:Request req = fillSOAPEnvelope(request, request.soapVersion);
    var response = httpClient->post(path, req);
}
