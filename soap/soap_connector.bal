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

documentation {
    SOAP client connector.
    F{{clientEP}} Http client endpoint
}
public type SoapConnector object {

    public {
        http:Client clientEP;
    }

    documentation {
        Sends request and expects a response
        P{{path}} Resource path
        P{{request}} Request to be sent
        R{{}} If success, returns the response object, else returns `SoapError` object
    }
    public function sendSoapRequest(string path, SoapRequest request) returns (SoapResponse|SoapError);
};

public function SoapConnector::sendSoapRequest(string path, SoapRequest request) returns (SoapResponse|SoapError) {
    endpoint http:Client httpClient = self.clientEP;
    http:Request req = fillSOAPEnvelope(request, request.soapVersion);
    var response = httpClient->post(path, request = req);
    match response {
        http:Response httpResponse => {
            return createSOAPResponse(httpResponse, request.soapVersion);
        }
        error err => {
            return err;
        }
    }
}