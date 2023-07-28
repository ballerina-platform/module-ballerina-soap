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

# Object for the basic SOAP client endpoint.
public client class BasicClient {

    http:Client soapClient;
    SoapVersion version = SOAP11;

    public function init(string url, http:ClientConfiguration? config = (), SoapVersion? version = ()) returns error? {
        if config is http:ClientConfiguration {
            self.soapClient = check new (url, config);
        } else {
            self.soapClient = check new (url);
        }
        if version is SoapVersion {
            self.version = version;
        }
    }

    # Sends SOAP request and expects a response.
    #
    # + soap - SOAP request body as an `XML` or `mime:Entity[]` to work with SOAP attachments
    # + return - If successful, returns the response. Else, returns an error
    remote function sendReceive(xml|mime:Entity[] soap) returns xml|mime:Entity[]|error {
        return sendReceive(self.version, soap, self.soapClient);
    }

    # Fire and forget requests. Sends the request without the possibility of any response from the
    # service (even an error).
    #
    # + soap - SOAP request body as an `XML` or `mime:Entity[]` to work with SOAP attachments
    # + return - If successful, returns `nil`. Else, returns an error
    remote function sendOnly(xml|mime:Entity[] soap) returns error? {
        var _ = check sendOnly(self.version, soap, self.soapClient);
    }
}
