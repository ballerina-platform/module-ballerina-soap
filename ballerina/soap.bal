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

# Defines the supported SOAP versions.
public enum SoapVersion {
    # Represents SOAP 1.1 version
    SOAP11,
    # Represents SOAP 1.2 version
    SOAP12
}

# Soap client configurations.
#
# + soapVersion - Soap version
public type ClientConfiguration record {|
  *http:ClientConfiguration;
  SoapVersion soapVersion = SOAP11;
|};

# Object for the basic SOAP client endpoint.
public isolated client class Client {

    private final http:Client soapClient;
    private final SoapVersion soapVersion;

    public function init(string url, *ClientConfiguration config) returns error? {
        self.soapVersion = config.soapVersion;
        self.soapClient = check new (url,retrieveHttpClientConfig(config));
    }

    # Sends SOAP request and expects a response.
    #
    # + body - SOAP request body as an `XML` or `mime:Entity[]` to work with SOAP attachments
    # + return - If successful, returns the response. Else, returns an error
    remote function sendReceive(xml|mime:Entity[] body) returns xml|mime:Entity[]|error {
        return sendReceive(self.soapVersion, body, self.soapClient);
    }

    # Fire and forget requests. Sends the request without the possibility of any response from the
    # service (even an error).
    #
    # + body - SOAP request body as an `XML` or `mime:Entity[]` to work with SOAP attachments
    # + return - If successful, returns `nil`. Else, returns an error
    remote function sendOnly(xml|mime:Entity[] body) returns error? {
        return sendOnly(self.soapVersion, body, self.soapClient);
    }
}
