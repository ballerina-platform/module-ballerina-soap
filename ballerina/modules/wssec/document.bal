// Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com) All Rights Reserved.
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

import ballerina/jballerina.java;

public isolated class Document {

    public isolated function init(xml xmlPayload) returns Error? {
        handle|error documentBuilder = newDocument(self, xmlPayload);
        if documentBuilder is error {
            return error Error(documentBuilder.message());
        }
    }

    public isolated function getEnvelope() returns xml|Error = @java:Method {
        'class: "org.wssec.DocumentBuilder"
    } external;

    public isolated function getEncryptedData() returns byte[] = @java:Method {
        'class: "org.wssec.DocumentBuilder"
    } external;

    public isolated function getSignatureData() returns byte[] = @java:Method {
        'class: "org.wssec.DocumentBuilder"
    } external;
}

isolated function newDocument(Document doc, xml xmlPayload) returns handle|error = @java:Constructor {
    'class: "org.wssec.DocumentBuilder"
} external;
