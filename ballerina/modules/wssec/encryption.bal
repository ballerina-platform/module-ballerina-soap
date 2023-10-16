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

isolated class Encryption {

    private handle nativeEncryption;

    isolated function init() returns Error? {
        self.nativeEncryption = newEncryption();
    }

    public isolated function setEncryptionAlgorithm(string encryptionAlgorithm) = @java:Method {
        'class: "org.wssec.Encryption"
    } external;

    public isolated function setEncryptedData(byte[] encryptedData) = @java:Method {
        'class: "org.wssec.Encryption"
    } external;

    public isolated function getEncryptedKeyElements(byte[] encryptedKey) returns string|Error = @java:Method {
        'class: "org.wssec.Encryption"
    } external;
}

isolated function newEncryption() returns handle = @java:Constructor {
    'class: "org.wssec.Encryption"
} external;
