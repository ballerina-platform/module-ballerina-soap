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

isolated class WsSecurity {
    isolated function applyUsernameTokenPolicy(WSSecurityHeader wsSecurityHeader, string username, 
                                      string password, string pwType) returns string|Error = @java:Method {
        'class: "org.wssec.WsSecurity"
    } external;

    isolated function applyTimestampPolicy(WSSecurityHeader wsSecurityHeader, int timeToLive)
        returns string|Error = @java:Method {
        'class: "org.wssec.WsSecurity"
    } external;

    isolated function applySignatureOnlyPolicy(WSSecurityHeader wsSecurityPolicy, Signature signature,
                                               string? x509FilePath) returns string|Error = @java:Method {
        'class: "org.wssec.WsSecurity"
    } external;

    isolated function applySignatureOnly(Document soapEnvelope, boolean soap12, SignatureConfig signatureConfig)
        returns string|Error = @java:Method {
        'class: "org.wssec.WsSecurity"
    } external;

    isolated function applyEncryptionOnly(Document soapEnvelope, boolean soap12, EncryptionConfig encryptionConfig)
        returns string|Error = @java:Method {
        'class: "org.wssec.WsSecurity"
    } external;

    isolated function applySignatureAndEncryption(Document soapEnvelope, boolean soap12, 
                                                  SignatureConfig signatureConfig, EncryptionConfig encryptionConfig)
        returns string|Error = @java:Method {
        'class: "org.wssec.WsSecurity"
    } external;

    isolated function applyEncryptionOnlyPolicy(WSSecurityHeader wsSecurityPolicy, Encryption encryption)
        returns string|Error = @java:Method {
        'class: "org.wssec.WsSecurity"
    } external;

    isolated function verifySignature(Document soapEnvelope, InboundConfig config)
        returns boolean|error = @java:Method {
        'class: "org.wssec.WsSecurity"
    } external;

    isolated function decryptEnvelope(Document soapEnvelope, InboundConfig config)
        returns Document|error = @java:Method {
        'class: "org.wssec.WsSecurity"
    } external;
}
