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

import ballerina/crypto;
import ballerina/jballerina.java;

isolated class Signature {

    private handle nativeSignature;

    isolated function init() returns Error? {
        self.nativeSignature = newSignature();
    }

    public isolated function signData(string dataString, SignatureAlgorithm signatureAlgorithm,
                                      crypto:PrivateKey privateKey) returns byte[]|Error {
        byte[] data = dataString.toBytes();
        do {
            match signatureAlgorithm {
                RSA_SHA1 => {
                    return check crypto:signRsaSha1(data, privateKey);
                }
                RSA_SHA256 => {
                    return check crypto:signRsaSha256(data, privateKey);
                }
                RSA_SHA384 => {
                    return check crypto:signRsaSha384(data, privateKey);
                }
                _ => {
                    return check crypto:signRsaSha512(data, privateKey);
                }
            }
        } on fail error signatureError {
            return error Error("Error occurred while signing the data", signatureError);
        }
    }

    public isolated function verifySignature(byte[] data, byte[] signature, crypto:PublicKey publicKey,
                                    SignatureAlgorithm signatureAlgorithm) returns boolean|Error {
        do {
            match signatureAlgorithm {
                RSA_SHA1 => {
                    return check crypto:verifyRsaSha1Signature(data, signature, publicKey);
                }
                RSA_SHA256 => {
                    return check crypto:verifyRsaSha256Signature(data, signature, publicKey);
                }
                RSA_SHA384 => {
                    return check crypto:verifyRsaSha384Signature(data, signature, publicKey);
                }
                _ => {
                    return check crypto:verifyRsaSha512Signature(data, signature, publicKey);
                }
            }
        } on fail error signatureError {
            return error Error("Error occurred while verifying the signature", signatureError);
        }
    }

    public isolated function setSignatureAlgorithm(string signatureAlgorithm) = @java:Method {
        'class: "org.wssec.Signature"
    } external;

    public isolated function setSignatureValue(byte[] signatureValue) = @java:Method {
        'class: "org.wssec.Signature"
    } external;
}

isolated function newSignature() returns handle = @java:Constructor {
    'class: "org.wssec.Signature"
} external;
