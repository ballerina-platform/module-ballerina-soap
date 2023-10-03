// Copyright (c) 2023, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import ballerina/crypto;
import ballerina/jballerina.java;

class Encryption {

    private handle nativeEncryption;

    function init() returns Error? {
        self.nativeEncryption = newEncryption();
    }

    function encryptData(string dataString, EncryptionAlgorithm encryptionAlgorithm,
                         crypto:PublicKey|crypto:PrivateKey key)
        returns byte[]|Error {
        byte[] data = dataString.toBytes();
        do {
            match encryptionAlgorithm {
                RSA_ECB => {
                    return check crypto:encryptRsaEcb(data, key);
                }
                _ => {
                    return error Error("Invalid/Missing key!");
                }
            }
        } on fail var e {
            return error(e.message());
        }
    }

    public function decryptData(byte[] cipherText, EncryptionAlgorithm encryptionAlgorithm,
                                crypto:PublicKey|crypto:PrivateKey key)
        returns byte[]|Error {
        do {
            match encryptionAlgorithm {
                RSA_ECB => {
                    return check crypto:decryptRsaEcb(cipherText, key);
                }
                _ => {
                    return error Error("Invalid/Missing key!");
                }
            }
        } on fail var e {
            return error Error(e.message());
        }
    }

    public function setEncryptionAlgorithm(string encryptionAlgorithm) = @java:Method {
        'class: "org.wssec.Encryption"
    } external;

    public function setEncryptedData(byte[] encryptedData) = @java:Method {
        'class: "org.wssec.Encryption"
    } external;

    public function getEncryptedKeyElements(byte[] encryptedKey) returns string|Error = @java:Method {
        'class: "org.wssec.Encryption"
    } external;
}

function newEncryption() returns handle = @java:Constructor {
    'class: "org.wssec.Encryption"
} external;
