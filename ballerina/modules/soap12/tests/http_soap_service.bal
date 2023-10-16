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

import ballerina/crypto;
import ballerina/http;
import ballerina/soap;

const crypto:KeyStore serverKeyStore = {
    path: X509_KEY_STORE_PATH,
    password: KEY_PASSWORD
};
crypto:PrivateKey serverPrivateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(serverKeyStore, KEY_ALIAS,
                                                                                KEY_PASSWORD);
crypto:PublicKey serverPublicKey = check crypto:decodeRsaPublicKeyFromTrustStore(serverKeyStore, KEY_ALIAS);

service / on new http:Listener(9090) {

    resource function post getPayload(http:Request request) returns http:Response|error {
        http:Response response = new;
        response.setPayload(check (check request.getBodyParts())[0].getXml());
        return response;
    }

    resource function post getSamePayload(http:Request request) returns http:Response|error {
        xml payload = check request.getXmlPayload();
        http:Response response = new;
        response.setPayload(payload);
        return response;
    }

    resource function post getSecuredPayload(http:Request request) returns http:Response|error {
        xml payload = check request.getXmlPayload();
        xml applyOutboundConfig = check soap:applyOutboundConfig(
            {
                verificationKey: clientPublicKey,
                signatureAlgorithm: soap:RSA_SHA256,
                decryptionAlgorithm: soap:RSA_ECB,
                decryptionKey: serverPrivateKey
            }, payload);
        xml securedEnv = check soap:applySecurityPolicies(
            {
                signatureAlgorithm: soap:RSA_SHA256,
                encryptionAlgorithm: soap:RSA_ECB,
                signatureKey: serverPrivateKey,
                encryptionKey: clientPublicKey
            }, applyOutboundConfig);
        http:Response response = new;
        response.setPayload(securedEnv);
        return response;
    }
}
