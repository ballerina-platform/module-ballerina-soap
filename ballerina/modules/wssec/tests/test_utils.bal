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
import ballerina/test;

const USERNAME = "username";
const PASSWORD = "password";

const KEY_ALIAS = "wss40";
const KEY_PASSWORD = "security";

const PUBLIC_KEY_PATH = "modules/wssec/tests/resources/public_key.cer";
const PRIVATE_KEY_PATH = "modules/wssec/tests/resources/private_key.pem";
const KEY_STORE_PATH = "modules/wssec/tests/resources/wss40.p12";
const X509_PUBLIC_CERT_PATH = "modules/wssec/tests/resources/x509_certificate.crt";
const X509_PUBLIC_CERT_PATH_2 = "modules/wssec/tests/resources/x509_certificate_2.crt";
const X509_KEY_STORE_PATH = "modules/wssec/tests/resources/x509_certificate.p12";
const X509_KEY_STORE_PATH_2 = "modules/wssec/tests/resources/x509_certificate_2.p12";

function assertTimestampToken(string envelopeString) {
    string:RegExp ts_token = re `<wsu:Timestamp wsu:Id=".*">`;
    string:RegExp created = re `<wsu:Created>.*</wsu:Created>`;
    string:RegExp expires = re `<wsu:Expires>.*</wsu:Expires>`;
    test:assertTrue(envelopeString.includesMatch(ts_token));
    test:assertTrue(envelopeString.includesMatch(created));
    test:assertTrue(envelopeString.includesMatch(expires));
}

function assertUsernameToken(string envelopeString, PasswordType passwordType) {
    string:RegExp usernameTokenTag = re `<wsse:UsernameToken .*>.*</wsse:UsernameToken>`;
    string:RegExp usernameTag = re `<wsse:Username>${USERNAME}</wsse:Username>`;
    test:assertTrue(envelopeString.includesMatch(usernameTokenTag));
    test:assertTrue(envelopeString.includesMatch(usernameTag));
    match passwordType {
        TEXT => {
            string:RegExp passwordTag = re `<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">${PASSWORD}</wsse:Password>`;
            test:assertTrue(envelopeString.includesMatch(passwordTag));
        }
        DIGEST => {
            string:RegExp passwordTag = re `<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">.*</wsse:Password>`;
            string:RegExp nonce = re `<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">.*</wsse:Nonce>`;
            string:RegExp created = re `<wsu:Created>.*</wsu:Created>`;
            test:assertTrue(envelopeString.includesMatch(passwordTag));
            test:assertTrue(envelopeString.includesMatch(nonce));
            test:assertTrue(envelopeString.includesMatch(created));
        }
        _ => {
            string:RegExp salt = re `<wsse11:Salt>.*</wsse11:Salt>`;
            string:RegExp iteration = re `<wsse11:Iteration>.*</wsse11:Iteration>`;
            test:assertTrue(envelopeString.includesMatch(salt));
            test:assertTrue(envelopeString.includesMatch(iteration));
        }
    }
}

function assertSignatureWithX509(string securedEnvelope) {
    string:RegExp keyIdentifier = re `<wsse:KeyIdentifier EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3">.*</wsse:KeyIdentifier>`;
    test:assertTrue(securedEnvelope.includesMatch(keyIdentifier));
    assertSignatureWithoutX509(securedEnvelope);
}

function assertSignatureWithoutX509(string securedEnvelope) {
    string:RegExp signature = re `<ds:Signature xmlns:ds=".*" .*">.*</ds:Signature>`;
    string:RegExp signatureInfo = re `<ds:SignedInfo>.*</ds:SignedInfo>`;
    string:RegExp canonicalizationMethod = re `<ds:CanonicalizationMethod Algorithm=".*">`;
    string:RegExp signatureMethod = re `<ds:SignatureMethod Algorithm=".*"/>`;
    string:RegExp transformMethod = re `<ds:Transform Algorithm=".*"/>`;
    string:RegExp digestMethod = re `<ds:DigestMethod Algorithm=".*"/>`;
    string:RegExp signatureValue = re `<ds:SignatureValue>.*</ds:SignatureValue>`;

    test:assertTrue(securedEnvelope.includesMatch(signature));
    test:assertTrue(securedEnvelope.includesMatch(signatureInfo));
    test:assertTrue(securedEnvelope.includesMatch(canonicalizationMethod));
    test:assertTrue(securedEnvelope.includesMatch(signatureMethod));
    test:assertTrue(securedEnvelope.includesMatch(transformMethod));
    test:assertTrue(securedEnvelope.includesMatch(digestMethod));
    test:assertTrue(securedEnvelope.includesMatch(signatureValue));
}

function assertEncryptedSymmetricKey(string securedEnvelope) {
    string:RegExp encryptedKey = re `<xenc:EncryptedKey .*">.*</xenc:EncryptedKey>`;
    string:RegExp encryptionMethod = re `<xenc:EncryptionMethod Algorithm=".*"/>`;
    string:RegExp keyInfo = re `<ds:KeyInfo .*/>`;
    string:RegExp cipherData = re `<xenc:CipherData>.*</xenc:CipherData>`;

    test:assertTrue(securedEnvelope.includesMatch(encryptedKey));
    test:assertTrue(securedEnvelope.includesMatch(encryptionMethod));
    test:assertTrue(securedEnvelope.includesMatch(keyInfo));
    test:assertTrue(securedEnvelope.includesMatch(cipherData));
}

function assertEncryptedPart(string securedEnvelope) {
    string:RegExp encryptedData = re `<xenc:EncryptedData xmlns:xenc=".*>`;
    string:RegExp encMethod = re `<xenc:EncryptionMethod Algorithm=".*"/>`;
    string:RegExp keyInfo = re `<ds:KeyInfo xmlns:ds=".*">`;
    string:RegExp cipherData = re `<xenc:CipherData>.*</xenc:CipherData>`;
    string:RegExp cipherValue = re `<xenc:CipherValue>.*</xenc:CipherValue>`;

    test:assertTrue(securedEnvelope.includesMatch(encryptedData));
    test:assertTrue(securedEnvelope.includesMatch(encMethod));
    test:assertTrue(securedEnvelope.includesMatch(keyInfo));
    test:assertTrue(securedEnvelope.includesMatch(cipherData));
    test:assertTrue(securedEnvelope.includesMatch(cipherValue));
}
