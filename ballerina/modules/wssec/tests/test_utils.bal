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

import ballerina/test;
import ballerina/crypto;

const USERNAME = "username";
const PASSWORD = "password";

const KEY_ALIAS = "wss40";
const KEY_PASSWORD = "security";

const SOAP_ENVELOPE_PATH = "modules/wssec/tests/resources/xml/soap_envelope.xml";
const PUBLIC_KEY_PATH = "modules/wssec/tests/resources/public_key.cer";
const PRIVATE_KEY_PATH = "modules/wssec/tests/resources/private_key.pem";
const KEY_STORE_PATH = "modules/wssec/tests/resources/wss40.p12";
const X509_PUBLIC_CERT_PATH = "modules/wssec/tests/resources/x509_certificate.crt";
const X509_PUBLIC_CERT_PATH_2 = "modules/wssec/tests/resources/x509_certificate_2.crt";
const X509_KEY_STORE_PATH = "modules/wssec/tests/resources/x509_certificate.p12";
const X509_KEY_STORE_PATH_2 = "modules/wssec/tests/resources/x509_certificate_2.p12";

const KEY_STORE_PATH_2 = "modules/wssec/tests/resources/keystore.jks";
const ALIAS = "mykey";

const crypto:KeyStore clientKeyStore = {
    path: X509_KEY_STORE_PATH_2,
    password: KEY_PASSWORD
};
crypto:PrivateKey clientPrivateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(clientKeyStore, KEY_ALIAS,
                                                                                  KEY_PASSWORD);
crypto:PublicKey clientPublicKey = check crypto:decodeRsaPublicKeyFromTrustStore(clientKeyStore, KEY_ALIAS);

const crypto:KeyStore serverKeyStore = {
    path: X509_KEY_STORE_PATH,
    password: KEY_PASSWORD
};
crypto:PrivateKey serverPrivateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(serverKeyStore, KEY_ALIAS,
                                                                                  KEY_PASSWORD);
crypto:PublicKey serverPublicKey = check crypto:decodeRsaPublicKeyFromTrustStore(serverKeyStore, KEY_ALIAS);

crypto:KeyStore keyStore = {
    path: KEY_STORE_PATH,
    password: KEY_PASSWORD
};
crypto:PrivateKey symmetricKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

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
    string:RegExp signature = re `<ds:Signature .*>`;
    string:RegExp signatureInfo = re `<ds:SignedInfo>`;
    string:RegExp canonicalizationMethod = re `<ds:CanonicalizationMethod Algorithm=".*">`;
    string:RegExp signatureMethod = re `<ds:SignatureMethod Algorithm=".*"/>`;
    string:RegExp transformMethod = re `<ds:Transform Algorithm=".*"/>`;
    string:RegExp digestMethod = re `<ds:DigestMethod Algorithm=".*"/>`;
    string:RegExp digestValue = re `ds:DigestValue>`;
    string:RegExp signatureValue = re `<ds:SignatureValue>`;

    test:assertTrue(securedEnvelope.includesMatch(signature));
    test:assertTrue(securedEnvelope.includesMatch(signatureInfo));
    test:assertTrue(securedEnvelope.includesMatch(canonicalizationMethod));
    test:assertTrue(securedEnvelope.includesMatch(signatureMethod));
    test:assertTrue(securedEnvelope.includesMatch(transformMethod));
    test:assertTrue(securedEnvelope.includesMatch(digestMethod));
    test:assertTrue(securedEnvelope.includesMatch(digestValue));
    test:assertTrue(securedEnvelope.includesMatch(signatureValue));
}

function assertEncryptedSymmetricKey(string securedEnvelope) {
    string:RegExp encryptedKey = re `<xenc:EncryptedKey .*">`;
    string:RegExp encryptionMethod = re `<xenc:EncryptionMethod Algorithm=".*"/>`;
    string:RegExp cipherData = re `<xenc:CipherData>`;

    test:assertTrue(securedEnvelope.includesMatch(encryptedKey));
    test:assertTrue(securedEnvelope.includesMatch(encryptionMethod));
    test:assertTrue(securedEnvelope.includesMatch(cipherData));
}

function assertEncryptedPart(string securedEnvelope) {
    string:RegExp encryptedData = re `<xenc:EncryptedData xmlns:xenc=".*>`;
    string:RegExp encMethod = re `<xenc:EncryptionMethod Algorithm=".*"/>`;
    string:RegExp cipherData = re `<xenc:CipherData>`;
    string:RegExp cipherValue = re `<xenc:CipherValue>`;

    test:assertTrue(securedEnvelope.includesMatch(encryptedData));
    test:assertTrue(securedEnvelope.includesMatch(encMethod));
    test:assertTrue(securedEnvelope.includesMatch(cipherData));
    test:assertTrue(securedEnvelope.includesMatch(cipherValue));
}
