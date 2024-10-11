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
import ballerina/test;
import ballerina/lang.regexp;
import ballerina/io;

@test:Config {
    groups: ["timestamp_token"]
}
function testTimestampToken() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body>
                <person>
                    <name>John Doe</name>
                    <age>30</age>
                    <address>
                        <city>New York</city>
                        <country>USA</country>
                    </address>
                </person>
            </soap:Body>
        </soap:Envelope>`;

    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;
    xml securedEnvelope = check applyTimestampToken(envelope = envelope, timeToLive = 600);
    string envelopeString = (securedEnvelope/<soap:Header>/*).toString();
    assertTimestampToken(envelopeString);
}

@test:Config {
    groups: ["timestamp_token", "error"]
}
function testTimestampTokenWithIncorrectTimeError() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body>
                <person>
                    <name>John Doe</name>
                    <age>30</age>
                    <address>
                        <city>New York</city>
                        <country>USA</country>
                    </address>
                </person>
            </soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;
    TimestampTokenConfig tsRecord = {
        timeToLive: -1
    };
    xml|Error generateEnvelope = applyTimestampToken(envelope, tsRecord);
    test:assertTrue(generateEnvelope is Error);
    if generateEnvelope is Error {
        test:assertEquals(generateEnvelope.message(), "Invalid value for `timeToLive`");
    }
}

@test:Config {
    groups: ["username_token", "password_text"]
}
function testUsernameTokenWithPlaintextPassword() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body>
                <person>
                    <name>John Doe</name>
                    <age>30</age>
                    <address>
                        <city>New York</city>
                        <country>USA</country>
                    </address>
                </person>
            </soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;

    UsernameTokenConfig utRecord = {
        username: USERNAME,
        password: PASSWORD,
        passwordType: TEXT
    };
    xml securedEnvelope = check applyUsernameToken(envelope, utRecord);
    string envelopeString = securedEnvelope.toString();
    assertUsernameToken(envelopeString, TEXT);
}

@test:Config {
    groups: ["username_token", "password_text", "derived_key"]
}
function testUsernameTokenWithPlaintextPasswordWithDerivedKey() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body>
                <person>
                    <name>John Doe</name>
                    <age>30</age>
                    <address>
                        <city>New York</city>
                        <country>USA</country>
                    </address>
                </person>
            </soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;
    UsernameTokenConfig utRecord = {
        username: USERNAME,
        password: PASSWORD,
        passwordType: DERIVED_KEY_TEXT
    };
    xml securedEnvelope = check applyUsernameToken(envelope, utRecord);
    string envelopeString = securedEnvelope.toString();

    assertUsernameToken(envelopeString, DERIVED_KEY_TEXT);
}

@test:Config {
    groups: ["username_token", "password_digest"]
}
function testUsernameTokenWithHashedPasword() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body>
                <person>
                    <name>John Doe</name>
                    <age>30</age>
                    <address>
                        <city>New York</city>
                        <country>USA</country>
                    </address>
                </person>
            </soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;
    UsernameTokenConfig utRecord = {
        username: USERNAME,
        password: PASSWORD,
        passwordType: DIGEST
    };
    xml securedEnvelope = check applyUsernameToken(envelope, utRecord);
    string envelopeString = securedEnvelope.toString();

    assertUsernameToken(envelopeString, DIGEST);
}

@test:Config {
    groups: ["username_token", "password_digest", "derived_key"]
}
function testUsernameTokenWithHashedPaswordWithDerivedKey() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body>
                <person>
                    <name>John Doe</name>
                    <age>30</age>
                    <address>
                        <city>New York</city>
                        <country>USA</country>
                    </address>
                </person>
            </soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;
    UsernameTokenConfig utRecord = {
        username: USERNAME,
        password: PASSWORD,
        passwordType: DERIVED_KEY_DIGEST
    };
    xml securedEnvelope = check applyUsernameToken(envelope, utRecord);
    string envelopeString = securedEnvelope.toString();

    assertUsernameToken(envelopeString, DERIVED_KEY_DIGEST);
}

@test:Config {
    groups: ["username_token", "signature", "symmetric_binding"]
}
function testSymmetricBindingPolicyWithSignatureOnly() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body>
                <person>
                    <name>John Doe</name>
                    <age>30</age>
                    <address>
                        <city>New York</city>
                        <country>USA</country>
                    </address>
                </person>
            </soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;

    SymmetricBindingConfig symmetricBinding = {
        signatureAlgorithm: RSA_SHA256,
        symmetricKey: symmetricKey,
        servicePublicKey: serverPublicKey
    };

    xml securedEnvelope = check applySymmetricBinding(envelope, false, symmetricBinding);
    string envelopeString = securedEnvelope.toString();
    byte[] signedData = check getSignatureData(securedEnvelope);

    boolean validity = check crypto:verifyRsaSha256Signature((envelope/<soap:Body>/*).toString().toBytes(),
                                                             signedData, publicKey);
    test:assertTrue(validity);

    assertEncryptedSymmetricKey(envelopeString);
    assertSignatureWithoutX509(envelopeString);
}

@test:Config {
    groups: ["username_token", "signature", "symmetric_binding"]
}
function testSymmetricBindingPolicyEncryptionOnly() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body><person></person></soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;

    SymmetricBindingConfig symmetricBinding = {
        encryptionAlgorithm: RSA_ECB,
        symmetricKey: symmetricKey,
        servicePublicKey: serverPublicKey
    };

    xml securedEnvelope = check applySymmetricBinding(envelope, false, symmetricBinding);
    string envelopeString = securedEnvelope.toString();

    byte[] encData = check getEncryptedData(securedEnvelope);
    byte[] decryptDataResult = check crypto:decryptRsaEcb(encData, publicKey);
    test:assertEquals((envelope/<soap:Body>/*).toString(), check string:fromBytes(decryptDataResult));

    assertEncryptedSymmetricKey(envelopeString);
    assertEncryptedPart(envelopeString);
}

@test:Config {
    groups: ["username_token", "signature", "symmetric_binding"]
}
function testSymmetricBindingWithSignatureAndEncryption() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body><person></person></soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;

    SymmetricBindingConfig symmetricBinding = {
        signatureAlgorithm: RSA_SHA256,
        encryptionAlgorithm: RSA_ECB,
        symmetricKey: symmetricKey,
        servicePublicKey: serverPublicKey
    };
    xml securedEnvelope = check applySymmetricBinding(envelope, false, symmetricBinding);
    string envelopeString = securedEnvelope.toString();

    byte[] signedData = check getSignatureData(securedEnvelope);

    boolean validity = check crypto:verifyRsaSha256Signature((envelope/<soap:Body>/*).toString().toBytes(),
                                                             signedData, publicKey);
    test:assertTrue(validity);

    byte[] encData = check getEncryptedData(securedEnvelope);
    byte[] decryptDataResult = check crypto:decryptRsaEcb(encData, publicKey);
    test:assertEquals((envelope/<soap:Body>/*).toString(), check string:fromBytes(decryptDataResult));

    assertEncryptedSymmetricKey(envelopeString);
    assertSignatureWithoutX509(envelopeString);
    assertEncryptedPart(envelopeString);
}

@test:Config {
    groups: ["username_token", "signature", "symmetric_binding"]
}
function testSymmetricBindingPolicyWithX509SignatureAndEncryption() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body><person></person></soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;

    SymmetricBindingConfig symmetricBinding = {
        signatureAlgorithm: RSA_SHA256,
        encryptionAlgorithm: RSA_ECB,
        symmetricKey: symmetricKey,
        servicePublicKey: serverPublicKey,
        x509Token: X509_PUBLIC_CERT_PATH_2
    };

    xml securedEnvelope = check applySymmetricBinding(envelope, false, symmetricBinding);
    string envelopeString = securedEnvelope.toString();

    byte[] signedData = check getSignatureData(securedEnvelope);

    boolean validity = check crypto:verifyRsaSha256Signature((envelope/<soap:Body>/*).toString().toBytes(),
                                                             signedData, publicKey);
    test:assertTrue(validity);

    byte[] encData = check getEncryptedData(securedEnvelope);
    byte[] decryptDataResult = check crypto:decryptRsaEcb(encData, publicKey);
    test:assertEquals((envelope/<soap:Body>/*).toString(), check string:fromBytes(decryptDataResult));

    assertEncryptedSymmetricKey(envelopeString);
    assertSignatureWithX509(envelopeString);
    assertEncryptedPart(envelopeString);
}

@test:Config {
    groups: ["username_token", "signature", "symmetric_binding"]
}
function testUsernameTokenWithSymmetricBinding() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body><person></person></soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;

    UsernameTokenConfig utRecord = {
        username: USERNAME,
        password: PASSWORD,
        passwordType: DIGEST
    };

    envelope = check applyUsernameToken(envelope, utRecord);

    SymmetricBindingConfig symmetricBinding = {
        signatureAlgorithm: RSA_SHA256,
        encryptionAlgorithm: RSA_ECB,
        symmetricKey: symmetricKey,
        servicePublicKey: serverPublicKey
    };
    xml securedEnvelope = check applySymmetricBinding(envelope, false, symmetricBinding);
    string envelopeString = securedEnvelope.toString();

    byte[] signedData = check getSignatureData(securedEnvelope);

    boolean validity = check crypto:verifyRsaSha256Signature((envelope/<soap:Body>/*).toString().toBytes(),
                                                             signedData, publicKey);
    test:assertTrue(validity);

    byte[] encData = check getEncryptedData(securedEnvelope);
    byte[] decryptDataResult = check crypto:decryptRsaEcb(encData, publicKey);
    test:assertEquals((envelope/<soap:Body>/*).toString(), check string:fromBytes(decryptDataResult));

    assertEncryptedSymmetricKey(envelopeString);
    assertUsernameToken(envelopeString, DIGEST);
    assertSignatureWithoutX509(envelopeString);
    assertEncryptedPart(envelopeString);
}

@test:Config {
    groups: ["username_token", "signature", "symmetric_binding"]
}
function testUsernameTokenTimestampWithSymmetricBindingAndX509Token() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body><person></person></soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;

    UsernameTokenConfig utRecord = {
        username: USERNAME,
        password: PASSWORD,
        passwordType: DIGEST
    };

    envelope = check applyUsernameToken(envelope, utRecord);
    envelope = check applyTimestampToken(envelope = envelope, timeToLive = 600);

    crypto:KeyStore serverKeyStore = {
        path: X509_KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PublicKey serverPublicKey = check crypto:decodeRsaPublicKeyFromTrustStore(serverKeyStore, KEY_ALIAS);

    crypto:KeyStore keyStore = {
        path: KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey symmetricKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

    SymmetricBindingConfig symmetricBinding = {
        signatureAlgorithm: RSA_SHA256,
        encryptionAlgorithm: RSA_ECB,
        symmetricKey: symmetricKey,
        servicePublicKey: serverPublicKey,
        x509Token: X509_PUBLIC_CERT_PATH_2
    };

    xml securedEnvelope = check applySymmetricBinding(envelope, false, symmetricBinding);
    string envelopeString = securedEnvelope.toString();
    byte[] signedData = check getSignatureData(securedEnvelope);

    boolean validity = check crypto:verifyRsaSha256Signature((envelope/<soap:Body>/*).toString().toBytes(),
                                                             signedData, publicKey);
    test:assertTrue(validity);

    byte[] encData = check getEncryptedData(securedEnvelope);
    byte[] decryptDataResult = check crypto:decryptRsaEcb(encData, publicKey);
    test:assertEquals((envelope/<soap:Body>/*).toString(), check string:fromBytes(decryptDataResult));

    assertEncryptedSymmetricKey(envelopeString);
    assertUsernameToken(envelopeString, DIGEST);
    assertTimestampToken(envelopeString);
    assertSignatureWithoutX509(envelopeString);
    assertEncryptedPart(envelopeString);
}

@test:Config {
    groups: ["username_token", "signature", "symmetric_binding", "outbound_config"]
}
function testSymmetricBindingWithOutboundConfig() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body><person></person></soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;

    crypto:KeyStore serverKeyStore = {
        path: X509_KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PublicKey serverPublicKey = check crypto:decodeRsaPublicKeyFromTrustStore(serverKeyStore, KEY_ALIAS);

    crypto:KeyStore keyStore = {
        path: KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey symmetricKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

    SymmetricBindingConfig symmetricBinding = {
        signatureAlgorithm: RSA_SHA256,
        encryptionAlgorithm: RSA_ECB,
        symmetricKey: symmetricKey,
        servicePublicKey: serverPublicKey
    };

    xml securedEnvelope = check applySymmetricBinding(envelope, false, symmetricBinding);
    string envelopeString = securedEnvelope.toString();

    InboundSecurityConfig outboundConfig = {
        verificationKey: publicKey,
        signatureAlgorithm: RSA_SHA256,
        decryptionAlgorithm: RSA_ECB,
        decryptionKey: publicKey
    };

    crypto:PrivateKey|crypto:PublicKey? privateKey = outboundConfig.decryptionKey;
    if privateKey is crypto:PrivateKey|crypto:PublicKey {
        byte[] encData = check getEncryptedData(securedEnvelope);
        byte[] decryptDataResult = check crypto:decryptRsaEcb(encData, privateKey);
        string decryptedBody = "<soap:Body >" + check string:fromBytes(decryptDataResult) + "</soap:Body>";
        envelopeString = regexp:replace(re `<soap:Body .*>.*</soap:Body>`, envelopeString, decryptedBody);
        securedEnvelope = check xml:fromString(envelopeString);
    }
    byte[] signedData = check getSignatureData(securedEnvelope);

    boolean validity = check crypto:verifyRsaSha256Signature((envelope/<soap:Body>/*).toString().toBytes(),
                                                             signedData, publicKey);
    test:assertTrue(validity);
}

@test:Config {
    groups: ["username_token", "signature", "asymmetric_binding", "new"]
}
function testAsymmetricBindingWithSignatureRsaSha256() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body><person></person></soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;

    AsymmetricConfig asymmetricConfig = {
        signatureConfig: {
            keystore: {
                path: KEY_STORE_PATH_2,
                password: PASSWORD
            },
            privateKeyAlias: ALIAS, 
            privateKeyPassword: PASSWORD,
            signatureAlgorithm: RSA_SHA256,
            canonicalizationAlgorithm: C14N_EXCL_OMIT_COMMENTS, 
            digestAlgorithm: SHA256
        }
    };
    xml securedEnvelope = check applyAsymmetricConfigurations(envelope, false, asymmetricConfig);
    InboundConfig inboundConfig = {
        keystore: {
            path: KEY_STORE_PATH_2,
            password: PASSWORD
        }
    };
    boolean validity = check verifySignature(securedEnvelope, inboundConfig);
    test:assertTrue(validity is true);
}

@test:Config {
    groups: ["username_token", "signature", "asymmetric_binding", "new"]
}
function testUsernameTokenWithAsymmetricBinding() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body><person></person></soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;

    UsernameTokenConfig utRecord = {
        username: USERNAME,
        password: PASSWORD,
        passwordType: DIGEST
    };
    envelope = check applyUsernameToken(envelope, utRecord);

    AsymmetricConfig asymmetricConfig = {
        signatureConfig: {
            keystore: {
                path: KEY_STORE_PATH_2,
                password: PASSWORD
            },
            privateKeyAlias: ALIAS, 
            privateKeyPassword: PASSWORD,
            signatureAlgorithm: RSA_SHA256,
            canonicalizationAlgorithm: C14N_EXCL_OMIT_COMMENTS, 
            digestAlgorithm: SHA256
        }
    };
    xml securedEnvelope = check applyAsymmetricConfigurations(envelope, false, asymmetricConfig);
    InboundConfig inboundConfig = {
        keystore: {
            path: KEY_STORE_PATH_2,
            password: PASSWORD
        }
    };
    boolean validity = check verifySignature(securedEnvelope, inboundConfig);
    assertUsernameToken(securedEnvelope.toString(), DIGEST);
    test:assertTrue(validity is true);
}

@test:Config {
    groups: ["username_token", "signature", "asymmetric_binding", "new"]
}
function testUsernameTokenTimestampWithAsymmetricBindingAndX509() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body><person></person></soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;

    UsernameTokenConfig utRecord = {
        username: USERNAME,
        password: PASSWORD,
        passwordType: DIGEST
    };
    envelope = check applyUsernameToken(envelope, utRecord);
    envelope = check applyTimestampToken(envelope = envelope, timeToLive = 600);

    AsymmetricConfig asymmetricConfig = {
        signatureConfig: {
            keystore: {
                path: KEY_STORE_PATH_2,
                password: PASSWORD
            },
            privateKeyAlias: ALIAS, 
            privateKeyPassword: PASSWORD,
            signatureAlgorithm: RSA_SHA256,
            canonicalizationAlgorithm: C14N_EXCL_OMIT_COMMENTS, 
            digestAlgorithm: SHA256
        }
    };
    xml securedEnvelope = check applyAsymmetricConfigurations(envelope, false, asymmetricConfig);
    InboundConfig inboundConfig = {
        keystore: {
            path: KEY_STORE_PATH_2,
            password: PASSWORD
        }
    };
    boolean validity = check verifySignature(securedEnvelope, inboundConfig);
    assertUsernameToken(securedEnvelope.toString(), DIGEST);
    assertTimestampToken(securedEnvelope.toString());
    test:assertTrue(validity is true);
}

@test:Config {
    groups: ["username_token", "signature", "asymmetric_binding", "new"]
}
function testAsymmetricBindingWithSignatureWithRsaSha1() returns error? {
    xml envelope =
    xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body><person></person></soap:Body>
        </soap:Envelope>`;
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;

    AsymmetricConfig asymmetricConfig = {
        signatureConfig: {
            keystore: {
                path: KEY_STORE_PATH_2,
                password: PASSWORD
            },
            privateKeyAlias: ALIAS, 
            privateKeyPassword: PASSWORD,
            signatureAlgorithm: RSA_SHA1,
            canonicalizationAlgorithm: C14N_EXCL_OMIT_COMMENTS, 
            digestAlgorithm: SHA1
        }
    };
    xml securedEnvelope = check applyAsymmetricConfigurations(envelope, false, asymmetricConfig);
    InboundConfig inboundConfig = {
        keystore: {
            path: KEY_STORE_PATH_2,
            password: PASSWORD
        }
    };
    boolean validity = check verifySignature(securedEnvelope, inboundConfig);
    test:assertTrue(validity is true);
}

@test:Config {
    groups: ["username_token", "signature", "asymmetric_binding", "new"]
}
function testAsymmetricBindingWithSignatureWithRsaSha512() returns error? {
    xml envelope = check io:fileReadXml(SOAP_ENVELOPE_PATH);
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;

    AsymmetricConfig asymmetricConfig = {
        signatureConfig: {
            keystore: {
                path: KEY_STORE_PATH_2,
                password: PASSWORD
            },
            privateKeyAlias: ALIAS, 
            privateKeyPassword: PASSWORD,
            signatureAlgorithm: RSA_SHA512,
            canonicalizationAlgorithm: C14N_EXCL_OMIT_COMMENTS, 
            digestAlgorithm: SHA512
        }
    };
    xml securedEnvelope = check applyAsymmetricConfigurations(envelope, false, asymmetricConfig);
    string envelopeString = securedEnvelope.toString();
    InboundConfig inboundConfig = {
        keystore: {
            path: KEY_STORE_PATH_2,
            password: PASSWORD
        }
    };
    boolean validity = check verifySignature(securedEnvelope, inboundConfig);
    test:assertTrue(validity is true);
    assertSignatureWithoutX509(envelopeString);
}

@test:Config {
    groups: ["username_token", "signature", "symmetric_binding", "new"]
}
function testAsymmetricBindingPolicyWithSignatureAndEncryption() returns error? {
    xml envelope = check io:fileReadXml(SOAP_ENVELOPE_PATH);
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;

    AsymmetricConfig asymmetricConfig = {
        signatureConfig: {
            keystore: {
                path: KEY_STORE_PATH_2,
                password: PASSWORD
            },
            privateKeyAlias: ALIAS, 
            privateKeyPassword: PASSWORD,
            signatureAlgorithm: RSA_SHA512,
            canonicalizationAlgorithm: C14N_EXCL_OMIT_COMMENTS, 
            digestAlgorithm: SHA512
        },
        encryptionConfig: {
            keystore: {
                path: KEY_STORE_PATH_2,
                password: PASSWORD
            },
            publicKeyAlias: ALIAS
        }
    };
    xml securedEnvelope = check applyAsymmetricConfigurations(envelope, false, asymmetricConfig);
    string envelopeString = securedEnvelope.toString();
    InboundConfig inboundConfig = {
        keystore: {
            path: KEY_STORE_PATH_2,
            password: PASSWORD
        }
    };
    Document doc = check decryptEnvelope(securedEnvelope, inboundConfig);
    boolean validity = check verifySignature(doc, inboundConfig);
    test:assertTrue(validity is true);
    assertEncryptedSymmetricKey(envelopeString);
    assertEncryptedPart(envelopeString);
}

@test:Config {
    groups: ["username_token", "signature", "symmetric_binding", "new"]
}
function testAsymmetricBindingPolicyWithEncryption() returns error? {
    xml envelope = check io:fileReadXml(SOAP_ENVELOPE_PATH);
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;

    AsymmetricConfig asymmetricConfig = {
        encryptionConfig: {
            keystore: {
                path: KEY_STORE_PATH_2,
                password: PASSWORD
            },
            publicKeyAlias: ALIAS
        }
    };
    xml securedEnvelope = check applyAsymmetricConfigurations(envelope, false, asymmetricConfig);
    string envelopeString = securedEnvelope.toString();
    InboundConfig inboundConfig = {
        keystore: {
            path: KEY_STORE_PATH_2,
            password: PASSWORD
        }
    };
    assertEncryptedSymmetricKey(envelopeString);
    assertEncryptedPart(envelopeString);
    Document doc = check decryptEnvelope(securedEnvelope, inboundConfig);
    xml body = (check doc.getEnvelope())/<soap:Body>;
    test:assertEquals(body, envelope/<soap:Body>);
}
