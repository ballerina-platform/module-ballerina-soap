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
import ballerina/regex;

xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;
xmlns "http://www.w3.org/2000/09/xmldsig#" as ds;

isolated function addSecurityHeader(Document document) returns WSSecurityHeader|Error {
    WSSecurityHeader wsSecHeader = check new (document);
    Error? insertHeader = wsSecHeader.insertSecHeader();
    if insertHeader is () {
        return wsSecHeader;
    }
    return insertHeader;
}

public isolated function decryptData(byte[] cipherText, EncryptionAlgorithm encryptionAlgorithm,
                            crypto:PublicKey|crypto:PrivateKey key) returns byte[]|Error {
    Encryption encrypt = check new ();
    return encrypt.decryptData(cipherText, encryptionAlgorithm, key);
}

public isolated function verifyData(byte[] data, byte[] signature, crypto:PublicKey publicKey,
                           SignatureAlgorithm signatureAlgorithm) returns boolean|Error {
    Signature sign = check new ();
    return sign.verifySignature(data, signature, publicKey, signatureAlgorithm);
}

isolated function addSignature(Signature sign, string signatureAlgorithm, byte[] signature) returns Signature|Error {
    sign.setSignatureAlgorithm(signatureAlgorithm);
    sign.setSignatureValue(signature);
    return sign;
}

isolated function addEncryption(Encryption encrypt, string encryptionAlgorithm, byte[] encryption) returns Encryption|Error {
    encrypt.setEncryptionAlgorithm(encryptionAlgorithm);
    encrypt.setEncryptedData(encryption);
    return encrypt;
}

isolated function applyEncryptedKey(string envelopeString, crypto:PrivateKey symmetricKey, crypto:PublicKey encryptKey)
    returns string|Error {
    string securedEnvelope = envelopeString;
    do {
        Encryption encryption = check new ();
        byte[] encryptedKey = check crypto:encryptRsaEcb(symmetricKey.toBalString().toBytes(), encryptKey);
        string encryptedKeyElements = check encryption.getEncryptedKeyElements(encryptedKey);
        string replace = regex:replace(encryptedKeyElements, string `<?.*?><`, "<");
        string:RegExp securityToken = 
            re `<wsse:SecurityTokenReference.*><wsse:Reference URI="#null"/></wsse:SecurityTokenReference>`;
        if securedEnvelope.includesMatch(securityToken) {
            securedEnvelope = regex:replace(securedEnvelope, securityToken.toString(), replace);
        }
        else if securedEnvelope.includesMatch(re `<wsse:SecurityTokenReference .*/>`) {
            securedEnvelope = regex:replace(securedEnvelope, string `<wsse:SecurityTokenReference .*/>`, replace);
        }
        return securedEnvelope;
    } on fail var e {
        return error Error(e.message());
    }
}

isolated function convertStringToXml(string envelope) returns xml|Error {
    do {
        return check xml:fromString(regex:replace(envelope, string `<?.*?><`, "<"));
    } on fail var e {
        return error Error(e.message());
    }
}

# Returns the encrypted data of the SOAP envelope.
#
# + envelope - The SOAP envelope
# + return - A `byte[]` if the encrypted data is successfully decoded or else `wssec:Error`
public isolated function getEncryptedData(xml envelope) returns byte[]|Error {
    Document document = check new (envelope);
    return document.getEncryptedData();
}

# Returns the signed data of the SOAP envelope.
#
# + envelope - The SOAP envelope
# + return - A `byte[]` if the signed data is successfully decoded or else `wssec:Error`
public isolated function getSignatureData(xml envelope) returns byte[]|Error {
    Document document = check new (envelope);
    return document.getSignatureData();
}

# Apply timestamp token security policy to the SOAP envelope.
#
# + envelope - The SOAP envelope
# + timestampToken - The `TSRecord` record with the required parameters
# + return - A `xml` type of SOAP envelope if the security binding is successfully added or else `wssec:Error`
public isolated function applyTimestampToken(xml envelope, *TimestampTokenConfig timestampToken) returns xml|Error {
    if timestampToken.timeToLive <= 0 {
        return error Error("Invalid value for `timeToLive`");
    }
    Document document = check new (envelope);
    WSSecurityHeader wsSecurityHeader = check addSecurityHeader(document);
    WsSecurity wsSecurity = new;
    string securedEnvelope = check wsSecurity.applyTimestampPolicy(wsSecurityHeader, timestampToken.timeToLive);
    return convertStringToXml(securedEnvelope);
}

# Apply username token security policy to the SOAP envelope.
#
# + envelope - The SOAP envelope
# + usernameToken - The `UsernameTokenConfig` record with the required parameters
# + return - A `xml` type of SOAP envelope if the security binding is successfully added or else `wssec:Error`
public isolated function applyUsernameToken(xml envelope, *UsernameTokenConfig usernameToken) returns xml|Error {
    Document document = check new (envelope);
    WSSecurityHeader wsSecurityHeader = check addSecurityHeader(document);
    WsSecurity wsSecurity = new;
    string securedEnvelope = check wsSecurity
        .applyUsernameTokenPolicy(wsSecurityHeader, usernameToken.username, usernameToken.password,
                                  usernameToken.passwordType);
    return convertStringToXml(securedEnvelope);
}

# Apply symmetric binding security policy with username token to the SOAP envelope.
#
# + envelope - The SOAP envelope
# + symmetricBinding - The `SymmetricBindingConfig` record with the required parameters
# + return - A `xml` type of SOAP envelope if the security binding is successfully added or else `wssec:Error`
public isolated function applySymmetricBinding(xml envelope, *SymmetricBindingConfig symmetricBinding) returns xml|Error {
    Document document = check new (envelope);
    WSSecurityHeader wsSecurityHeader = check addSecurityHeader(document);
    string securedEnvelope = envelope.toBalString();
    if symmetricBinding.signatureAlgorithm !is () {
        Signature signature = check new ();
        byte[] signedData = check signature.signData((envelope/<soap:Body>/*).toString(),
                                                     <SignatureAlgorithm>symmetricBinding.signatureAlgorithm,
                                                     symmetricBinding.symmetricKey);
        Signature signatureResult = check addSignature(signature,
                                                       <SignatureAlgorithm>symmetricBinding.signatureAlgorithm,
                                                       signedData);
        WsSecurity wsSecurity = new;
        securedEnvelope = check wsSecurity.applySignatureOnlyPolicy(wsSecurityHeader, signatureResult,
                                                                    symmetricBinding.x509Token);
    }
    if symmetricBinding.encryptionAlgorithm !is () {
        Encryption encryption = check new ();
        byte[] encryptData = check encryption.encryptData((envelope/<soap:Body>/*).toString(),
                                                          <EncryptionAlgorithm>symmetricBinding.encryptionAlgorithm,
                                                          symmetricBinding.symmetricKey);
        Encryption encryptionResult = check addEncryption(encryption,
                                                          <EncryptionAlgorithm>symmetricBinding.encryptionAlgorithm,
                                                          encryptData);
        WsSecurity wsSecurity = new;
        securedEnvelope = check wsSecurity.applyEncryptionOnlyPolicy(wsSecurityHeader, encryptionResult);
    }
    securedEnvelope = check applyEncryptedKey(securedEnvelope, symmetricBinding.symmetricKey,
                                              symmetricBinding.servicePublicKey);
    return convertStringToXml(securedEnvelope);
}

# Apply asymmetric binding security policy with X509 token to the SOAP envelope.
#
# + envelope - The SOAP envelope
# + asymmetricBinding - The `AsymmetricBindingConfig` record with the required parameters
# + return - A `xml` type of SOAP envelope if the security binding is successfully added or else `wssec:Error`
public isolated function applyAsymmetricBinding(xml envelope, *AsymmetricBindingConfig asymmetricBinding) returns xml|Error {
    Document document = check new (envelope);
    WSSecurityHeader wsSecurityHeader = check addSecurityHeader(document);
    string securedEnvelope = envelope.toBalString();
    if asymmetricBinding.signatureAlgorithm !is () {
        Signature signature = check new ();
        byte[] signedData = check signature.signData((envelope/<soap:Body>/*).toString(),
                                                     <SignatureAlgorithm>asymmetricBinding.signatureAlgorithm,
                                                     <crypto:PrivateKey>asymmetricBinding.signatureKey);
        Signature signatureResult = check addSignature(signature,
                                                       <SignatureAlgorithm>asymmetricBinding.signatureAlgorithm,
                                                       signedData);
        WsSecurity wsSecurity = new;
        securedEnvelope = check wsSecurity.applySignatureOnlyPolicy(wsSecurityHeader, signatureResult,
                                                                    asymmetricBinding.x509Token);
    }
    if asymmetricBinding.encryptionAlgorithm !is () {
        Encryption encryption = check new ();
        byte[] encryptData = check encryption.encryptData((envelope/<soap:Body>/*).toString(),
                                                          <EncryptionAlgorithm>asymmetricBinding.encryptionAlgorithm,
                                                          <crypto:PublicKey>asymmetricBinding.encryptionKey);
        Encryption encryptionResult = check addEncryption(encryption,
                                                          <EncryptionAlgorithm>asymmetricBinding.encryptionAlgorithm,
                                                          encryptData);
        WsSecurity wsSecurity = new;
        securedEnvelope = check wsSecurity.applyEncryptionOnlyPolicy(wsSecurityHeader, encryptionResult);
    }
    return convertStringToXml(securedEnvelope);
}
