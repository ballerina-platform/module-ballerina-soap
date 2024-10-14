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
import ballerina/lang.regexp;

xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap11;
xmlns "http://www.w3.org/2003/05/soap-envelope" as soap12;
xmlns "http://www.w3.org/2000/09/xmldsig#" as ds;


public isolated function verifySignature(xml|Document soapEnvelope, InboundConfig config) returns boolean|error {
    WsSecurity wsSecurity = new;
    Document document;
    if soapEnvelope is xml {
        document = check new (soapEnvelope);
    } else {
        document = soapEnvelope;
    }
    return check wsSecurity.verifySignature(document, config);
}

public isolated function decryptEnvelope(xml soapEnvelope, InboundConfig config) returns Document|error {
    WsSecurity wsSecurity = new;
    Document document = check new (soapEnvelope);
    return check wsSecurity.decryptEnvelope(document, config);
}

isolated function addSecurityHeader(Document document) returns WSSecurityHeader|Error {
    WSSecurityHeader wsSecHeader = check new (document);
    Error? insertHeader = wsSecHeader.insertSecHeader();
    return insertHeader ?: wsSecHeader;
}

public isolated function verifyData(byte[] data, byte[] signature, crypto:PublicKey publicKey,
                                    SignatureAlgorithm signatureAlgorithm) returns Error? {
    Signature sign = check new ();
    boolean verifySignature = check sign.verifySignature(data, signature, publicKey, signatureAlgorithm);
    if !verifySignature {
        return error Error("Signature verification of the SOAP envelope has been failed");
    }
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
        string replace = regexp:replace(re `<?.*?><`, encryptedKeyElements, "<");
        string:RegExp securityToken = 
            re `<wsse:SecurityTokenReference.*><wsse:Reference URI="#null"/></wsse:SecurityTokenReference>`;
        if securedEnvelope.includesMatch(securityToken) {
            securedEnvelope = regexp:replace(securityToken, securedEnvelope, replace);
        }
        else if securedEnvelope.includesMatch(re `<wsse:SecurityTokenReference .*/>`) {
            securedEnvelope = regexp:replace(re `<wsse:SecurityTokenReference .*/>`, securedEnvelope, replace);
        }
        return securedEnvelope;
    } on fail error encryptionError {
        return error Error("Error occurred while applying the encrypted key to the envelope", encryptionError);
    }
}

isolated function convertStringToXml(string envelope) returns xml|Error {
    xml|error xmlEnvelope = xml:fromString(regexp:replace(re `<?.*?><`, envelope, "<"));
    if xmlEnvelope is error {
        return error Error(xmlEnvelope.message());
    }
    return xmlEnvelope;
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
# + soap12 - A boolean flag. Set to `true` for SOAP 1.2, or `false` for SOAP 1.1.
# + symmetricBinding - The `SymmetricBindingConfig` record with the required parameters
# + return - A `xml` type of SOAP envelope if the security binding is successfully added or else `wssec:Error`
public isolated function applySymmetricBinding(xml envelope, boolean soap12, *SymmetricBindingConfig symmetricBinding)
    returns xml|crypto:Error|Error {
    Document document = check new (envelope);
    WSSecurityHeader wsSecurityHeader = check addSecurityHeader(document);
    string securedEnvelope = envelope.toBalString();
    SignatureAlgorithm? signatureAlgorithm = symmetricBinding.signatureAlgorithm;
    EncryptionAlgorithm? encryptionAlgorithm = symmetricBinding.encryptionAlgorithm;
    if signatureAlgorithm is SignatureAlgorithm {
        Signature signature = check new ();
        byte[] signedData;
        if soap12 {
            signedData = check signature.signData((envelope/<soap12:Body>/*).toString(), signatureAlgorithm,
                                                  symmetricBinding.symmetricKey);
        } else {
            signedData = check signature.signData((envelope/<soap11:Body>/*).toString(), signatureAlgorithm,
                                                  symmetricBinding.symmetricKey);
        }
        
        Signature signatureResult = check addSignature(signature, signatureAlgorithm, signedData);
        WsSecurity wsSecurity = new;
        securedEnvelope = check wsSecurity.applySignatureOnlyPolicy(wsSecurityHeader, signatureResult,
                                                                    symmetricBinding.x509Token);
    }
    if encryptionAlgorithm is EncryptionAlgorithm {
        Encryption encryption = check new ();
        byte[] encryptData;
        if soap12 {
            encryptData = check crypto:encryptRsaEcb((envelope/<soap12:Body>/*).toString().toBytes(),
                                                     symmetricBinding.symmetricKey);
        } else {
            encryptData = check crypto:encryptRsaEcb((envelope/<soap11:Body>/*).toString().toBytes(),
                                                     symmetricBinding.symmetricKey);
        }
        Encryption encryptionResult = check addEncryption(encryption, encryptionAlgorithm, encryptData);
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
# + soap12 - A boolean flag. Set to `true` for SOAP 1.2, or `false` for SOAP 1.1.
# + asymmetricBinding - The `AsymmetricBindingConfig` record with the required parameters
# + return - A `xml` type of SOAP envelope if the security binding is successfully added or else `wssec:Error`
public isolated function applyAsymmetricConfigurations(xml envelope, boolean soap12, 
                                                       *AsymmetricBindingConfig asymmetricBinding)
    returns xml|Error {
    Document document = check new (envelope);
    WsSecurity wsSecurity = new;
    _ = check addSecurityHeader(document);
    SignatureConfig? signatureConfig = asymmetricBinding.signatureConfig;
    EncryptionConfig? encryptionConfig = asymmetricBinding.encryptionConfig;
    string securedEnvelope = envelope.toString();
    if signatureConfig !is () && encryptionConfig !is () {
        securedEnvelope = check wsSecurity
            .applySignatureAndEncryption(document, soap12, signatureConfig, encryptionConfig);
    } else if signatureConfig !is () {
        securedEnvelope = check wsSecurity.applySignatureOnly(document, soap12, signatureConfig);
    } else if encryptionConfig !is () {
        securedEnvelope = check wsSecurity.applyEncryptionOnly(document, soap12, encryptionConfig);
    }
    return convertStringToXml(securedEnvelope);
}

