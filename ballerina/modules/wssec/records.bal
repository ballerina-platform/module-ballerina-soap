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

# Union type of all the inbound web service security configurations.
public type OutboundSecurityConfig NoPolicy|UsernameTokenConfig|TimestampTokenConfig|SymmetricBindingConfig
    |TransportBindingConfig|AsymmetricBindingConfig;

# Represents the record for outbound security configurations to verify and decrypt SOAP envelopes.
#
# + verificationKey - The public key to verify the signature of the SOAP envelope
# + decryptionKey - The private key to decrypt the SOAP envelope
# + signatureAlgorithm - The algorithm to verify the SOAP envelope
# + decryptionAlgorithm - The algorithm to decrypt the SOAP body
public type InboundSecurityConfig record {|
    crypto:PublicKey verificationKey?;
    crypto:PrivateKey|crypto:PublicKey decryptionKey?;
    SignatureAlgorithm signatureAlgorithm?;
    EncryptionAlgorithm decryptionAlgorithm?;
|};

# Represents the record for Username Token policy.
#
# + username - The name of the user
# + password - The password of the user
# + passwordType - The password type of the username token
public type UsernameTokenConfig record {|
    string username;
    string password;
    PasswordType passwordType;
|};

# Represents the record for Timestamp Token policy.
#
# + timeToLive - The time to get expired
public type TimestampTokenConfig record {|
    int timeToLive = 300;
|};

# Represents the record for Symmetric Binding policy.
#
# + symmetricKey - The key to sign and encrypt the SOAP envelope 
# + servicePublicKey - The key to encrypt the symmetric key  
# + signatureAlgorithm - The algorithm to sign the SOAP envelope
# + encryptionAlgorithm - The algorithm to encrypt the SOAP envelope
# + x509Token - The path or token of the X509 certificate
public type SymmetricBindingConfig record {|
    crypto:PrivateKey symmetricKey;
    crypto:PublicKey servicePublicKey;
    SignatureAlgorithm signatureAlgorithm?;
    EncryptionAlgorithm encryptionAlgorithm?;
    string x509Token?;
|};

# Represents the record for Asymmetric Binding policy.
#
# + signatureConfig - Configuration for applying digital signatures
# + encryptionConfig - Configuration for applying encryption
# + x509Token - The path or token of the X509 certificate
public type AsymmetricBindingConfig record {|
    SignatureConfig signatureConfig?;
    EncryptionConfig encryptionConfig?;
    string x509Token?;
|};

# Represents the record for signature configurations.
#
# + keystore - The keystore to store the private key
# + privateKeyAlias - The alias of the private key
# + privateKeyPassword - The password of the private key
# + signatureAlgorithm - The algorithm to sign the SOAP envelope
# + canonicalizationAlgorithm - The algorithm to canonicalize the SOAP envelope
# + digestAlgorithm - The algorithm to digest the SOAP envelope
public type SignatureConfig record {|
    crypto:KeyStore keystore;
    string privateKeyAlias;
    string privateKeyPassword;
    SignatureAlgorithm signatureAlgorithm?;
    CanonicalizationAlgorithm canonicalizationAlgorithm = C14N_EXCL_OMIT_COMMENTS;
    DigestAlgorithm digestAlgorithm = SHA1;
|};

# Represents the record for encryption configurations.
#
# + keystore - The keystore to store the public key
# + publicKeyAlias - The alias of the public key
# + encryptionAlgorithm - The algorithm to encrypt the SOAP envelope
public type EncryptionConfig record {|
    crypto:KeyStore keystore;
    string publicKeyAlias;
    EncryptionAlgorithm encryptionAlgorithm?;
|};

# Represents the record for Transport Binding policy.
# + protocol - Protocol of the endpoint
public type TransportBindingConfig "TransportBinding";

# Represents the record to send SOAP envelopes with no security policy.
public type NoPolicy "NoPolicy";

# Represents the record for outbound security configurations to verify and decrypt SOAP envelopes.
#
# + decryptKeystore - The keystore to decrypt the SOAP envelope
# + signatureKeystore - The keystore to verify the signature of the SOAP envelope
public type InboundConfig record {|
    crypto:KeyStore decryptKeystore?;
    crypto:KeyStore signatureKeystore?;
|};
