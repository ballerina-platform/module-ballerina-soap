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

# Represents the record for Username Token with Asymmetric Binding policy.
#
# + signatureKey - The private key to sign the SOAP envelope
# + encryptionKey - The public key to encrypt the SOAP body
# + signatureAlgorithm - The algorithm to sign the SOAP envelope
# + encryptionAlgorithm - The algorithm to encrypt the SOAP body
# + x509Token - field description
public type AsymmetricBindingConfig record {|
    crypto:PrivateKey signatureKey?;
    crypto:PublicKey encryptionKey?;
    SignatureAlgorithm signatureAlgorithm?;
    EncryptionAlgorithm encryptionAlgorithm?;
    string x509Token?;
|};

# Represents the record for Transport Binding policy.
# + protocol - Protocol of the endpoint
public type TransportBindingConfig "TransportBinding";

