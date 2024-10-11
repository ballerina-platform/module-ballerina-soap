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

import soap.wssec;

# Represents enums for all the supported password types.
#
public enum PasswordType {
    TEXT,
    DIGEST,
    DERIVED_KEY_TEXT,
    DERIVED_KEY_DIGEST
}

# Represents enums for all the supported signature algorithms.
#
public enum SignatureAlgorithm {
    RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
    RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
}

# Represents enums for all the supported encryption algorithms.
#
public enum EncryptionAlgorithm {
    RSA_ECB = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
}

# Represents the record for outbound security configurations to verify and decrypt SOAP envelopes.
# 
# + verificationKey - The public key to verify the signature of the SOAP envelope
# + decryptionKey - The private key to decrypt the SOAP envelope
# + signatureAlgorithm - The algorithm to verify the SOAP envelope
# + decryptionAlgorithm - The algorithm to decrypt the SOAP body
public type InboundSecurityConfig record {
    *wssec:InboundSecurityConfig;
};

# Union type of all the inbound web service security configurations.
public type OutboundSecurityConfig wssec:OutboundSecurityConfig;
