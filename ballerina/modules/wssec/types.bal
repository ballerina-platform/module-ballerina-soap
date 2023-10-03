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

public enum PasswordType {
    TEXT,
    DIGEST,
    DERIVED_KEY_TEXT,
    DERIVED_KEY_DIGEST
}

public enum SignatureAlgorithm {
    RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
    RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
    HMAC_SHA1 = "http://www.w3.org/2000/09/xmldsig#hmac-sha1",
    HMAC_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
    HMAC_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384",
    HMAC_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512"
}

public enum EncryptionAlgorithm {
    RSA_ECB = "http://www.w3.org/2001/04/xmlenc#rsa-1_5",
    AES_128 = "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
    AES_192 = "http://www.w3.org/2001/04/xmlenc#aes192-cbc",
    AES_256 = "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
    AES_128_ECB = "http://www.w3.org/2009/xmlenc11#aes128-ecb",
    AES_192_ECB = "http://www.w3.org/2009/xmlenc11#aes192-ecb",
    AES_256_ECB = "http://www.w3.org/2009/xmlenc11#aes256-ecb",
    AES_128_GCM = "http://www.w3.org/2009/xmlenc11#aes128-gcm",
    AES_192_GCM = "http://www.w3.org/2009/xmlenc11#aes192-gcm",
    AES_256_GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
}
