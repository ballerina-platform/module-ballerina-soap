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
    RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
}

public enum CanonicalizationAlgorithm {
    C14N_OMIT_COMMENTS = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    C14N_WITH_COMMENTS = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
    C14N_EXCL_OMIT_COMMENTS = "http://www.w3.org/2001/10/xml-exc-c14n#",
    C14N_EXCL_WITH_COMMENTS = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
}

public enum DigestAlgorithm {
    SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1",
    SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256",
    SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384",
    SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"
}

public enum EncryptionAlgorithm {
    TRIPLE_DES = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
    AES_128 = "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
    AES_256 = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
}
