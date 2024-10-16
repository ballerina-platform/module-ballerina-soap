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

package org.wssec;

public class Constants {

    private Constants() {
    }

    public static final int ITERATION = 1000;
    public static final String DIGEST = "DIGEST";
    public static final String DERIVED_KEY_TEXT = "DERIVED_KEY_TEXT";
    public static final String DERIVED_KEY_DIGEST = "DERIVED_KEY_DIGEST";
    public static final String PASSWORD = "password";
    public static final String NATIVE_SEC_HEADER = "nativeSecHeader";
    public static final String NATIVE_DOCUMENT = "nativeDocumentBuilder";
    public static final String NATIVE_SIGNATURE = "nativeSignature";
    public static final String NATIVE_ENCRYPTION = "nativeEncryption";
    public static final String SIGNATURE_VALUE_TAG = "ds:SignatureValue";
    public static final String SIGNATURE_METHOD_TAG = "ds:SignatureMethod";
    public static final String ALGORITHM = "Algorithm";
    public static final String KEY_INFO_TAG = "ds:KeyInfo";
    public static final String CIPHER_DATA_TAG = "xenc:CipherData";
    public static final String XML_ENC_NS = "xmlns:xenc";
    public static final String XML_DS_NS = "xmlns:ds";
    public static final String ENCRYPTED_KEY_TAG = "xenc:EncryptedKey";
    public static final String ENCRYPTION_METHOD_TAG = "xenc:EncryptionMethod";
    public static final String NAMESPACE_URI_ENC = "http://www.w3.org/2001/04/xmlenc#";
    public static final String CIPHER_VALUE_TAG = "CipherValue";
    public static final String X509 = "X.509";
    public static final String AES = "AES";
    public static final String EMPTY_XML_DOCUMENT_ERROR = "XML Document is empty";
    public static final String CRYPTO_PROVIDER_FIELD = "org.apache.ws.security.crypto.provider";
    public static final String CRYPTO_PROVIDER_VALUE = "org.apache.wss4j.common.crypto.Merlin";
    public static final String KEYSTORE = "keystore";
    public static final String DECRYPT_KEYSTORE = "decryptKeystore";
    public static final String SIGNATURE_KEYSTORE = "signatureKeystore";
    public static final String PATH = "path";
    public static final String DIGEST_ALGORITHM = "digestAlgorithm";
    public static final String CANONICALIZATION_ALGORITHM = "canonicalizationAlgorithm";
    public static final String SIGNATURE_ALGORITHM = "signatureAlgorithm";
    public static final String PRIVATE_KEY_PASSWORD = "privateKeyPassword";
    public static final String PRIVATE_KEY_ALIAS = "privateKeyAlias";
    public static final String PUBLIC_KEY_ALIAS = "publicKeyAlias";
    public static final String ENCRYPTION_ALGORITHM = "encryptionAlgorithm";
    public static final String KEYSTORE_PATH_FIELD = "org.apache.ws.security.crypto.merlin.keystore.file";
    public static final String KEYSTORE_PASSWORD_FIELD = "org.apache.ws.security.crypto.merlin.keystore.password";
}
