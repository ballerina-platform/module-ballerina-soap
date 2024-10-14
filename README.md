# Ballerina SOAP Library

[![Build](https://github.com/ballerina-platform/module-ballerina-soap/actions/workflows/build-timestamped-master.yml/badge.svg)](https://github.com/ballerina-platform/module-ballerina-soap/actions/workflows/build-timestamped-master.yml)
[![codecov](https://codecov.io/gh/ballerina-platform/module-ballerina-soap/branch/master/graph/badge.svg)](https://codecov.io/gh/ballerina-platform/module-ballerina-soap)
[![Trivy](https://github.com/ballerina-platform/module-ballerina-soap/actions/workflows/trivy-scan.yml/badge.svg)](https://github.com/ballerina-platform/module-ballerina-soap/actions/workflows/trivy-scan.yml)
[![GraalVM Check](https://github.com/ballerina-platform/module-ballerina-soap/actions/workflows/build-with-bal-test-graalvm.yml/badge.svg)](https://github.com/ballerina-platform/module-ballerina-soap/actions/workflows/build-with-bal-test-graalvm.yml)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/ballerina-platform/module-ballerina-soap.svg)](https://github.com/ballerina-platform/module-ballerina-soap/commits/master)
[![Github issues](https://img.shields.io/github/issues/ballerina-platform/ballerina-standard-library/module/soap.svg?label=Open%20Issues)](https://github.com/ballerina-platform/ballerina-standard-library/labels/module%2Fsoap)
[![codecov](https://codecov.io/gh/ballerina-platform/module-ballerina-soap/branch/master/graph/badge.svg)](https://codecov.io/gh/ballerina-platform/module-ballerina-soap)

This module offers a set of APIs that facilitate the transmission of XML requests to a SOAP backend. It excels in managing security policies within SOAP requests, ensuring the transmission of secured SOAP envelopes. Moreover, it possesses the capability to efficiently extract data from security-applied SOAP responses.

SOAP module abstracts out the details of the creation of a SOAP envelope, headers, and the body in a SOAP message.

## Client

The `Client` is used to connect to and interact with `SOAP` endpoints.

### SOAP 1.1 Client

```ballerina
import ballerina/soap.soap11;

soap11:Client soapClient = check new ("http://www.dneonline.com/calculator.asmx?WSDL");
```

### SOAP 1.2 Client

```ballerina
import ballerina/soap.soap12;

soap12:Client soapClient = check new ("http://www.dneonline.com/calculator.asmx?WSDL");
```

## APIs associated with SOAP

- **Send & Receive**: Sends SOAP request and receives a response.
- **Send Only**: Fires and forgets requests. Sends the request without the possibility of any response from the service.

The SOAP 1.1 specification requires the inclusion of the `action` parameter as a mandatory component within its APIs. In contrast, SOAP 1.2 relaxes this requirement, making the action parameter optional.

### Example: Send & Receive

```ballerina
import ballerina/soap.soap11;

public function main() returns error? {
    soap11:Client soapClient = check new ("http://www.dneonline.com/calculator.asmx?WSDL");

    xml envelope = xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                            <soap:Body>
                            <quer:Add xmlns:quer="http://tempuri.org/">
                                <quer:intA>2</quer:intA>
                                <quer:intB>3</quer:intB>
                            </quer:Add>
                            </soap:Body>
                        </soap:Envelope>`;
    xml response = check soapClient->sendReceive(envelope, "http://tempuri.org/Add");
}
```

### Example: Send Only

```ballerina
import ballerina/soap.soap11;

public function main() returns error? {
    soap11:Client soapClient = check new ("http://www.dneonline.com/calculator.asmx?WSDL");

    xml envelope = xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                            <soap:Body>
                            <quer:Add xmlns:quer="http://tempuri.org/">
                                <quer:intA>2</quer:intA>
                                <quer:intB>3</quer:intB>
                            </quer:Add>
                            </soap:Body>
                        </soap:Envelope>`;
    check soapClient->sendOnly(envelope, "http://tempuri.org/Add");
}
```

## Security

The SOAP client module introduces a robust framework for configuring security measures in SOAP communication. Security is a critical concern when exchanging data via web services, and this module offers comprehensive options to fortify SOAP requests and responses.

There are two primary security configurations available for SOAP clients:

- `outboundSecurity`: This configuration is applied to the SOAP envelope when a request is made. It includes various ws security policies such as Username Token, Timestamp Token, X509 Token, Symmetric Binding, Asymmetric Binding, and Transport Binding, either individually or in combination with each other.

- `inboundSecurity`: This configuration is applied to the SOAP envelope when a response is received. Its purpose is to decrypt the data within the envelope and verify the digital signature for security validation.

### Policies

This library currently supports the following WS Security policies:

- **Username Token**: Provides authentication through username and password credentials.
- **Timestamp Token**: Enhances message integrity by incorporating timestamp information.
- **X509 Token**: Allows the use of X.509 certificates for secure communication.
- **Symmetric Binding**: Enables symmetric key-based security mechanisms.
- **Asymmetric Binding**: Facilitates the use of asymmetric cryptography for enhanced security.

These policies empower SOAP clients to enhance the security of their web service communications by selecting and implementing the appropriate security mechanisms to safeguard their SOAP envelopes.

### Security Policy Configuration Types

#### Inbound Security Configurations

- `TimestampTokenConfig`: Represents the record for Timestamp Token policy.
  - Fields:
    - `int` timeToLive : The time to get expired

- `UsernameTokenConfig`: Represents the record for Username Token policy.
  - Fields:
    - `string` username : The name of the user
    - `string` password : The password of the user
    - `PasswordType` passwordType : The password type of the username token

- `SymmetricBindingConfig`: Represents the record for Symmetric Binding policy.
  - Fields:
    - `crypto:PrivateKey` symmetricKey : The key to sign and encrypt the SOAP envelope
    - `crypto:PublicKey` servicePublicKey : The key to encrypt the symmetric key
    - `SignatureAlgorithm` signatureAlgorithm : The algorithm to sign the SOAP envelope
    - `EncryptionAlgorithm` encryptionAlgorithm : The algorithm to encrypt the SOAP envelope
    - `string` x509Token : The path or token of the X509 certificate

- `AsymmetricBindingConfig`: Represents the record for Asymmetric Binding policy.
  - Fields:
    - `SignatureConfig` signatureConfig : Configuration for applying digital signatures
    - `EncryptionConfig` encryptionConfig : Configuration for applying encryption
    - `string` x509Token : The path or token of the X509 certificate

#### Outbound Security Configurations

- `InboundSecurityConfig`: Represents the record for outbound security configurations to verify and decrypt SOAP envelopes.
  - Fields:
    - `crypto:PublicKey` verificationKey : The public key to verify the signature of the SOAP envelope
    - `crypto:PrivateKey`|`crypto:PublicKey` decryptionKey : The private key to decrypt the SOAP envelope
    - `SignatureAlgorithm` signatureAlgorithm : The algorithm to verify the SOAP envelope
    - `EncryptionAlgorithm` decryptionAlgorithm : The algorithm to decrypt the SOAP body

### Apply Security Policies

#### SOAP 1.1 Client: UsernameToken and TranportBinding Policy

```ballerina
import ballerina/crypto;
import ballerina/mime;
import ballerina/soap;
import ballerina/soap.soap11;

public function main() returns error? {
    soap11:Client soapClient = check new ("https://www.secured-soap-endpoint.com", 
        {
            outboundSecurity: [
            {
                username: "username",
                password: "password",
                passwordType: soap:TEXT
            },
            TRANSPORT_BINDING
            ]
        });

    xml envelope = xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                            <soap:Body>
                            <quer:Add xmlns:quer="http://tempuri.org/">
                                <quer:intA>2</quer:intA>
                                <quer:intB>3</quer:intB>
                            </quer:Add>
                            </soap:Body>
                        </soap:Envelope>`;
    xml response = check soapClient->sendReceive(envelope, "http://tempuri.org/Add");
}
```

#### SOAP 1.2 Client with Asymmetric Binding and Outbound Security Configuration

```ballerina
import ballerina/crypto;
import ballerina/mime;
import ballerina/soap;
import ballerina/soap.soap12;

public function main() returns error? {
    configurable crypto:PrivateKey clientPrivateKey = ?;
    configurable crypto:PublicKey clientPublicKey = ?;
    configurable ​crypto:PublicKey serverPublicKey = ?;

    soap12:Client soapClient = check new ("https://www.secured-soap-endpoint.com",
    {
        outboundSecurity: {
            signatureConfig: {
                keystore: {
                    path: KEY_STORE_PATH_2,
                    password: PASSWORD
                }, 
                privateKeyAlias: ALIAS, 
                privateKeyPassword: PASSWORD, 
                canonicalizationAlgorithm: wssec:C14N_EXCL_OMIT_COMMENTS, 
                digestAlgorithm: wssec:SHA1
            },
            encryptionConfig: {
                keystore: {
                    path: KEY_STORE_PATH_2,
                    password: PASSWORD
                },
                publicKeyAlias: ALIAS,
                encryptionAlgorithm: wssec:AES_128
            }
        },
        inboundSecurity: {
            keystore: {
                path: KEY_STORE_PATH_2,
                password: PASSWORD
            },
            decryptionAlgorithm: wssec:AES_128
        }
    });

   xml envelope = xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                           <soap:Body>
                           <quer:Add xmlns:quer="http://tempuri.org/">
                              <quer:intA>2</quer:intA>
                              <quer:intB>3</quer:intB>
                           </quer:Add>
                           </soap:Body>
                     </soap:Envelope>`;
    xml response = check soapClient->sendReceive(envelope, "http://tempuri.org/Add");
}
```

## Issues and projects

The **Issues** and **Projects** tabs are disabled for this repository as this is part of the Ballerina Standard Library. To report bugs, request new features, start new discussions, view project boards, etc., go to the Ballerina Standard Library [parent repository](https://github.com/ballerina-platform/ballerina-standard-library).

This repository contains only the source code of the package.

## Build from the source

### Set up the prerequisites

1. Download and install Java SE Development Kit (JDK) version 17 (from one of the following locations).
    - [Oracle](https://www.oracle.com/java/technologies/downloads/)

    - [OpenJDK](https://adoptium.net/)

      > **Note:** Set the JAVA_HOME environment variable to the path name of the directory into which you installed JDK.

2. Export your Github Personal access token with the read package permissions as follows.

    ```bash
        export packageUser=<Username>
        export packagePAT=<Personal access token>
    ```

### Build the source

Execute the commands below to build from source.

1. To build the library:

   ```bash
   ./gradlew clean build
   ```

2. To run the integration tests:

   ```bash
   ./gradlew clean test
   ```

3. To build the module without the tests:

   ```bash
   ./gradlew clean build -x test
   ```

4. To debug module implementation:

   ```bash
   ./gradlew clean build -Pdebug=<port>
   ./gradlew clean test -Pdebug=<port>
   ```

5. To debug the module with Ballerina language:

   ```bash
   ./gradlew clean build -PbalJavaDebug=<port>
   ./gradlew clean test -PbalJavaDebug=<port>
   ```

6. Publish ZIP artifact to the local `.m2` repository:

   ```bash
   ./gradlew clean build publishToMavenLocal
   ```

7. Publish the generated artifacts to the local Ballerina central repository:

   ```bash
   ./gradlew clean build -PpublishToLocalCentral=true
   ```

8. Publish the generated artifacts to the Ballerina central repository:

   ```bash
   ./gradlew clean build -PpublishToCentral=true
   ```

## Contribute to Ballerina

As an open source project, Ballerina welcomes contributions from the community.

For more information, go to the [contribution guidelines](https://github.com/ballerina-platform/ballerina-lang/blob/master/CONTRIBUTING.md).

## Code of conduct

All contributors are encouraged to read the [Ballerina Code of Conduct](https://ballerina.io/code-of-conduct).

## Useful links

- Chat live with us via our [Discord server](https://discord.gg/ballerinalang).
- Post all technical questions on Stack Overflow with the [#ballerina](https://stackoverflow.com/questions/tagged/ballerina) tag.
- For more information go to the [`soap` library](https://lib.ballerina.io/ballerina/soap/latest).
- For example demonstrations of the usage, go to [Ballerina By Examples](https://ballerina.io/swan-lake/learn/by-example/).
