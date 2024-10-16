# Overview

This module offers a set of APIs that facilitate the transmission of XML requests to a SOAP 1.2 backend. It excels in managing security policies within SOAP requests, ensuring the transmission of secured SOAP envelopes. Moreover, it possesses the capability to efficiently extract data from security-applied SOAP responses.

SOAP module abstracts out the details of the creation of a SOAP envelope, headers, and the body in a SOAP message.

## Client

The `Client` is used to connect to and interact with `SOAP` 1.2 endpoints.

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
import ballerina/soap.soap12;

public function main() returns error? {
    soap12:Client soapClient = check new ("http://www.dneonline.com/calculator.asmx?WSDL");

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
import ballerina/soap.soap12;

public function main() returns error? {
    soap12:Client soapClient = check new ("http://www.dneonline.com/calculator.asmx?WSDL");

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

- `outboundSecurity`: This configuration applies WS-Security policies to outgoing SOAP messages. It supports multiple security options, such as Username Token, Timestamp Token, X.509 Token, Symmetric Binding, Asymmetric Binding, and Transport Binding. These can be used individually or in combination to secure the message.

- `inboundSecurity`: This configuration handles the security of incoming SOAP messages. It decrypts encrypted data and verifies the digital signature to confirm the authenticity of the message.


### Policies

This library currently supports the following WS Security policies:

- **Username Token**: Provides authentication through username and password credentials.
- **Timestamp Token**: Enhances message integrity by incorporating timestamp information.
- **X509 Token**: Allows the use of X.509 certificates for secure communication.
- **Symmetric Binding**: Enables symmetric key-based security mechanisms.
- **Asymmetric Binding**: Facilitates the use of asymmetric cryptography for enhanced security.

These policies empower SOAP clients to enhance the security of their web service communications by selecting and implementing the appropriate security mechanisms to safeguard their SOAP envelopes.

### Security Policy Configuration Types

#### Outbound Security Configurations

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

#### Inbound Security Configurations

- `InboundSecurityConfig`: Represents the record for outbound security configurations to verify and decrypt SOAP envelopes.
  - Fields:
    - `crypto:KeyStore` decryptKeystore - The keystore to decrypt the SOAP envelope
    - `crypto:KeyStore` signatureKeystore - The keystore to verify the signature of the SOAP envelope

### Apply Security Policies

#### SOAP 1.2 Client with Asymmetric Binding and Outbound Security Configuration

```ballerina
import ballerina/crypto;
import ballerina/mime;
import ballerina/soap;
import ballerina/soap.soap12;

public function main() returns error? {
    soap12:Client soapClient = check new ("http://www.secured-soap-endpoint.com",
    {
        outboundSecurity: {
            signatureConfig: {
                keystore: {
                    path: KEY_STORE_PATH_2,
                    password: PASSWORD
                }, 
                privateKeyAlias: ALIAS, 
                privateKeyPassword: PASSWORD,
                signatureAlgorithm: wssec:RSA_SHA1
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
            decryptKeystore: {
                path: KEY_STORE_PATH_2,
                password: PASSWORD
            },
            signatureKeystore: {
                path: KEY_STORE_PATH_2,
                password: PASSWORD
            }
        }
    });
}
```
