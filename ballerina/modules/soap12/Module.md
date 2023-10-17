## Overview

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
    xml|mime:Entity[] response = check soapClient->sendReceive(envelope, "http://tempuri.org/Add");
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

- `inboundSecurity`: This configuration is applied to the SOAP envelope when a request is made. It includes various ws security policies such as Username Token, Timestamp Token, X509 Token, Symmetric Binding, Asymmetric Binding, and Transport Binding, either individually or in combination with each other.

- `outboundSecurity`: This configuration is applied to the SOAP envelope when a response is received. Its purpose is to decrypt the data within the envelope and verify the digital signature for security validation.

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

-  `TimestampTokenConfig`: Represents the record for Timestamp Token policy.
	- Fields:
	    - `int` timeToLive : The time to get expired

- `UsernameTokenConfig`: Represents the record for Username Token policy.
    - Fields:
        -  `string` username : The name of the user
        -  `string` password : The password of the user
        -  `PasswordType` passwordType : The password type of the username token

- `SymmetricBindingConfig`: Represents the record for Symmetric Binding policy.
    - Fields:
        - `crypto:PrivateKey` symmetricKey : The key to sign and encrypt the SOAP envelope
        - `crypto:PublicKey` servicePublicKey : The key to encrypt the symmetric key
        - `SignatureAlgorithm` signatureAlgorithm : The algorithm to sign the SOAP envelope
        - `EncryptionAlgorithm` encryptionAlgorithm : The algorithm to encrypt the SOAP envelope
        - `string` x509Token : The path or token of the X509 certificate

- `AsymmetricBindingConfig`: Represents the record for Username Token with Asymmetric Binding policy.
    - Fields:
        - `crypto:PrivateKey` signatureKey : The private key to sign the SOAP envelope
        - `crypto:PublicKey` encryptionKey : The public key to encrypt the SOAP body
        - `SignatureAlgorithm` signatureAlgorithm : The algorithm to sign the SOAP envelope
        - `EncryptionAlgorithm` encryptionAlgorithm : The algorithm to encrypt the SOAP body
        - `string` x509Token : field description

#### Outbound Security Configurations

- `OutboundSecurityConfig`: Represents the record for outbound security configurations to verify and decrypt SOAP envelopes.
    - Fields:
        - `crypto:PublicKey` verificationKey : The public key to verify the signature of the SOAP envelope
        - `crypto:PrivateKey`|`crypto:PublicKey` decryptionKey : The private key to decrypt the SOAP envelope
        - `SignatureAlgorithm` signatureAlgorithm : The algorithm to verify the SOAP envelope
        - `EncryptionAlgorithm` decryptionAlgorithm : The algorithm to decrypt the SOAP body

### Apply Security Policies

#### SOAP 1.2 Client with Asymmetric Binding and Outbound Security Configuration

```ballerina
import ballerina/crypto;
import ballerina/mime;
import ballerina/soap;
import ballerina/soap.soap12;

public function main() returns error? {
    crypto:PrivateKey clientPrivateKey = ...//
    crypto:PublicKey clientPublicKey = ...//
    ​​crypto:PublicKey serverPublicKey = ...//

    soap12:Client soapClient = check new ("http://secured-soap-endpoint.com",
    {
        inboundSecurity: {
                signatureAlgorithm: soap:RSA_SHA256,
                encryptionAlgorithm: soap:RSA_ECB,
                signatureKey: clientPrivateKey,
                encryptionKey: serverPublicKey,
        },
        outboundSecurity: {
                verificationKey: serverPublicKey,
                signatureAlgorithm: soap:RSA_SHA256,
                decryptionKey: clientPrivateKey,
                decryptionAlgorithm: soap:RSA_ECB
        }
    });
}
```

**Note**: The `http://secured-soap-endpoint.com` URL represents an endpoint for a SOAP server equipped to handle web service security. Please be aware that this URL is provided for illustrative purposes and does not correspond to an actual live server.

## Report issues

To report bugs, request new features, start new discussions, view project boards, etc., go to the [Ballerina standard library parent repository](https://github.com/ballerina-platform/ballerina-standard-library).

## Useful links

- Chat live with us via our [Discord server](https://discord.gg/ballerinalang).
- Post all technical questions on Stack Overflow with the [#ballerina](https://stackoverflow.com/questions/tagged/ballerina) tag.
