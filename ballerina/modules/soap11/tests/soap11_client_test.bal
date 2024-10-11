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

import soap;
import soap.wssec;

import ballerina/crypto;
import ballerina/io;
import ballerina/mime;
import ballerina/test;

const string KEY_ALIAS = "wss40";
const string KEY_PASSWORD = "security";
const IMAGE_PATH = "../ballerina/icon.png";
const FILE_PATH = "../ballerina/Module.md";
const string KEY_STORE_PATH = "modules/wssec/tests/resources/wss40.p12";
const string X509_KEY_STORE_PATH = "modules/wssec/tests/resources/x509_certificate.p12";
const string X509_KEY_STORE_PATH_2 = "modules/wssec/tests/resources/x509_certificate_2.p12";
const wssec:TransportBindingConfig TRANSPORT_BINDING = "TransportBinding";
const wssec:NoPolicy NO_POLICY = "NoPolicy";

const KEY_STORE_PATH_2 = "modules/wssec/tests/resources/keystore.jks";
const ALIAS = "mykey";
const PASSWORD = "password";

const crypto:KeyStore clientKeyStore = {
    path: X509_KEY_STORE_PATH_2,
    password: KEY_PASSWORD
};
crypto:PrivateKey clientPrivateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(clientKeyStore, KEY_ALIAS,
                                                                                KEY_PASSWORD);
crypto:PublicKey clientPublicKey = check crypto:decodeRsaPublicKeyFromTrustStore(clientKeyStore, KEY_ALIAS);

crypto:KeyStore keyStore = {
    path: KEY_STORE_PATH,
    password: KEY_PASSWORD
};
crypto:PrivateKey symmetricKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);
crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, KEY_ALIAS);

@test:Config {
    groups: ["soap11", "send_receive", "mime"]
}
function testSendReceiveWithMime() returns error? {
    Client soapClient = check new ("http://localhost:9090");
    xml body = xml `<soap:Envelope
                        xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                        soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                        <soap:Body>
                          <quer:Add xmlns:quer="http://tempuri.org/">
                            <quer:intA>2</quer:intA>
                            <quer:intB>3</quer:intB>
                          </quer:Add>
                        </soap:Body>
                    </soap:Envelope>`;

    mime:Entity[] mtomMessage = [];
    mime:Entity envelope = new;
    check envelope.setContentType("application/xop+xml");
    envelope.setContentId("<soap@envelope>");
    envelope.setBody(body);
    mtomMessage.push(envelope);

    mime:Entity bytesPart = new;
    string readContent = check io:fileReadString(FILE_PATH);
    bytesPart.setFileAsEntityBody(FILE_PATH);
    string|byte[]|io:ReadableByteChannel|mime:EncodeError bytes = mime:base64Encode(readContent.toBytes());
    if bytes !is byte[] {
        return error("error");
    }
    bytesPart.setBody(bytes);
    check bytesPart.setContentType("image/jpeg");
    bytesPart.setContentId("<image1>");
    mtomMessage.push(bytesPart);

    xml response = check soapClient->sendReceive(mtomMessage, "http://tempuri.org/Add", path = "/getPayload");
    test:assertEquals(response, body);
}

@test:Config {
    groups: ["soap11", "send_receive", "mime"]
}
function testSendReceiveWithMime2() returns error? {
    Client soapClient = check new ("http://localhost:9090");
    xml body = xml `<soap:Envelope
                        xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                        soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                        <soap:Body>
                          <quer:Add xmlns:quer="http://tempuri.org/">
                            <quer:intA>2</quer:intA>
                            <quer:intB>3</quer:intB>
                          </quer:Add>
                        </soap:Body>
                    </soap:Envelope>`;

    mime:Entity[] mtomMessage = [];
    mime:Entity envelope = new;
    check envelope.setContentType("application/xop+xml");
    envelope.setContentId("<soap@envelope>");
    envelope.setBody(body);
    mtomMessage.push(envelope);

    mime:Entity bytesPart = new;
    string readContent = check io:fileReadString(FILE_PATH);
    bytesPart.setFileAsEntityBody(FILE_PATH);
    string|byte[]|io:ReadableByteChannel|mime:EncodeError bytes = mime:base64Encode(readContent.toBytes());
    if bytes !is byte[] {
        return error("error");
    }
    bytesPart.setBody(bytes);
    check bytesPart.setContentType("image/jpeg");
    bytesPart.setContentId("<image1>");
    mtomMessage.push(bytesPart);

    xml response = check soapClient->sendReceive(mtomMessage, "http://tempuri.org/Add", path = "/getPayload");
    test:assertEquals(response, body);
}

@test:Config {
    groups: ["soap11", "send_receive", "mime"]
}
function testSendReceiveWithMime3() returns error? {
    Client soapClient = check new ("http://localhost:9090");
    xml body = xml `<soap:Envelope
                        xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                        soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                        <soap:Body>
                          <quer:Add xmlns:quer="http://tempuri.org/">
                            <quer:intA>2</quer:intA>
                            <quer:intB>3</quer:intB>
                          </quer:Add>
                        </soap:Body>
                    </soap:Envelope>`;

    mime:Entity[] mtomMessage = [];
    mime:Entity envelope = new;
    check envelope.setContentType("application/xop+xml");
    envelope.setContentId("<soap@envelope>");
    envelope.setBody(body);
    mtomMessage.push(envelope);

    mime:Entity bytesPart = new;
    string readContent = check io:fileReadString(FILE_PATH);
    bytesPart.setFileAsEntityBody(FILE_PATH);
    string|byte[]|io:ReadableByteChannel|mime:EncodeError bytes = mime:base64Encode(readContent.toBytes());
    if bytes !is byte[] {
        return error("error");
    }
    bytesPart.setBody(bytes);
    check bytesPart.setContentType("image/jpeg");
    bytesPart.setContentId("<image1>");
    mtomMessage.push(bytesPart);

    mime:Entity[] response = check soapClient->sendReceive(mtomMessage, "http://tempuri.org/Add", path = "/getMimePayload");
    test:assertEquals(response[0].getXml(), check mtomMessage[0].getXml());
}

@test:Config {
    groups: ["soap11", "send_only"]
}
function testSendOnly() returns error? {
    xml body = xml `<soap:Envelope
                        xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                        soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                        <soap:Body>
                          <quer:Add xmlns:quer="http://tempuri.org/">
                            <quer:intA>2</quer:intA>
                            <quer:intB>3</quer:intB>
                          </quer:Add>
                        </soap:Body>
                    </soap:Envelope>`;

    Client soapClient = check new ("http://localhost:9090");
    check soapClient->sendOnly(body, "http://tempuri.org/Add");
}

@test:Config {
    groups: ["soap11", "send_only"]
}
function testSendOnlyError() returns error? {
    xml body = xml `<soap:Envelope
                        xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                        soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                        <soap:Body>
                          <quer:Add xmlns:quer="http://tempuri.org/">
                            <quer:intA>2</quer:intA>
                            <quer:intB>3</quer:intB>
                          </quer:Add>
                        </soap:Body>
                    </soap:Envelope>`;

    Client soapClient = check new ("error-url");
    Error? response = soapClient->sendOnly(body, "http://tempuri.org/Add", path = "/error");
    test:assertTrue(response is Error);
}

@test:Config {
    groups: ["soap11", "send_receive"]
}
function testSendReceive() returns error? {
    Client soapClient = check new ("http://localhost:9090",
        {
            outboundSecurity: NO_POLICY,
            inboundSecurity: {}
        }
    );

    xml body = xml `<soap:Envelope
                        xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                        soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                        <soap:Body>
                          <quer:Add xmlns:quer="http://tempuri.org/">
                            <quer:intA>2</quer:intA>
                            <quer:intB>3</quer:intB>
                          </quer:Add>
                        </soap:Body>
                    </soap:Envelope>`;
    xml response = check soapClient->sendReceive(body, "http://tempuri.org/Add");
    xml expected = xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><soap:Body><AddResponse xmlns="http://tempuri.org/"><AddResult>5</AddResult></AddResponse></soap:Body></soap:Envelope>`;
    test:assertEquals(response, expected);
}

@test:Config {
    groups: ["soap11", "send_receive"]
}
function testSendReceiveWithInvalidAction() returns error? {
    Client soapClient = check new ("http://localhost:9090",
        {
            outboundSecurity: NO_POLICY,
            inboundSecurity: {}
        }
    );

    xml body = xml `<soap:Envelope
                        xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                        soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                        <soap:Body>
                          <quer:Add xmlns:quer="http://tempuri.org/">
                            <quer:intA>2</quer:intA>
                            <quer:intB>3</quer:intB>
                          </quer:Add>
                        </soap:Body>
                    </soap:Envelope>`;
    xml response = check soapClient->sendReceive(body, "http://tempuri.org/invalid_action");
    xml expected = xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><soap:Body><soap:Fault><faultcode>soap:Client</faultcode><faultstring>System.Web.Services.Protocols.SoapException: Server did not recognize the value of HTTP Header SOAPAction: http://tempuri.org/invalid_action.
   at System.Web.Services.Protocols.Soap11ServerProtocolHelper.RouteRequest()
   at System.Web.Services.Protocols.SoapServerProtocol.RouteRequest(SoapServerMessage message)
   at System.Web.Services.Protocols.SoapServerProtocol.Initialize()
   at System.Web.Services.Protocols.ServerProtocol.SetContext(Type type, HttpContext context, HttpRequest request, HttpResponse response)
   at System.Web.Services.Protocols.ServerProtocolFactory.Create(Type type, HttpContext context, HttpRequest request, HttpResponse response, Boolean&amp; abortProcessing)</faultstring><detail/></soap:Fault></soap:Body></soap:Envelope>`;
    test:assertEquals(response, expected);
}

@test:Config {
    groups: ["soap11", "send_receive"]
}
function testSendReceiveWithHeaders() returns error? {
    xml body = xml `<soap:Envelope
                        xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                        soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                        <soap:Body>
                          <quer:Add xmlns:quer="http://tempuri.org/">
                            <quer:intA>2</quer:intA>
                            <quer:intB>3</quer:intB>
                          </quer:Add>
                        </soap:Body>
                    </soap:Envelope>`;

    Client soapClient = check new ("http://localhost:9090");

    xml response = check soapClient->sendReceive(body, "http://tempuri.org/Add", {foo: ["bar1", "bar2"]});
    xml expected = xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><soap:Body><AddResponse xmlns="http://tempuri.org/"><AddResult>5</AddResult></AddResponse></soap:Body></soap:Envelope>`;
    test:assertEquals(response, expected);
}

@test:Config {
    groups: ["soap11"]
}
function testTransportBindingError() returns error? {
    Client|Error soapClient = new ("http://localhost:9090",
        outboundSecurity = TRANSPORT_BINDING
    );
    test:assertTrue(soapClient is Error);
    test:assertEquals((<Error>soapClient).message(), SOAP_CLIENT_ERROR);
}

@test:Config {
    groups: ["soap11"]
}
function testTransportBindingError2() returns error? {
    Client|Error soapClient = new ("http://localhost:9090",
        outboundSecurity = [
            TRANSPORT_BINDING
        ]
    );
    test:assertTrue(soapClient is Error);
    test:assertEquals((<Error>soapClient).message(), SOAP_CLIENT_ERROR);
}

@test:Config {
    groups: ["soap11", "send_receive"]
}
function testSendReceiveError() returns error? {
    Client soapClient = check new ("http://www.dneonline.com/invalidcalculator.asmx?WSDL");
    xml body = xml `<soap:Envelope
                        xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                        soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                        <soap:Body>
                          <quer:Add xmlns:quer="http://tempuri.org/">
                            <quer:intA>2</quer:intA>
                            <quer:intB>3</quer:intB>
                          </quer:Add>
                        </soap:Body>
                    </soap:Envelope>`;
    xml|Error response = soapClient->sendReceive(body, "http://tempuri.org/Add");
    test:assertTrue(response is Error);
    test:assertEquals((<Error>response).message(), SOAP_ERROR);
}

@test:Config {
    groups: ["soap11", "send_receive"]
}
function testSendReceiveWithUsernameTokenSecurity() returns error? {
    Client soapClient = check new ("http://localhost:9091",
        {
            outboundSecurity: {
                username: "user",
                password: "password",
                passwordType: soap:TEXT
            },
            inboundSecurity: {}
        }
    );
    xml envelope = xml `<soap:Envelope
                        xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                        soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                        <soap:Body>
                          <quer:Add xmlns:quer="http://tempuri.org/">
                            <quer:intA>2</quer:intA>
                            <quer:intB>3</quer:intB>
                          </quer:Add>
                        </soap:Body>
                    </soap:Envelope>`;
    xml response = check soapClient->sendReceive(envelope, "http://tempuri.org/Add");
    xmlns "http://schemas.xmlsoap.org/soap/envelope" as soap11;
    error? assertUsernameToken = soap:assertUsernameToken(response.toString(), "user", "password", soap:TEXT, (envelope/<soap11:Body>/*).toString());
    test:assertTrue(assertUsernameToken !is error);
}

@test:Config {
    groups: ["soap11", "send_receive", "new"]
}
function testSendReceiveWithAsymmetricBindingSecurity() returns error? {
    Client soapClient = check new ("http://localhost:9091",
        {
            outboundSecurity: {
                signatureConfig: {
                    keystore: {
                        path: KEY_STORE_PATH_2,
                        password: PASSWORD
                    },
                    privateKeyAlias: ALIAS, 
                    privateKeyPassword: PASSWORD,
                    signatureAlgorithm: wssec:RSA_SHA512,
                    canonicalizationAlgorithm: wssec:C14N_EXCL_OMIT_COMMENTS, 
                    digestAlgorithm: wssec:SHA512
                }
            }
        }
    );
    xml body = xml `<soap:Envelope
                        xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                        soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                        <soap:Body>
                          <quer:Add xmlns:quer="http://tempuri.org/">
                            <quer:intA>2</quer:intA>
                            <quer:intB>3</quer:intB>
                          </quer:Add>
                        </soap:Body>
                    </soap:Envelope>`;
    xml response = check soapClient->sendReceive(body, "http://tempuri.org/Add");
    wssec:InboundConfig inboundConfig = {
        keystore: {
            path: KEY_STORE_PATH_2,
            password: PASSWORD
        }
    };
    boolean verifySignature = check wssec:verifySignature(response, inboundConfig);
    test:assertTrue(verifySignature);
}

@test:Config {
    groups: ["soap11", "send_receive"]
}
function testSoapEndpoint() returns error? {
    string username = "user";
    string password = "password";
    Client soapClient = check new ("http://localhost:9090",
        {
            outboundSecurity: {
                username: username,
                password: password,
                passwordType: wssec:TEXT
            }
        }
    );
    xml body = xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><soap:Body><quer:Add xmlns:quer="http://tempuri.org/"><quer:intA>2</quer:intA><quer:intB>3</quer:intB></quer:Add></soap:Body></soap:Envelope>`;
    xml response = check soapClient->sendReceive(body, "http://tempuri.org/Add", path = "/getSamePayload");
    return soap:assertUsernameToken(response.toString(), username, password, wssec:TEXT, string `<soap:Body><quer:Add xmlns:quer="http://tempuri.org/"><quer:intA>2</quer:intA><quer:intB>3</quer:intB></quer:Add></soap:Body>`);
}

@test:Config {
    groups: ["soap11", "send_receive"]
}
function testSoapReceiveWithSymmetricBindingAndOutboundConfig() returns error? {
    Client soapClient = check new ("http://localhost:9090",
        {
            outboundSecurity: {
                signatureAlgorithm: wssec:RSA_SHA256,
                encryptionAlgorithm: wssec:RSA_ECB,
                symmetricKey: symmetricKey,
                servicePublicKey: serverPublicKey
            },
            inboundSecurity: {
                verificationKey: publicKey,
                signatureAlgorithm: wssec:RSA_SHA256,
                decryptionAlgorithm: wssec:RSA_ECB,
                decryptionKey: publicKey
            }
        }
    );
    xml body = xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><soap:Body><quer:Add xmlns:quer="http://tempuri.org/"><quer:intA>2</quer:intA><quer:intB>3</quer:intB></quer:Add></soap:Body></soap:Envelope>`;
    xml response = check soapClient->sendReceive(body, "http://tempuri.org/Add", path = "/getSamePayload");
    return soap:assertSymmetricBinding(response.toString(), string `<soap:Body><quer:Add xmlns:quer="http://tempuri.org/"><quer:intA>2</quer:intA><quer:intB>3</quer:intB></quer:Add></soap:Body>`);
}

@test:Config {
    groups: ["soap11", "send_receive"]
}
function testSendReceiveWithAsymmetricBindingAndOutboundConfig() returns error? {
    Client soapClient = check new ("http://localhost:9090",
        {
            outboundSecurity: {
                signatureAlgorithm: soap:RSA_SHA256,
                encryptionAlgorithm: soap:RSA_ECB,
                signatureKey: clientPrivateKey,
                encryptionKey: serverPublicKey
            },
            inboundSecurity: {
                verificationKey: serverPublicKey,
                signatureAlgorithm: soap:RSA_SHA256,
                decryptionAlgorithm: soap:RSA_ECB,
                decryptionKey: clientPrivateKey
            }
        }
    );
    xml body = xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><soap:Body><quer:Add xmlns:quer="http://tempuri.org/"><quer:intA>2</quer:intA><quer:intB>3</quer:intB></quer:Add></soap:Body></soap:Envelope>`;
    xml response = check soapClient->sendReceive(body, "http://tempuri.org/Add", path = "/getSecuredPayload");
    return soap:assertSymmetricBinding(response.toString(), string `<soap:Body><quer:Add xmlns:quer="http://tempuri.org/"><quer:intA>2</quer:intA><quer:intB>3</quer:intB></quer:Add></soap:Body>`);
}

@test:Config {
    groups: ["soap11", "send_receive", "mime"]
}
function testOutboundConfigWithMime2() returns error? {
    Client soapClient = check new ("http://localhost:9090",
        {
            outboundSecurity: {
                signatureAlgorithm: soap:RSA_SHA256,
                encryptionAlgorithm: soap:RSA_ECB,
                signatureKey: clientPrivateKey,
                encryptionKey: serverPublicKey
            },
            inboundSecurity: {
                verificationKey: serverPublicKey,
                signatureAlgorithm: soap:RSA_SHA256,
                decryptionAlgorithm: soap:RSA_ECB,
                decryptionKey: clientPrivateKey
            }
        }
    );
    xml body = xml `<soap:Envelope
                        xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                        soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                        <soap:Body>
                          <quer:Add xmlns:quer="http://tempuri.org/">
                            <quer:intA>2</quer:intA>
                            <quer:intB>3</quer:intB>
                          </quer:Add>
                        </soap:Body>
                    </soap:Envelope>`;

    mime:Entity[] mtomMessage = [];
    mime:Entity envelope = new;
    check envelope.setContentType("application/xop+xml");
    envelope.setContentId("<soap@envelope>");
    envelope.setBody(body);
    mtomMessage.push(envelope);

    mime:Entity bytesPart = new;
    string readContent = check io:fileReadString(FILE_PATH);
    bytesPart.setFileAsEntityBody(FILE_PATH);
    string|byte[]|io:ReadableByteChannel|mime:EncodeError bytes = mime:base64Encode(readContent.toBytes());
    if bytes !is byte[] {
        return error("error");
    }
    bytesPart.setBody(bytes);
    check bytesPart.setContentType("image/jpeg");
    bytesPart.setContentId("<image1>");
    mtomMessage.push(bytesPart);
    xml response = check soapClient->sendReceive(mtomMessage, "http://tempuri.org/Add", path = "/getSecuredMimePayload");
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap11;
    test:assertEquals(response/<soap11:Body>, body/<soap11:Body>);
}

@test:Config {
    groups: ["soap11", "send_receive", "mime"]
}
function testInvalidOutboundConfigWithMime() returns error? {
    Client soapClient = check new ("http://localhost:9090",
        {
            outboundSecurity: {
                signatureAlgorithm: soap:RSA_SHA256,
                encryptionAlgorithm: soap:RSA_ECB,
                signatureKey: clientPrivateKey,
                encryptionKey: serverPublicKey
            },
            inboundSecurity: {
                verificationKey: clientPublicKey,
                signatureAlgorithm: soap:RSA_SHA256,
                decryptionAlgorithm: soap:RSA_ECB,
                decryptionKey: serverPrivateKey
            }
        }
    );
    xml body = xml `<soap:Envelope
                        xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                        soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                        <soap:Body>
                          <quer:Add xmlns:quer="http://tempuri.org/">
                            <quer:intA>2</quer:intA>
                            <quer:intB>3</quer:intB>
                          </quer:Add>
                        </soap:Body>
                    </soap:Envelope>`;

    mime:Entity[] mtomMessage = [];
    mime:Entity envelope = new;
    check envelope.setContentType("application/xop+xml");
    envelope.setContentId("<soap@envelope>");
    envelope.setBody(body);
    mtomMessage.push(envelope);

    mime:Entity bytesPart = new;
    string readContent = check io:fileReadString(FILE_PATH);
    bytesPart.setFileAsEntityBody(FILE_PATH);
    string|byte[]|io:ReadableByteChannel|mime:EncodeError bytes = mime:base64Encode(readContent.toBytes());
    if bytes !is byte[] {
        return error("error");
    }
    bytesPart.setBody(bytes);
    check bytesPart.setContentType("image/jpeg");
    bytesPart.setContentId("<image1>");
    mtomMessage.push(bytesPart);
    xml|Error response = soapClient->sendReceive(mtomMessage, "http://tempuri.org/Add", path = "/getSecuredMimePayload");
    test:assertTrue(response is Error);
    test:assertEquals((<Error>response).message(), "Outbound security configurations do not match with the SOAP response");
}
