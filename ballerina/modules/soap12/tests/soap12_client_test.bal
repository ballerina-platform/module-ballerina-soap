// Copyright (c) 2023, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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

import ballerina/mime;
import ballerina/test;
import ballerina/crypto;
import soap.wssec;

const string KEY_ALIAS = "wss40";
const string KEY_PASSWORD = "security";
const string KEY_STORE_PATH = "modules/wssec/tests/resources/wss40.p12";
const string X509_KEY_STORE_PATH = "modules/wssec/tests/resources/x509_certificate.p12";
const string X509_KEY_STORE_PATH_2 = "modules/wssec/tests/resources/x509_certificate_2.p12";
const wssec:TransportBindingConfig TRANSPORT_BINDING = "TransportBinding";
const wssec:NoPolicy NO_POLICY = "NoPolicy";

@test:Config {
    groups: ["soap12", "send_only"]
}
function testSendOnly12() returns error? {
    xml body = xml `<soap:Envelope
                        xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
                        soap:encodingStyle="http://www.w3.org/2003/05/soap-encoding">
                        <soap:Body>
                          <quer:Add xmlns:quer="http://tempuri.org/">
                            <quer:intA>2</quer:intA>
                            <quer:intB>3</quer:intB>
                          </quer:Add>
                        </soap:Body>
                    </soap:Envelope>`;

    Client soapClient = check new ("http://www.dneonline.com/calculator.asmx?WSDL");

    _ = check soapClient->sendOnly(body, "http://tempuri.org/Add");
}

@test:Config {
    groups: ["soap12", "send_receive"]
}
function testSendReceive12() returns error? {
    Client soapClient = check new ("http://www.dneonline.com/calculator.asmx?WSDL");

    xml body = xml `<soap:Envelope
                    xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
                    soap:encodingStyle="http://www.w3.org/2003/05/soap-encoding">
                    <soap:Body>
                      <quer:Add xmlns:quer="http://tempuri.org/">
                        <quer:intA>2</quer:intA>
                        <quer:intB>3</quer:intB>
                      </quer:Add>
                    </soap:Body>
                </soap:Envelope>`;
    xml|mime:Entity[] response = check soapClient->sendReceive(body, "http://tempuri.org/Add");

    xml expected = xml `<soap:Body xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><AddResponse xmlns="http://tempuri.org/"><AddResult>5</AddResult></AddResponse></soap:Body>`;
    test:assertEquals(response, expected);
}

@test:Config {
    groups: ["soap12", "send_receive"]
}
function testSendReceive12WithHeaders() returns error? {
    xml body = xml `<soap:Envelope
                        xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
                        soap:encodingStyle="http://www.w3.org/2003/05/soap-encoding">
                        <soap:Body>
                          <quer:Add xmlns:quer="http://tempuri.org/">
                            <quer:intA>2</quer:intA>
                            <quer:intB>3</quer:intB>
                          </quer:Add>
                        </soap:Body>
                    </soap:Envelope>`;

    Client soapClient = check new ("http://www.dneonline.com/calculator.asmx?WSDL");

    xml|mime:Entity[] response = check soapClient->sendReceive(body, "http://tempuri.org/Add",
                                                                {foo: ["bar1", "bar2"]});

    xml expected = xml `<soap:Body xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><AddResponse xmlns="http://tempuri.org/"><AddResult>5</AddResult></AddResponse></soap:Body>`;
    test:assertEquals(response, expected);
}

@test:Config {
    groups: ["soap12", "send_receive"]
}
function testSendReceive12WithoutSoapAction() returns error? {
    xml body = xml `<soap:Envelope
                        xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
                        soap:encodingStyle="http://www.w3.org/2003/05/soap-encoding">
                        <soap:Body>
                          <quer:Add xmlns:quer="http://tempuri.org/">
                            <quer:intA>2</quer:intA>
                            <quer:intB>3</quer:intB>
                          </quer:Add>
                        </soap:Body>
                    </soap:Envelope>`;

    Client soapClient = check new ("http://www.dneonline.com/calculator.asmx?WSDL");

    xml|mime:Entity[] response = check soapClient->sendReceive(body);

    xml expected = xml `<soap:Body xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><AddResponse xmlns="http://tempuri.org/"><AddResult>5</AddResult></AddResponse></soap:Body>`;
    test:assertEquals(response, expected);
}

@test:Config {
    groups: ["soap12", "send_only"]
}
function testSendOnly12WithoutSoapAction() returns error? {
    xml body = xml `<soap:Envelope
                        xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
                        soap:encodingStyle="http://www.w3.org/2003/05/soap-encoding">
                        <soap:Body>
                          <quer:Add xmlns:quer="http://tempuri.org/">
                            <quer:intA>2</quer:intA>
                            <quer:intB>3</quer:intB>
                          </quer:Add>
                        </soap:Body>
                    </soap:Envelope>`;

    Client soapClient = check new ("http://www.dneonline.com/calculator.asmx?WSDL");

    _ = check soapClient->sendOnly(body);
}

@test:Config {
    groups: ["soap12", "send_receive"]
}
function testSendReceive12IncludingHeadersWithoutSoapAction() returns error? {
    xml body = xml `<soap:Envelope
                        xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
                        soap:encodingStyle="http://www.w3.org/2003/05/soap-encoding">
                        <soap:Body>
                          <quer:Add xmlns:quer="http://tempuri.org/">
                            <quer:intA>2</quer:intA>
                            <quer:intB>3</quer:intB>
                          </quer:Add>
                        </soap:Body>
                    </soap:Envelope>`;

    Client soapClient = check new ("http://www.dneonline.com/calculator.asmx?WSDL");

    xml|mime:Entity[] response = check soapClient->sendReceive(body, (), {foo: ["bar1", "bar2"]});
    xml expected = xml `<soap:Body xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><AddResponse xmlns="http://tempuri.org/"><AddResult>5</AddResult></AddResponse></soap:Body>`;
    test:assertEquals(response, expected);
}

@test:Config {
    groups: ["soap12"]
}
function testTransportBindingError() returns error? {
    Client|Error soapClient = new ("http://www.dneonline.com/calculator.asmx?WSDL", inboundSecurity = TRANSPORT_BINDING);
    test:assertTrue(soapClient is Error);
    test:assertEquals((<Error>soapClient).message(), SOAP_CLIENT_ERROR);
}

@test:Config {
    groups: ["soap12"]
}
function testTransportBindingError2() returns error? {
    Client|Error soapClient = new ("http://www.dneonline.com/calculator.asmx?WSDL",
      inboundSecurity = [
        TRANSPORT_BINDING
      ]
    );
    test:assertTrue(soapClient is Error);
    test:assertEquals((<Error>soapClient).message(), SOAP_CLIENT_ERROR);
}

@test:Config {
    groups: ["soap12", "send_receive"]
}
function testSendReceiveError() returns error? {
    Client soapClient = check new ("http://www.dneonline.com/invalidcalculator.asmx?WSDL");
    xml body = xml `<soap:Envelope
                    xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
                    soap:encodingStyle="http://www.w3.org/2003/05/soap-encoding">
                    <soap:Body>
                      <quer:Add xmlns:quer="http://tempuri.org/">
                        <quer:intA>2</quer:intA>
                        <quer:intB>3</quer:intB>
                      </quer:Add>
                    </soap:Body>
                </soap:Envelope>`;
    xml|mime:Entity[]|Error response = soapClient->sendReceive(body, "http://tempuri.org/Add");
    test:assertTrue(response is Error);
    test:assertEquals((<Error>response).message(), SOAP_RESPONSE_ERROR);
}


@test:Config {
    groups: ["soap12", "send_receive"]
}
function testSendReceiveWithTimestampTokenSecurity() returns error? {
    Client soapClient = check new ("http://www.dneonline.com/calculator.asmx?WSDL",
        {
            inboundSecurity: [
                {
                    timeToLive: 600
                }
            ]
        }
    );
    xml body = xml `<soap:Envelope
                        xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
                        soap:encodingStyle="http://www.w3.org/2003/05/soap-encoding">
                        <soap:Body>
                          <quer:Add xmlns:quer="http://tempuri.org/">
                            <quer:intA>2</quer:intA>
                            <quer:intB>3</quer:intB>
                          </quer:Add>
                        </soap:Body>
                    </soap:Envelope>`;
    xml|mime:Entity[] response = check soapClient->sendReceive(body, "http://tempuri.org/Add");
    xml expected = xml `<soap:Body xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Fault><soap:Code><soap:Value>soap:MustUnderstand</soap:Value></soap:Code><soap:Reason><soap:Text xml:lang="en">System.Web.Services.Protocols.SoapHeaderException: SOAP header Security was not understood.
   at System.Web.Services.Protocols.SoapHeaderHandling.SetHeaderMembers(SoapHeaderCollection headers, Object target, SoapHeaderMapping[] mappings, SoapHeaderDirection direction, Boolean client)
   at System.Web.Services.Protocols.SoapServerProtocol.CreateServerInstance()
   at System.Web.Services.Protocols.WebServiceHandler.Invoke()
   at System.Web.Services.Protocols.WebServiceHandler.CoreProcessRequest()</soap:Text></soap:Reason></soap:Fault></soap:Body>`;

    test:assertEquals(response.toString(), expected.toString());
}

@test:Config {
    groups: ["soap12", "send_receive"]
}
function testSendReceiveWithUsernameTokenSecurity() returns error? {
    Client soapClient = check new ("http://www.dneonline.com/calculator.asmx?WSDL",
        {
            inboundSecurity: {
                username: "user",
                password: "password",
                passwordType: soap:TEXT
            },
            outboundSecurity: {}
        }
    );
    xml body = xml `<soap:Envelope
                        xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
                        soap:encodingStyle="http://www.w3.org/2003/05/soap-encoding">
                        <soap:Body>
                          <quer:Add xmlns:quer="http://tempuri.org/">
                            <quer:intA>2</quer:intA>
                            <quer:intB>3</quer:intB>
                          </quer:Add>
                        </soap:Body>
                    </soap:Envelope>`;
    xml|mime:Entity[] response = check soapClient->sendReceive(body, "http://tempuri.org/Add");
    xml expected = xml `<soap:Body xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Fault><soap:Code><soap:Value>soap:MustUnderstand</soap:Value></soap:Code><soap:Reason><soap:Text xml:lang="en">System.Web.Services.Protocols.SoapHeaderException: SOAP header Security was not understood.
   at System.Web.Services.Protocols.SoapHeaderHandling.SetHeaderMembers(SoapHeaderCollection headers, Object target, SoapHeaderMapping[] mappings, SoapHeaderDirection direction, Boolean client)
   at System.Web.Services.Protocols.SoapServerProtocol.CreateServerInstance()
   at System.Web.Services.Protocols.WebServiceHandler.Invoke()
   at System.Web.Services.Protocols.WebServiceHandler.CoreProcessRequest()</soap:Text></soap:Reason></soap:Fault></soap:Body>`;

    test:assertEquals(response.toString(), expected.toString());
}

@test:Config {
    groups: ["soap12", "send_receive"]
}
function testSendReceiveWithAsymmetricBindingSecurity() returns error? {
    crypto:KeyStore serverKeyStore = {
        path: X509_KEY_STORE_PATH,
        password: KEY_PASSWORD
    };

    crypto:PublicKey serverPublicKey = check crypto:decodeRsaPublicKeyFromTrustStore(serverKeyStore, KEY_ALIAS);

    crypto:KeyStore clientKeyStore = {
        path: X509_KEY_STORE_PATH_2,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey clientPrivateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(clientKeyStore, KEY_ALIAS, KEY_PASSWORD);

    Client soapClient = check new ("http://www.dneonline.com/calculator.asmx?WSDL",
        {
            inboundSecurity: {
                signatureAlgorithm: soap:RSA_SHA256,
                encryptionAlgorithm: soap:RSA_ECB,
                signatureKey: clientPrivateKey,
                encryptionKey: serverPublicKey
            }
        }
    );
    xml body = xml `<soap:Envelope
                        xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
                        soap:encodingStyle="http://www.w3.org/2003/05/soap-encoding">
                        <soap:Body>
                          <quer:Add xmlns:quer="http://tempuri.org/">
                            <quer:intA>2</quer:intA>
                            <quer:intB>3</quer:intB>
                          </quer:Add>
                        </soap:Body>
                    </soap:Envelope>`;
    xml|mime:Entity[] response = check soapClient->sendReceive(body, "http://tempuri.org/Add");
    xml expected = xml `<soap:Body xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Fault><soap:Code><soap:Value>soap:MustUnderstand</soap:Value></soap:Code><soap:Reason><soap:Text xml:lang="en">System.Web.Services.Protocols.SoapHeaderException: SOAP header Security was not understood.
   at System.Web.Services.Protocols.SoapHeaderHandling.SetHeaderMembers(SoapHeaderCollection headers, Object target, SoapHeaderMapping[] mappings, SoapHeaderDirection direction, Boolean client)
   at System.Web.Services.Protocols.SoapServerProtocol.CreateServerInstance()
   at System.Web.Services.Protocols.WebServiceHandler.Invoke()
   at System.Web.Services.Protocols.WebServiceHandler.CoreProcessRequest()</soap:Text></soap:Reason></soap:Fault></soap:Body>`;

    test:assertEquals(response.toString(), expected.toString());
}

@test:Config {
    groups: ["soap12", "send_receive"]
}
function testSendReceiveWithSymmetricBindingSecurity() returns error? {
    crypto:KeyStore serverKeyStore = {
        path: X509_KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PublicKey serverPublicKey = check crypto:decodeRsaPublicKeyFromTrustStore(serverKeyStore, KEY_ALIAS);

    crypto:KeyStore keyStore = {
        path: KEY_STORE_PATH,
        password: KEY_PASSWORD
    };
    crypto:PrivateKey symmetricKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, KEY_ALIAS, KEY_PASSWORD);

    Client soapClient = check new ("http://www.dneonline.com/calculator.asmx?WSDL",
        {
            inboundSecurity: {
                signatureAlgorithm: soap:RSA_SHA256,
                encryptionAlgorithm: soap:RSA_ECB,
                symmetricKey: symmetricKey,
                servicePublicKey: serverPublicKey
            }
        }
    );
    xml body = xml `<soap:Envelope
                        xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
                        soap:encodingStyle="http://www.w3.org/2003/05/soap-encoding">
                        <soap:Body>
                          <quer:Add xmlns:quer="http://tempuri.org/">
                            <quer:intA>2</quer:intA>
                            <quer:intB>3</quer:intB>
                          </quer:Add>
                        </soap:Body>
                    </soap:Envelope>`;
    xml|mime:Entity[] response = check soapClient->sendReceive(body, "http://tempuri.org/Add");
    xml expected = xml `<soap:Body xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Fault><soap:Code><soap:Value>soap:MustUnderstand</soap:Value></soap:Code><soap:Reason><soap:Text xml:lang="en">System.Web.Services.Protocols.SoapHeaderException: SOAP header Security was not understood.
   at System.Web.Services.Protocols.SoapHeaderHandling.SetHeaderMembers(SoapHeaderCollection headers, Object target, SoapHeaderMapping[] mappings, SoapHeaderDirection direction, Boolean client)
   at System.Web.Services.Protocols.SoapServerProtocol.CreateServerInstance()
   at System.Web.Services.Protocols.WebServiceHandler.Invoke()
   at System.Web.Services.Protocols.WebServiceHandler.CoreProcessRequest()</soap:Text></soap:Reason></soap:Fault></soap:Body>`;

    test:assertEquals(response.toString(), expected.toString());
}
