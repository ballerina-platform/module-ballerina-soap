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
import soap.wssec;

import ballerina/mime;
import ballerina/test;

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
