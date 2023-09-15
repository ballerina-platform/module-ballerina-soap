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

import ballerina/test;
import ballerina/mime;

@test:Config {}
function testSendReceive11() returns error? {
    Client soapClient = check new ("http://www.dneonline.com/calculator.asmx?WSDL");

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

    xml|mime:Entity[] response = check soapClient->sendReceive(body, "http://tempuri.org/Add");

    xml expected = xml `<soap:Body xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><AddResponse xmlns="http://tempuri.org/"><AddResult>5</AddResult></AddResponse></soap:Body>`;
    test:assertEquals(response, expected);
}

@test:Config {}
function testSendReceive12() returns error? {
    Client soapClient = check new ("http://www.dneonline.com/calculator.asmx?WSDL", soapVersion = SOAP12);

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

@test:Config {}
function testSendOnly11() returns error? {
    Client soapClient = check new ("http://www.dneonline.com/calculator.asmx?WSDL");

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

    _ = check soapClient->sendOnly(body, "http://tempuri.org/Add");
}

@test:Config {}
function testSendOnly12() returns error? {
    Client soapClient = check new ("http://www.dneonline.com/calculator.asmx?WSDL", soapVersion = SOAP12);

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

    _ = check soapClient->sendOnly(body, "http://tempuri.org/Add");
}

@test:Config {}
function testSendReceive11WithHeaders() returns error? {
    Client soapClient = check new ("http://www.dneonline.com/calculator.asmx?WSDL");

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

    xml|mime:Entity[] response = check soapClient->sendReceive(body, "http://tempuri.org/Add",
                                                               {foo: ["bar1", "bar2"]});

    xml expected = xml `<soap:Body xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><AddResponse xmlns="http://tempuri.org/"><AddResult>5</AddResult></AddResponse></soap:Body>`;
    test:assertEquals(response, expected);
}

@test:Config {}
function testSendReceive12WithHeaders() returns error? {
    Client soapClient = check new ("http://www.dneonline.com/calculator.asmx?WSDL", soapVersion = SOAP12);

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

    xml|mime:Entity[] response = check soapClient->sendReceive(body, "http://tempuri.org/Add",
                                                               {foo: ["bar1", "bar2"]});

    xml expected = xml `<soap:Body xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><AddResponse xmlns="http://tempuri.org/"><AddResult>5</AddResult></AddResponse></soap:Body>`;
    test:assertEquals(response, expected);
}

@test:Config {}
function testSendReceive12WithoutSoapAction() returns error? {
    Client soapClient = check new ("http://www.dneonline.com/calculator.asmx?WSDL", soapVersion = SOAP12);

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

    xml|mime:Entity[] response = check soapClient->sendReceive(body);

    xml expected = xml `<soap:Body xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><AddResponse xmlns="http://tempuri.org/"><AddResult>5</AddResult></AddResponse></soap:Body>`;
    test:assertEquals(response, expected);
}

@test:Config {}
function testSendOnly12WithoutSoapAction() returns error? {
    Client soapClient = check new ("http://www.dneonline.com/calculator.asmx?WSDL", soapVersion = SOAP12);

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

    _ = check soapClient->sendOnly(body);
}

@test:Config {}
function testSendReceive12IncludingHeadersWithoutSoapAction() returns error? {
    Client soapClient = check new ("http://www.dneonline.com/calculator.asmx?WSDL", soapVersion = SOAP12);

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

    xml|mime:Entity[] response = check soapClient->sendReceive(body, (), {foo: ["bar1", "bar2"]});
    xml expected = xml `<soap:Body xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><AddResponse xmlns="http://tempuri.org/"><AddResult>5</AddResult></AddResponse></soap:Body>`;
    test:assertEquals(response, expected);
}
