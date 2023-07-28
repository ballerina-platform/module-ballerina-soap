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

@test:Config {}
function testSendReceive11() returns error? {
    BasicClient soapClient = check new("http://ws.cdyne.com/phoneverify/phoneverify.asmx?wsdl");

    xml body = xml `<quer:CheckPhoneNumber xmlns:quer="http://ws.cdyne.com/PhoneVerify/query">
         <quer:PhoneNumber>18006785432</quer:PhoneNumber>
         <quer:LicenseKey>0</quer:LicenseKey>
      </quer:CheckPhoneNumber>`;

    var response = soapClient->sendReceive(body);

    xml expected = xml `<soap:Body xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><CheckPhoneNumberResponse xmlns="http://ws.cdyne.com/PhoneVerify/query"><CheckPhoneNumberResult><Company>Toll Free</Company><Valid>true</Valid><Use>Assigned to a code holder for normal use.</Use><State>TF</State><RC/><OCN/><OriginalNumber>18006785432</OriginalNumber><CleanNumber>8006785432</CleanNumber><SwitchName/><SwitchType/><Country>United States</Country><CLLI/><PrefixType>Landline</PrefixType><LATA/><sms>Landline</sms><Email/><AssignDate>Unknown</AssignDate><TelecomCity/><TelecomCounty/><TelecomState>TF</TelecomState><TelecomZip/><TimeZone/><Lat/><Long/><Wireless>false</Wireless><LRN/></CheckPhoneNumberResult></CheckPhoneNumberResponse></soap:Body>`;
    if response is error {
        test:assertFail(msg = response.message());
    } else {
        test:assertEquals(response, expected);
    }
}

@test:Config {}
function testSendReceive12() returns error? {
    BasicClient soapClient = check new("http://ws.cdyne.com/phoneverify/phoneverify.asmx?wsdl", version = SOAP12);

    xml body = xml `<quer:CheckPhoneNumber xmlns:quer="http://ws.cdyne.com/PhoneVerify/query">
         <quer:PhoneNumber>18006785432</quer:PhoneNumber>
         <quer:LicenseKey>0</quer:LicenseKey>
      </quer:CheckPhoneNumber>`;

    var response = soapClient->sendReceive(body);

    xml expected = xml `<soap:Body xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><CheckPhoneNumberResponse xmlns="http://ws.cdyne.com/PhoneVerify/query"><CheckPhoneNumberResult><Company>Toll Free</Company><Valid>true</Valid><Use>Assigned to a code holder for normal use.</Use><State>TF</State><RC/><OCN/><OriginalNumber>18006785432</OriginalNumber><CleanNumber>8006785432</CleanNumber><SwitchName/><SwitchType/><Country>United States</Country><CLLI/><PrefixType>Landline</PrefixType><LATA/><sms>Landline</sms><Email/><AssignDate>Unknown</AssignDate><TelecomCity/><TelecomCounty/><TelecomState>TF</TelecomState><TelecomZip/><TimeZone/><Lat/><Long/><Wireless>false</Wireless><LRN/></CheckPhoneNumberResult></CheckPhoneNumberResponse></soap:Body>`;
    if response is error {
        test:assertFail(msg = response.message());
    } else {
        test:assertEquals(response, expected);
    }
}

@test:Config {}
function testSendOnly11() returns error? {
    BasicClient soapClient = check new("http://ws.cdyne.com/phoneverify/phoneverify.asmx?wsdl");

    xml body = xml `<quer:CheckPhoneNumber xmlns:quer="http://ws.cdyne.com/PhoneVerify/query">
         <quer:PhoneNumber>18006785432</quer:PhoneNumber>
         <quer:LicenseKey>0</quer:LicenseKey>
      </quer:CheckPhoneNumber>`;

    var response = soapClient->sendOnly(body);

    if response is error {
        test:assertFail(msg = response.message());
    }
}

@test:Config {}
function testSendOnly12() returns error? {
    BasicClient soapClient = check new("http://ws.cdyne.com/phoneverify/phoneverify.asmx?wsdl", version = SOAP12);

    xml body = xml `<quer:CheckPhoneNumber xmlns:quer="http://ws.cdyne.com/PhoneVerify/query">
         <quer:PhoneNumber>18006785432</quer:PhoneNumber>
         <quer:LicenseKey>0</quer:LicenseKey>
      </quer:CheckPhoneNumber>`;

    var response = soapClient->sendOnly(body);

    if response is error {
        test:assertFail(msg = response.message());
    }
}
