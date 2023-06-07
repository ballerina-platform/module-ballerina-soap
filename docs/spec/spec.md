# Specification: Ballerina Soap Library

_Owners_: @shafreenAnfar @MadhukaHarith92  
_Reviewers_: @shafreenAnfar  
_Created_: 2023/06/07  
_Updated_: 2023/06/07  
_Edition_: Swan Lake

## Introduction
This is the specification for the Soap standard library of [Ballerina language](https://ballerina.io/), which provides APIs to send an ordinary XML request to a SOAP backend by specifying the necessary details to construct a SOAP envelope.

The Soap library specification has evolved and may continue to evolve in the future. The released versions of the specification can be found under the relevant GitHub tag.

If you have any feedback or suggestions about the library, start a discussion via a [GitHub issue](https://github.com/ballerina-platform/ballerina-standard-library/issues) or in the [Discord server](https://discord.gg/ballerinalang). Based on the outcome of the discussion, the specification and implementation can be updated. Community feedback is always welcome. Any accepted proposal, which affects the specification is stored under `/docs/proposals`. Proposals under discussion can be found with the label `type/proposal` in GitHub.

The conforming implementation of the specification is released and included in the distribution. Any deviation from the specification is considered a bug.

## Contents

1. [Overview](#1-overview)
2. [Compatibility](#2-compatibility)
3. [Usage Example](#3-usage-example)

## 1. Overview
This specification elaborates on the functions available in the Soap library.

The soap module abstracts out the details of the creation of a SOAP envelope, headers, and the body in a SOAP message.

## 2. Compatibility

|                          |      Versions      |
|:------------------------:|:------------------:|
| Ballerina Language       | 2201.6.0           |
| SOAP Version             | 0.1                |

## 3. Usage Example

```ballerina
import ballerina/io;
import ballerina/soap;
  
public function main () {

    soap:Soap12Client soapClient = new("http://ws.cdyne.com/phoneverify/phoneverify.asmx?wsdl");

    xml body = xml `<quer:CheckPhoneNumber xmlns:quer="http://ws.cdyne.com/PhoneVerify/query"> 
         <quer:PhoneNumber>18006785432</quer:PhoneNumber>
         <quer:LicenseKey>0</quer:LicenseKey>
      </quer:CheckPhoneNumber>`;

    var response = soapClient->sendReceive(body);
    if (response is soap:SoapResponse) {
        io:println(response["payload"]);
    } else {
        io:println(response.message());
    }
}
```

Follow the steps below to run this example.

1. Save the example in a Ballerina file (e.g., `soapExample.bal`).
2. Execute the `ballerina run soapExample.bal` command to run the file.
   You will get a response similar to the following.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<soap:Body xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
   <CheckPhoneNumberResponse xmlns="http://ws.cdyne.com/PhoneVerify/query">
      <CheckPhoneNumberResult>
         <Company>Toll Free</Company>
         <Valid>true</Valid>
         <Use>Assigned to a code holder for normal use.</Use>
         <State>TF</State>
         <RC />
         <OCN />
         <OriginalNumber>18006785432</OriginalNumber>
         <CleanNumber>8006785432</CleanNumber>
         <SwitchName />
         <SwitchType />
         <Country>United States</Country>
         <CLLI />
         <PrefixType>Landline</PrefixType>
         <LATA />
         <sms>Landline</sms>
         <Email />
         <AssignDate>Unknown</AssignDate>
         <TelecomCity />
         <TelecomCounty />
         <TelecomState>TF</TelecomState>
         <TelecomZip />
         <TimeZone />
         <Lat />
         <Long />
         <Wireless>false</Wireless>
         <LRN />
      </CheckPhoneNumberResult>
   </CheckPhoneNumberResponse>
</soap:Body>
```
