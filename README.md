[![Build Status](https://travis-ci.org/wso2-ballerina/module-soap.svg?branch=master)](https://travis-ci.org/wso2-ballerina/module-soap)

# SOAP Connector

The SOAP connector allows you to send an ordinary XML request to a soap backend by specifying the necessary details to
construct a SOAP envelope. It abstracts out the details of the creation of a SOAP envelope, headers and the body in a
SOAP message.

## Compatibility

| Ballerina Language Version  | SOAP Version   |
|:---------------------------:|:--------------:|
| 0.982.0                     | 1.1 & 1.2      |

## Getting Started

Refer the [Getting Started](https://ballerina.io/learn/getting-started/) guide to download and install Ballerina.

### Usage Example

```ballerina
import wso2/soap;

function main (string... args) {
    endpoint soap:Client soapClient {
        clientConfig: {
            url: "http://localhost:9000"
        }
    }

    xml body = xml `<m0:getQuote xmlns:m0="http://services.samples">
                        <m0:request>
                            <m0:symbol>WSO2</m0:symbol>
                        </m0:request>
                    </m0:getQuote>`;

    soap:SoapRequest soapRequest = {
        soapAction: "urn:getQuote",
        payload: body
    };

    var details = soapClient->sendReceive("/services/SimpleStockQuoteService", soapRequest);
    match details {
        soap:SoapResponse soapResponse => io:println(soapResponse);
        soap:SoapError soapError => io:println(soapError);
    }
}
```

You may run this example using the following steps:

1. First [run the axis2 server](https://docs.wso2.com/display/EI620/Setting+Up+the+ESB+Samples#SettingUptheESBSamples-StartingtheAxis2server).
2. Save the example in a ballerina file (eg.: `soapExample.bal`)
3. Run the file using the command `ballerina run soapExample.bal`
4. You will get a response similar to the following

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ns:getQuoteResponse xmlns:ns="http://services.samples">
   <ns:return xmlns:ax21="http://services.samples/xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="ax21:GetQuoteResponse">
      <ax21:change>3.8023739781944386</ax21:change>
      <ax21:earnings>-9.58706726808414</ax21:earnings>
      <ax21:high>90.1204744818775</ax21:high>
      <ax21:last>87.00770771274415</ax21:last>
      <ax21:lastTradeTimestamp>Wed Jan 10 10:17:04 IST 2018</ax21:lastTradeTimestamp>
      <ax21:low>89.96298980939689</ax21:low>
      <ax21:marketCap>5.349140522956562E7</ax21:marketCap>
      <ax21:name>WSO2 Company</ax21:name>
      <ax21:open>-85.85962074870565</ax21:open>
      <ax21:peRatio>-19.963567651822213</ax21:peRatio>
      <ax21:percentageChange>3.867313309537189</ax21:percentageChange>
      <ax21:prevClose>98.32081535306169</ax21:prevClose>
      <ax21:symbol>WSO2</ax21:symbol>
      <ax21:volume>16449</ax21:volume>
   </ns:return>
</ns:getQuoteResponse>
```
