Connects to SOAP backend from Ballerina. 

# Package Overview

The SOAP connector allows you to send an ordinary XML request to a soap backend by specifying the necessary details to
construct a SOAP envelope. It abstracts out the details of the creation of a SOAP envelope, headers and the body in a
SOAP message.

## Compatibility
|                          |    Version     |
|:------------------------:|:--------------:|
| Ballerina Language       | 0.973.0        |
| SOAP Version             | 1.1 & 1.2      |

## Sample

First, import the `wso2/scim2` package into the Ballerina project.
```
import wso2/soap;
```

Instantiate the connector by giving backend URL details in the HTTP client config.

```
endpoint soap:Client soapClient {
    clientConfig: {
        url: "http://localhost:9000"
    }
}
```

The `sendSoapRequest` function send a soap request to initiated backend url with the given `SoapRequest` object.
```
xml body = xml `<m0:getQuote xmlns:m0="http://services.samples">
                    <m0:request>
                        <m0:symbol>WSO2</m0:symbol>
                    </m0:request>
                </m0:getQuote>`;

soap:SoapRequest soapRequest = {
    soapAction: "urn:getQuote",
    payload: body
};

var details = soapClient->sendSoapRequest("/services/SimpleStockQuoteService", soapRequest);
match details {
    soap:SoapResponse soapResponse => io:println(soapResponse);
    soap:SoapError soapError => test:assertFail(msg = soapError.message);
}
```