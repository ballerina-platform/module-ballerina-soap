Connects from Ballerina to the SOAP backend. 

# Module Overview

The SOAP connector allows you to send an ordinary XML request to a SOAP backend by specifying the necessary details to
construct a SOAP envelope. It abstracts out the details of the creation of a SOAP envelope, headers, and the body in a
SOAP message.

## Compatibility
|                          |    Version     |
|:------------------------:|:--------------:|
| Ballerina Language       | 1.0.1        |
| SOAP Version             | 1.1 & 1.2      |

## Sample

First, import the `wso2/soap` module into the Ballerina project.
```ballerina
import wso2/soap;
```

Instantiate a connector by giving the backend URL.
```ballerina
soap:Soap11Client soap11Client = new("http://localhost:9000/services/SimpleStockQuoteService");
```  
or
```ballerina
soap:Soap12Client soap12Client = new("http://localhost:9000/services/SimpleStockQuoteService");
```

The `sendReceive` function sends a SOAP request to the initiated backend URL. For SOAP 1.1 requests, you can invoke the sendReceive function by passing the `body` and the `soapAction`. For SOAP 1.2 requests, you can invoke it by passing only the body. 

If you want to add WS-Security, WS-Addressing or other headers, you can configure the`Options` record accordingly and pass it to the function. 
```ballerina
xml body = xml `<m0:getQuote xmlns:m0="http://services.samples">
                    <m0:request>
                        <m0:symbol>WSO2</m0:symbol>
                    </m0:request>
                </m0:getQuote>`;

soap:UsernameToken usernameToken = {
    username: "admin",
    password: "admin",
    passwordType: "PasswordDigest"
};

soap:Options soapOptions = {
    usernameToken: usernameToken
};
    var response = soapClient->sendReceive("urn:mediate", body, soapOptions);
    if (response is soap:SoapResponse) {
        io:println(response);
    } else {
        io:println(response.detail()?.message);
    }
```
