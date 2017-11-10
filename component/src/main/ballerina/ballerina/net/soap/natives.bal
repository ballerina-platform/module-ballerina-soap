package ballerina.net.soap;

@Description { value:"SOAP Client Connector"}

@Description { value: "Enum to represent SOAP versions"}
enum SoapVersion {
   SOAP11, SOAP12
}

@Description { value: "Parameter struct represents a request for send actions."}
@Field {value:"headers: The array of SOAP headers for the SOAP envelop to send to the endpoint"}
@Field {value:"payload: The xml of SOAP payload for the SOAP envelop to send to the endpoint"}
@Field {value:"soapAction: The value of SOAP Action to send to the endpoint"}
@Field {value:"from: The value for the source endpoint parameter used for WS-Addressing"}
@Field {value:"to: The value for the destination parameter used for WS-Addressing"}
@Field {value:"replyTo: The value for the reply endpoint parameter used for WS-Addressing. This element
must be present if a reply is expected. If this element is present, messageId must be present"}
@Field {value:"faultTo: The value for the fault endpoint parameter used for WS-Addressing.
If this element is present, messageId must be present"}
@Field {value:"messageId: The value for the messageId parameter used for WS-Addressing"}
@Field {value:"relatesTo: The value for the relationship parameter used for WS-Addressing.
In the form of a (URI, QName) pair"}
@Field {value:"username: The value for the username parameter used for WS-Security Username Token"}
@Field {value:"password: The value for the password parameter used for WS-Security Username Token"}
public struct  Request {
   xml[] headers;
   xml payload;
   string soapAction;
   string from;
   string to;
   string replyTo;
   string faultTo;
   string messageId;
   string relatesTo;

   string username;
   string password;

}

@Description { value: "Parameter struct represents a response for send actions."}
@Field {value:"headers: The array of SOAP headers for the SOAP envelop receives from the endpoint"}
@Field {value:"payload: The xml of SOAP payload for the SOAP envelop receives from the endpoint"}
@Field {value:"from: The value for the source endpoint parameter used for WS-Addressing"}
@Field {value:"to: The value for the destination parameter used for WS-Addressing"}
@Field {value:"replyTo: The value for the reply endpoint parameter used for WS-Addressing. This element
must be present if a reply is sent. If this element is present, messageId must be present"}
@Field {value:"faultTo: The value for the fault endpoint parameter used for WS-Addressing.
If this element is present, messageId must be present"}
@Field {value:"messageId: The value for the messageId parameter used for WS-Addressing"}
@Field {value:"relatesTo: The value for the relationship parameter used for WS-Addressing.
In the form of a (URI, QName) pair"}
public struct Response {
    xml[] headers;
    xml payload;
    string from;
    string to;
    string replyTo;
    string faultTo;
    string messageId;
    string relatesTo;
}

@Description { value: "Parameter struct represents a SOAP Error."}
@Field {value:"msg: The value for the error message"}
@Field {value:"cause: The value for the cause"}
@Field {value:"stackTrace: The value for the stackTrace"}
@Field {value:"errorCode: The value for the errorCode"}
public struct SoapError {
   string msg;
   error cause;
   StackFrame[] stackTrace;
   int errorCode;
}

@Description { value:"SOAP client connector."}
public connector SoapClient () {

    @Description {value:"Send Robust requests."}
    @Param {value:"request: Request to be sent"}
    @Param { value:"endpointURL: Endpoint the request should be sent" }
    @Return { value:"SoapError: The error if an error occurred" }
    action sendRobust(Request request, string endpointURL) (SoapError) {
        return null;
    }

    @Description {value:"Fire and forget requests."}
    @Param {value:"request: Request to be sent"}
    @Param { value:"endpointURL: Endpoint the request should be sent" }
    action fireAndForget(Request request, string endpointURL) {

    }

    @Description {value:"Send request an expect a response."}
    @Param {value:"request: Request to be sent"}
    @Param { value:"endpointURL: Endpoint the request should be sent" }
    @Return { value:"Response: The response received from the backend" }
    @Return { value:"SoapError: The error if an error occurred" }
    action sendReceive(Request request, string endpointURL) (Response, SoapError) {
        return null, null;
    }

}
