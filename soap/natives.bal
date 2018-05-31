package ballerina.net.soap;

import ballerina.net.http;

@Description { value:"SOAP Client Connector" }

@Description { value: "Enum to represent SOAP versions" }
public enum SoapVersion {
    SOAP11, SOAP12
}

@Description { value: "Parameter struct represents a request for send actions." }
@Field { value:"headers: The array of SOAP headers for the SOAP envelop to send to the endpoint" }
@Field { value:"payload: The xml of SOAP payload for the SOAP envelop to send to the endpoint" }
@Field { value:"soapAction: The value of SOAP Action to send to the endpoint" }
@Field { value:"from: The value for the source endpoint parameter used for WS-Addressing" }
@Field { value:"to: The value for the destination parameter used for WS-Addressing" }
@Field { value:"replyTo: The value for the reply endpoint parameter used for WS-Addressing. This element
must be present if a reply is expected. If this element is present, messageId must be present" }
@Field { value:"faultTo: The value for the fault endpoint parameter used for WS-Addressing.
If this element is present, messageId must be present" }
@Field { value:"messageId: The value for the messageId parameter used for WS-Addressing" }
@Field { value:"relatesTo: The value for the relationship parameter used for WS-Addressing.
In the form of a (URI, QName) pair" }
@Field { value:"username: The value for the username parameter used for WS-Security Username Token" }
@Field { value:"password: The value for the password parameter used for WS-Security Username Token" }
public struct  Request {
    xml[] headers;
    xml payload;
    SoapVersion soapVersion;
    string soapAction;
    string from;
    string to;
    string wsaAction;
    string replyTo;
    string relationshipType;
    string faultTo;
    string messageId;
    string relatesTo;

    string username;
    string password;
    string passwordType;
}

@Description { value: "Parameter struct represents a response for send actions." }
@Field { value:"headers: The array of SOAP headers for the SOAP envelop receives from the endpoint" }
@Field { value:"payload: The xml of SOAP payload for the SOAP envelop receives from the endpoint" }
@Field { value:"from: The value for the source endpoint parameter used for WS-Addressing" }
@Field { value:"to: The value for the destination parameter used for WS-Addressing" }
@Field { value:"replyTo: The value for the reply endpoint parameter used for WS-Addressing. This element
must be present if a reply is sent. If this element is present, messageId must be present" }
@Field { value:"faultTo: The value for the fault endpoint parameter used for WS-Addressing.
If this element is present, messageId must be present" }
@Field { value:"messageId: The value for the messageId parameter used for WS-Addressing" }
@Field { value:"relatesTo: The value for the relationship parameter used for WS-Addressing.
In the form of a (URI, QName) pair" }
public struct Response {
    xml[] headers;
    xml payload;
    SoapVersion soapVersion;
    string from;
    string to;
    string wsaAction;
    string replyTo;
    string faultTo;
    string messageId;
    string relatesTo;
}

@Description { value: "Parameter struct represents a SOAP Error." }
@Field { value:"msg: The value for the error message" }
@Field { value:"cause: The value for the cause" }
@Field { value:"stackTrace: The value for the stackTrace" }
@Field { value:"errorCode: The value for the errorCode" }
public struct SoapError {
    string msg;
    error cause;
    StackFrame[] stackTrace;
    int errorCode;
}

@Description { value:"SOAP client connector." }
@Param { value:"serviceUri: Url of the service" }
@Param { value:"connectorOptions: connector options" }
public connector SoapClient (string serviceUri, http:Options connectorOptions) {

    endpoint<http:HttpClient> httpConnector {
        create http:HttpClient(serviceUri, connectorOptions);
    }

    @Description { value:"Send Robust requests.Sends the request and possibly receives an error" }
    @Param { value:"path: Resource path " }
    @Param { value:"request: Request to be sent" }
    @Return { value:"SoapError: The error if an error occurred" }
    action sendRobust (string path, Request request) (SoapError) {
        http:Request req = fillSOAPEnvelope(request, initSoapVersion(request.soapVersion));
        http:HttpConnectorError httpError = {};
        //In the send robust scenario response is ignored, but the error if it exists is returned
        _, httpError = httpConnector.post(path, req);
        return getSoapError(httpError);
    }

    @Description { value:"Fire and forget requests. Sends the request without the possibility of any response from the
     service (even an error)" }
    @Param { value:"path: Resource path " }
    @Param { value:"request: Request to be sent" }
    action fireAndForget (string path, Request request) {
        http:Request req = fillSOAPEnvelope(request, initSoapVersion(request.soapVersion));
        //In the fire and forget scenario both the response and the error are ignored.
        _, _ = httpConnector.post(path, req);
    }

    @Description { value:"Sends request and expects a response." }
    @Param { value:"path: Resource path " }
    @Param { value:"request: Request to be sent" }
    @Return { value:"Response: The response received from the backend" }
    @Return { value:"SoapError: The error if an error occurred" }
    action sendReceive (string path, Request request) (Response, SoapError) {
        SoapVersion soapVersion = initSoapVersion(request.soapVersion);
        http:Request req = fillSOAPEnvelope(request, soapVersion);
        http:Response resp = {};
        http:HttpConnectorError httpError = {};

        Response soapResponse = {};
        resp, httpError = httpConnector.post(path, req);
        if (resp != null && httpError == null) {
            soapResponse = createSOAPResponse(resp, soapVersion);
        }
        return soapResponse, getSoapError(httpError);
    }

}

@Description { value:"Returns a SoapError from the HttpConnectorError" }
@Param { value:"httpError: The HttpConnectorError" }
@Return { value:"SoapError: The SoapError obtained from the HttpConnectorError" }
function getSoapError(http:HttpConnectorError httpError) (SoapError) {
    if (httpError != null) {
        SoapError soapError = {};
        soapError.msg = httpError.msg;
        soapError.cause = httpError.cause;
        soapError.stackTrace = httpError.stackTrace;
        soapError.errorCode = httpError.statusCode;
        return soapError;
    }
    return null;
}

@Description { value:"Prepare a SOAP envelope with the xml to be sent." }
@Param { value:"request: The request to be sent" }
@Param { value:"soapVersion: The soap version of the request" }
@Return { value:"http:Request: Returns the soap Request as http:Request with the soap envelope" }
function fillSOAPEnvelope (Request request, SoapVersion soapVersion) (http:Request) {
    xml soapEnv = createSoapEnvelop(soapVersion);
    xml soapPayload = createSoapHeader(request, soapVersion);
    if (request.payload != null) {
        xml body = createSoapBody(request.payload, soapVersion);
        soapPayload = soapPayload + body;
    }
    soapEnv.setChildren(soapPayload);
    http:Request req = {};

    req.setXmlPayload(soapEnv);
    if (soapVersion == SoapVersion.SOAP11) {
        req.setHeader("Content-Type", "text/xml");
        req.addHeader("SOAPAction", request.soapAction);
    } else {
        req.setHeader("Content-Type", "application/soap+xml");
    }
    return req;
}

@Description { value:"Creates the soap response from the http Response" }
@Param { value:"resp: The http response" }
@Param { value:"soapVersion: The soap version of the request" }
@Return { value:"Response: The soap response created from the http response" }
function createSOAPResponse (http:Response resp, SoapVersion soapVersion) (Response) {
    Response response = {};
    response.soapVersion = soapVersion;
    xml soapHeaders = resp.getXmlPayload().selectChildren("Header").children();
    if (soapHeaders != null) {
        int i = 0;
        xml[] headersXML = [];
        while (i < lengthof soapHeaders) {
            headersXML[i] = soapHeaders[i];
            i = i + 1;
        }
        response.headers = headersXML;
    }
    response.payload = resp.getXmlPayload().selectChildren("Body").children().elements()[0];
    return response;
}

@Description { value:"Initializes the SoapVersion if it's null" }
@Param { value:"soapVersion: The given soapVersion " }
@Return { value:"SoapVersion: Returns SoapVersion.SOAP11 if given SoapVersion is null else returns the same SoapVersion" }
function initSoapVersion (SoapVersion soapVersion) (SoapVersion) {
    if (soapVersion == null) {
        soapVersion = SoapVersion.SOAP11;
    }
    return soapVersion;
}

@Description { value:"Provides the namespace for the given soap version." }
@Param { value:"soapVersion: The soap version of the request" }
@Return { value:"string: The namespace for the given soap version" }
function getNamespace (SoapVersion soapVersion) (string) {
    if (soapVersion == SoapVersion.SOAP11) {
        return "http://schemas.xmlsoap.org/soap/envelope/";
    }
    return "http://www.w3.org/2003/05/soap-envelope";
}

@Description { value:"Provides the encoding style for the given soap version" }
@Param { value:"soapVersion: The soap version of the request" }
@Return { value:"string: the encoding style for the given soap version" }
function getEncodingStyle (SoapVersion soapVersion) (string) {
    if (soapVersion == SoapVersion.SOAP11) {
        return "http://schemas.xmlsoap.org/soap/encoding/";
    }
    return "http://www.w3.org/2003/05/soap-encoding";
}

@Description { value:"Provides an empty soap envelope for the given soap version" }
@Param { value:"soapVersion: The soap version of the request" }
@Return { value:"xml: xml with the empty soap envelope" }
function createSoapEnvelop (SoapVersion soapVersion) (xml) {
    string namespace = getNamespace(soapVersion);
    string encodingStyle = getEncodingStyle(soapVersion);
    return xml `<soap:Envelope
                     xmlns:soap="{{namespace}}"
                     soap:encodingStyle="{{encodingStyle}}">
                     </soap:Envelope>`;
}

@Description { value:"Provides the soap headers in the request as xml" }
@Param { value:"request: Request to be sent" }
@Param { value:"soapVersion: The soap version of the request" }
@Return { value:"xml: xml with the empty soap header" }
function createSoapHeader (Request request, SoapVersion soapVersion) (xml) {
    string namespace = getNamespace(soapVersion);
    xml headersRoot = xml `<soap:Header xmlns:soap="{{namespace}}"></soap:Header>`;
    xml headerElement;
    if (request.headers != null) {
        xml[] headers = request.headers;
        int i = 1;
        xml headersXML = headers[0];
        while (i < lengthof headers) {
            headersXML = headersXML + headers[i];
            i = i + 1;
        }
        headerElement = headersXML;
    }
    if (request.to != "") {
        if (headerElement != null) {
            headerElement = headerElement + getWSAddressingHeaders(request);
        } else {
            headerElement = getWSAddressingHeaders(request);
        }
    }
    if (request.username != "") {
        if (headerElement != null) {
            headerElement = headerElement + getWSSecUsernameTokenHeaders(request);
        } else {
            headerElement = getWSSecUsernameTokenHeaders(request);
        }
    }
    if (headerElement != null) {
        headersRoot.setChildren(headerElement);
    }
    return headersRoot;
}
@Description { value:"Provides the soap body in the request as xml" }
@Param { value:"request: Request to be sent" }
@Param { value:"soapVersion: The soap version of the request" }
@Return { value:"xml: xml with the empty soap body" }
function createSoapBody (xml payload, SoapVersion soapVersion) (xml) {
    string namespace = getNamespace(soapVersion);
    xml bodyRoot = xml `<soap:Body xmlns:soap="{{namespace}}"></soap:Body>`;
    bodyRoot.setChildren(payload);
    return bodyRoot;
}

@Description { value:"Provides the WS addressing header" }
@Param { value:"request: Request to be sent" }
@Return { value:"xml: xml with the WS addressing header" }
function getWSAddressingHeaders (Request request) (xml) {
    xml headerElement;
    xmlns "https://www.w3.org/2005/08/addressing" as wsa;
    xml toElement = xml `<wsa:To>{{request.to}}</wsa:To>`;
    headerElement = toElement;
    xml actionElement = xml `<wsa:Action>{{request.wsaAction}}</wsa:Action>`;
    headerElement = headerElement + actionElement;
    if (request.relatesTo != "") {
        xml relatesToElement = xml `<wsa:RelatesTo>{{request.relatesTo}}</wsa:RelatesTo>`;
        if (request.relationshipType != "") {
            relatesToElement@["RelationshipType"] = request.relationshipType;
        }
        headerElement = headerElement + relatesToElement;
    }
    if (request.from != "") {
        xml fromElement = xml `<wsa:From>{{request.from}}</wsa:From>`;
        headerElement = headerElement + fromElement;
    }
    if (request.replyTo != "") {
        if (request.messageId != "") {
            xml messageIDElement = xml `<wsa:MessageID>{{request.messageId}}</wsa:MessageID>`;
            headerElement = headerElement + messageIDElement;
        }else{
            error  err = {msg: "If ReplyTo element is present, wsa:MessageID MUST be present"};
            throw err;
        }
        xml replyToElement = xml `<wsa:ReplyTo><wsa:Address>{{request.replyTo}}</wsa:Address></wsa:ReplyTo>`;
        headerElement = headerElement + replyToElement;
    }
    if (request.faultTo != "") {
        xml faultToElement = xml `<wsa:FaultTo>{{request.faultTo}}</wsa:FaultTo>`;
        headerElement = headerElement + faultToElement;
    }
    return headerElement;
}

@Description { value:"Provides the WS Secure Username Token Headers" }
@Param { value:"request: Request to be sent" }
@Return { value:"xml: xml with the WS Secure Username Token Headers" }
function getWSSecUsernameTokenHeaders (Request request) (xml) {
    xmlns "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" as wsse;
    xmlns "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" as wsu;
    xml securityRoot = xml `<wsse:Security></wsse:Security>`;
    xml usernameTokenRoot = xml `<wsse:UsernameToken> </wsse:UsernameToken>`;
    xml usernameElement = xml `<wsse:Username>{{request.username}}</wsse:Username>`;
    xml headerElement = usernameElement;
    xml passwordElement = xml `<wsse:Password>{{request.password}}</wsse:Password>`;
    if (request.passwordType != "") {
        passwordElement@["Type"] = request.passwordType;
    }
    headerElement = headerElement + passwordElement;
    usernameTokenRoot.setChildren(headerElement);
    Time time = currentTime();
    xml timestampElement = xml `<wsu:Timestamp><wsu:Created>{{time.toString()}}</wsu:Created></wsu:Timestamp>`;
    usernameTokenRoot = usernameTokenRoot + timestampElement;
    securityRoot.setChildren(usernameTokenRoot);
    return securityRoot;
}
