package ballerina.net.soap;

import ballerina.net.http;

@Description { value:"SOAP Client Connector"}

@Description { value: "Enum to represent SOAP versions"}
public enum SoapVersion {
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
    SoapVersion soapVersion;
    string from;
    string to;
    string wsaAction;
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
        endpoint<http:HttpClient> httpConnector {
            create http:HttpClient(endpointURL, getConnectorConfigs());
        }
        SoapVersion soapVersion = init(request.soapVersion);
        xml soapEnv = startEnvelop(soapVersion);
        xml soapPayload = addSoapHeaders(request, soapVersion);
        if (request.payload != null) {
            xml body = addSoapBody(request.payload, soapVersion);
            soapPayload = soapPayload + body;
        }
        soapEnv.setChildren(soapPayload);
        http:Request req = {};
        http:Response resp = {};
        http:HttpConnectorError httpError = {};
        req.setXmlPayload(soapEnv);
        if (soapVersion == SoapVersion.SOAP11) {
            req.setHeader("Content-Type", "text/xml;charset=UTF-8");
            req.addHeader("SOAPAction", request.soapAction);
        } else {
            req.setHeader("Content-Type", "application/soap+xml");
        }
        Response soapResponse = {};
        SoapError soapError = {};
        resp, httpError = httpConnector.post("", req);
        if (resp != null) {
            soapResponse = createResponse(resp, soapVersion);
        }
        if (httpError != null) {
            soapError.msg = httpError.msg;
            soapError.cause = httpError.cause;
            soapError.stackTrace = httpError.stackTrace;
            soapError.errorCode = httpError.statusCode;
        }
        return soapResponse, soapError;
    }

}

function getConnectorConfigs() (http:Options) {
    http:Options option = {
                              ssl: {
                                       trustStoreFile:"${ballerina.home}/bre/security/client-truststore.jks",
                                       trustStorePassword:"wso2carbon"
                                   },
                              followRedirects: {}
                          };
    return option;
}

function createResponse(http:Response resp, SoapVersion soapVersion) (Response) {
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
    response.payload = resp.getXmlPayload().selectChildren("Body").children();
    return response;
}

function init(SoapVersion soapVersion) (SoapVersion) {
    if (soapVersion == null) {
        soapVersion = SoapVersion.SOAP11;
    }
    return soapVersion;
}

function getNamespace(SoapVersion soapVersion) (string) {
    if (soapVersion == SoapVersion.SOAP11) {
        return "http://schemas.xmlsoap.org/soap/envelope/";
    }
    return "http://www.w3.org/2003/05/soap-envelope";
}

function getEncodingStyle(SoapVersion soapVersion) (string) {
    if (soapVersion == SoapVersion.SOAP11) {
        return "http://schemas.xmlsoap.org/soap/encoding/";
    }
    return "http://www.w3.org/2003/05/soap-encoding";
}

function startEnvelop(SoapVersion soapVersion) (xml) {
    string namespace = getNamespace(soapVersion);
    string encodingStyle = getEncodingStyle(soapVersion);
    return xml `<soap:Envelope
                     xmlns:soap="{{namespace}}"
                     soap:encodingStyle="{{encodingStyle}}">
                     </soap:Envelope>`;
}

function addSoapHeaders(Request request, SoapVersion soapVersion) (xml) {
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
        headerElement = addWSAddressingHeaders(request);
    }
    if (request.username != "") {
        headerElement = addWSSecUsernameTokenHeaders(request);
    }
    if (headerElement != null) {
        headersRoot.setChildren(headerElement);
    }
    return headersRoot;
}

function addSoapBody(xml payload, SoapVersion soapVersion) (xml) {
    string namespace = getNamespace(soapVersion);
    xml bodyRoot = xml `<soap:Body xmlns:soap="{{namespace}}"></soap:Body>`;
    bodyRoot.setChildren(payload);
    return bodyRoot;
}

function addWSAddressingHeaders(Request request) (xml) {
    xml headerElement;
    xmlns "https://www.w3.org/2005/08/addressing" as wsa;
    xml toElement = xml `<wsa:To>{{request.to}}</wsa:To>`;
    headerElement = toElement;
    xml actionElement = xml `<wsa:Action>{{request.wsaAction}}</wsa:Action>`;
    headerElement = headerElement + actionElement;
    if (request.messageId != "") {
        xml messageIDElement = xml `<wsa:MessageID>{{request.messageId}}</wsa:MessageID>`;
        headerElement = headerElement + messageIDElement;
    }
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
        xml replyToElement = xml `<wsa:From>{{request.replyTo}}</wsa:From>`;
        headerElement = headerElement + replyToElement;
    }
    if (request.faultTo != "") {
        xml faultToElement = xml `<wsa:FaultTo>{{request.faultTo}}</wsa:FaultTo>`;
        headerElement = headerElement + faultToElement;
    }
    return headerElement;
}

function addWSSecUsernameTokenHeaders(Request request) (xml) {
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
