import ballerina.net.soap;

function testSoap11 (xml soapBody, string soapAction) (soap:Request, soap:SoapVersion, string) {
    soap:SoapVersion version11 = soap:SoapVersion.SOAP11;

    soap:Request request = {
                               soapAction:soapAction,
                               soapVersion:version11,
                               payload:soapBody
                           };
    return request, request.soapVersion, request.soapAction;
}

