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
import ballerina/crypto;
import ballerina/http;
import ballerina/mime;
import ballerina/soap;

const crypto:KeyStore serverKeyStore = {
    path: X509_KEY_STORE_PATH,
    password: KEY_PASSWORD
};
crypto:PrivateKey serverPrivateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(serverKeyStore, KEY_ALIAS,
                                                                                KEY_PASSWORD);
crypto:PublicKey serverPublicKey = check crypto:decodeRsaPublicKeyFromTrustStore(serverKeyStore, KEY_ALIAS);

service / on new http:Listener(9090) {

    resource function post .(http:Request request) returns xml|error {
        string action = check request.getHeader("SOAPAction");
        if action == "http://tempuri.org/Add" {
            return xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><soap:Body><AddResponse xmlns="http://tempuri.org/"><AddResult>5</AddResult></AddResponse></soap:Body></soap:Envelope>`;
        } else {
            return xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><soap:Body><soap:Fault><faultcode>soap:Client</faultcode><faultstring>System.Web.Services.Protocols.SoapException: Server did not recognize the value of HTTP Header SOAPAction: http://tempuri.org/invalid_action.
   at System.Web.Services.Protocols.Soap11ServerProtocolHelper.RouteRequest()
   at System.Web.Services.Protocols.SoapServerProtocol.RouteRequest(SoapServerMessage message)
   at System.Web.Services.Protocols.SoapServerProtocol.Initialize()
   at System.Web.Services.Protocols.ServerProtocol.SetContext(Type type, HttpContext context, HttpRequest request, HttpResponse response)
   at System.Web.Services.Protocols.ServerProtocolFactory.Create(Type type, HttpContext context, HttpRequest request, HttpResponse response, Boolean&amp; abortProcessing)</faultstring><detail/></soap:Fault></soap:Body></soap:Envelope>`;
        }
    }

    resource function post getPayload(http:Request request) returns xml|error {
        return check (check request.getBodyParts())[0].getXml();
    }

    resource function post getMimePayload(http:Request request) returns http:Response|error {
        http:Response response = new;
        mime:Entity[] mtomMessage = [];
        mime:Entity envelope = new;
        check envelope.setContentType("application/xop+xml");
        envelope.setContentId("<soap@envelope>");
        envelope.setBody(check (check request.getBodyParts())[0].getXml());
        mtomMessage.push(envelope);
        response.setBodyParts(mtomMessage);
        response.setPayload(mtomMessage);
        return response;
    }

    resource function post getSamePayload(http:Request request) returns xml|error {
        return check request.getXmlPayload();
    }

    resource function post getSecuredMimePayload(http:Request request) returns http:Response|error {
        xml payload = check (check request.getBodyParts())[0].getXml();
        http:Response response = new;
        mime:Entity[] mtomMessage = [];
        mime:Entity envelope = new;
        check envelope.setContentType("application/xop+xml");
        envelope.setContentId("<soap@envelope>");
        envelope.setBody(payload);
        mtomMessage.push(envelope);
        response.setBodyParts(mtomMessage);
        response.setPayload(mtomMessage);
        return response;
    }

    resource function post getSecuredPayload(http:Request request) returns xml|error {
        xml payload = check request.getXmlPayload();
        xml applyInboundConfig = check soap:applyInboundConfig(
            {
                decryptKeystore: {
                    path: KEY_STORE_PATH_2,
                    password: PASSWORD
                },
                signatureKeystore: {
                    path: KEY_STORE_PATH_2,
                    password: PASSWORD
                }
            },
            payload,
            false
        );
        return applyInboundConfig;
    }
}
