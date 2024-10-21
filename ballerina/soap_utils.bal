// Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com) All Rights Reserved.
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

import soap.wssec;

import ballerina/crypto;
import ballerina/http;
import ballerina/jballerina.java;
import ballerina/lang.regexp;
import ballerina/mime;
import ballerina/test;

public isolated function validateTransportBindingPolicy(ClientConfig config) returns Error? {
    if config.httpConfig.secureSocket is () {
        wssec:OutboundSecurityConfig|wssec:OutboundSecurityConfig[] securityPolicy = config.outboundSecurity;
        if securityPolicy is wssec:TransportBindingConfig {
            return error Error(INVALID_PROTOCOL_ERROR);
        } else if securityPolicy is wssec:OutboundSecurityConfig[] {
            foreach wssec:OutboundSecurityConfig policy in securityPolicy {
                if policy is wssec:TransportBindingConfig {
                    return error Error(INVALID_PROTOCOL_ERROR);
                }
            }
        }
    }
}

public isolated function getReadOnlyClientConfig(ClientConfig original) returns readonly & ClientConfig = @java:Method {
    'class: "org.wssec.WsSecurity"
} external;

public isolated function applySecurityPolicies(wssec:OutboundSecurityConfig|wssec:OutboundSecurityConfig[] security,
        xml envelope, boolean soap12 = true)
    returns xml|crypto:Error|wssec:Error {
    if security is wssec:TimestampTokenConfig {
        return wssec:applyTimestampToken(envelope, security);
    } else if security is wssec:UsernameTokenConfig {
        return wssec:applyUsernameToken(envelope, security);
    } else if security is wssec:SymmetricBindingConfig {
        return wssec:applySymmetricBinding(envelope, soap12, security);
    } else if security is wssec:AsymmetricBindingConfig {
        return wssec:applyAsymmetricConfigurations(envelope, soap12, security);
    } else if security is wssec:OutboundSecurityConfig {
        return envelope;
    } else {
        xml securedEnvelope = envelope.clone();
        foreach wssec:OutboundSecurityConfig policy in security {
            securedEnvelope = check applySecurityPolicies(policy, securedEnvelope, soap12);
        }
        return securedEnvelope;
    }
}

public isolated function applyInboundConfig(wssec:InboundConfig inboundSecurity, xml envelope,
                                             boolean soap12 = true) returns xml|Error {
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap11;
    xmlns "http://www.w3.org/2003/05/soap-envelope" as soap12;
    xml soapEnvelope = envelope;
    do {
        crypto:KeyStore? encryptionAlgorithm = inboundSecurity.decryptKeystore;
        if encryptionAlgorithm is crypto:KeyStore {
            wssec:Document doc = check wssec:decryptEnvelope(envelope, inboundSecurity);
            soapEnvelope = check doc.getEnvelope();
        }
        crypto:KeyStore? signatureAlgorithm = inboundSecurity.signatureKeystore;
        if signatureAlgorithm is crypto:KeyStore {
            boolean validity = check wssec:verifySignature(soapEnvelope, inboundSecurity);
            if !validity {
                return error Error("Signature verification failed");
            }
        }
        return soapEnvelope;
    } on fail error soapError {
        return error Error("Outbound security configurations do not match with the SOAP response", soapError);
    }
}

public isolated function sendReceive(xml|mime:Entity[] body, http:Client httpClient, string? soapAction = (),
                                     map<string|string[]> headers = {}, string path = "", boolean soap12 = true)
    returns xml|mime:Entity[]|Error {
    http:Request req = soap12 ? createSoap12HttpRequest(body, soapAction, headers)
        : createSoap11HttpRequest(body, <string>soapAction, headers);
    do {
        http:Response response = check httpClient->post(path, req);
        return check createSoapResponse(response);
    } on fail var soapError {
        return error Error(SOAP_RESPONSE_ERROR, soapError);
    }
}

public isolated function sendOnly(xml|mime:Entity[] body, http:Client httpClient, string? soapAction = (),
                                  map<string|string[]> headers = {}, string path = "", boolean soap12 = true)
    returns Error? {
    http:Request req = soap12 ? createSoap12HttpRequest(body, soapAction, headers)
        : createSoap11HttpRequest(body, <string>soapAction, headers);
    http:Response|http:ClientError response = httpClient->post(path, req);
    if response is http:ClientError {
        return error Error(response.message());
    }
}

isolated function createSoap11HttpRequest(xml|mime:Entity[] body, string soapAction,
                                          map<string|string[]> headers = {}) returns http:Request {
    http:Request req = new;
    if body is xml {
        req.setXmlPayload(body);
        req.setHeader(mime:CONTENT_TYPE, mime:TEXT_XML);
    } else {
        req.setBodyParts(body);
        req.setHeader(mime:CONTENT_TYPE, mime:MULTIPART_MIXED);
    }
    req.addHeader(SOAP_ACTION, soapAction);
    foreach string key in headers.keys() {
        req.addHeader(key, headers[key].toBalString());
    }
    return req;
}

isolated function createSoap12HttpRequest(xml|mime:Entity[] body, string? soapAction,
                                          map<string|string[]> headers = {}) returns http:Request {
    http:Request req = new;
    if body is xml {
        req.setXmlPayload(body);
    } else {
        req.setBodyParts(body);
    }
    if soapAction is string {
        mime:MediaType|mime:InvalidContentTypeError mediaType;
        if body is xml {
            mediaType = mime:getMediaType(mime:APPLICATION_SOAP_XML);
        } else {
            mediaType = mime:getMediaType(mime:MULTIPART_MIXED);
        }
        if mediaType is mime:MediaType {
            mediaType.parameters = {"action": string `"${soapAction}"`};
            req.setHeader(mime:CONTENT_TYPE, mediaType.toString());
        }
    } else if body is xml {
        req.setHeader(mime:CONTENT_TYPE, mime:TEXT_XML);
    } else {
        req.setHeader(mime:CONTENT_TYPE, mime:MULTIPART_MIXED);
    }
    foreach string key in headers.keys() {
        req.addHeader(key, headers[key].toBalString());
    }
    return req;
}

isolated function createSoapResponse(http:Response response) returns xml|mime:Entity[]|error {
    mime:Entity[]|http:ClientError payload = response.getBodyParts();
    if payload !is mime:Entity[] {
        xml|error responsePayload = response.getXmlPayload();
        if responsePayload is xml {
            return responsePayload;
        }
        return error(response.reasonPhrase);
    }
    return payload;
}

public function assertUsernameToken(string envelopeString, string username, string password,
        wssec:PasswordType passwordType, string body) returns error? {
    string:RegExp bodyData = check regexp:fromString(body);
    test:assertTrue(envelopeString.includesMatch(bodyData));
    string:RegExp usernameTokenTag = re `<wsse:UsernameToken .*>.*</wsse:UsernameToken>`;
    string:RegExp usernameTag = re `<wsse:Username>${username}</wsse:Username>`;
    test:assertTrue(envelopeString.includesMatch(usernameTokenTag));
    test:assertTrue(envelopeString.includesMatch(usernameTag));
    string:RegExp passwordTag = re `<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">${password}</wsse:Password>`;
    test:assertTrue(envelopeString.includesMatch(passwordTag));
}

public function assertSymmetricBinding(string envelopeString, string body) returns error? {
    string:RegExp bodyData = check regexp:fromString(body);
    test:assertTrue(envelopeString.includesMatch(bodyData));
    assertSignatureWithoutX509(envelopeString);
}

public function assertSignatureWithoutX509(string securedEnvelope) {
    string:RegExp signature = re `<ds:Signature xmlns:ds=".*" .*">.*</ds:Signature>`;
    string:RegExp signatureInfo = re `<ds:SignedInfo>.*</ds:SignedInfo>`;
    string:RegExp canonicalizationMethod = re `<ds:CanonicalizationMethod Algorithm=".*">`;
    string:RegExp signatureMethod = re `<ds:SignatureMethod Algorithm=".*"/>`;
    string:RegExp transformMethod = re `<ds:Transform Algorithm=".*"/>`;
    string:RegExp digestMethod = re `<ds:DigestMethod Algorithm=".*"/>`;
    string:RegExp signatureValue = re `<ds:SignatureValue>.*</ds:SignatureValue>`;

    test:assertTrue(securedEnvelope.includesMatch(signature));
    test:assertTrue(securedEnvelope.includesMatch(signatureInfo));
    test:assertTrue(securedEnvelope.includesMatch(canonicalizationMethod));
    test:assertTrue(securedEnvelope.includesMatch(signatureMethod));
    test:assertTrue(securedEnvelope.includesMatch(transformMethod));
    test:assertTrue(securedEnvelope.includesMatch(digestMethod));
    test:assertTrue(securedEnvelope.includesMatch(signatureValue));
}
