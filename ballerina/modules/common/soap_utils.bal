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
import soap.wssec;

import ballerina/crypto;
import ballerina/http;
import ballerina/mime;
import ballerina/regex;

public function validateTransportBindingPolicy(ClientConfig config) returns Error? {
    if config.httpConfig.secureSocket is () {
        wssec:InboundSecurityConfig|wssec:InboundSecurityConfig[] securityPolicy = config.inboundSecurity;
        if securityPolicy is wssec:TransportBindingConfig {
            return error Error("Invalid protocol detected: Please use the `https` protocol instead of `http`.");
        } else if securityPolicy is wssec:InboundSecurityConfig[] {
            foreach wssec:InboundSecurityConfig policy in securityPolicy {
                if policy is wssec:TransportBindingConfig {
                    return error Error("Invalid protocol detected: Please use the `https` protocol instead of `http`.");
                }
            }
        }
    }
}

public function retrieveHttpClientConfig(ClientConfig config) returns http:ClientConfiguration {
    return {
        httpVersion: config.httpConfig.httpVersion,
        http1Settings: config.httpConfig.http1Settings,
        http2Settings: config.httpConfig.http2Settings,
        timeout: config.httpConfig.timeout,
        poolConfig: config.httpConfig?.poolConfig,
        auth: config.httpConfig?.auth,
        retryConfig: config.httpConfig?.retryConfig,
        responseLimits: config.httpConfig.responseLimits,
        secureSocket: config.httpConfig?.secureSocket,
        circuitBreaker: config.httpConfig?.circuitBreaker
    };
}

public function applySecurityPolicies(wssec:InboundSecurityConfig|wssec:InboundSecurityConfig[] inboundSecurity, xml envelope)
    returns xml|wssec:Error {
    wssec:InboundSecurityConfig|wssec:InboundSecurityConfig[] securityPolicy = inboundSecurity;
    xml securedEnvelope;
    if securityPolicy is wssec:InboundSecurityConfig {
        if securityPolicy is wssec:TimestampTokenConfig {
            securedEnvelope = check wssec:applyTimestampToken(envelope, securityPolicy);
        } else if securityPolicy is wssec:UsernameTokenConfig {
            securedEnvelope = check wssec:applyUsernameToken(envelope, securityPolicy);
        } else if securityPolicy is wssec:SymmetricBindingConfig {
            securedEnvelope = check wssec:applySymmetricBinding(envelope, securityPolicy);
        } else if securityPolicy is wssec:AsymmetricBindingConfig {
            securedEnvelope = check wssec:applyAsymmetricBinding(envelope, securityPolicy);
        } else {
            securedEnvelope = envelope;
        }
    } else {
        foreach wssec:InboundSecurityConfig policy in securityPolicy {
            securedEnvelope = check applySecurityPolicies(policy, envelope);
        }
    }
    return securedEnvelope;
}

public function applyOutboundConfig(wssec:OutboundSecurityConfig outboundSecurity, xml envelope) returns xml|Error {
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap;
    xml soapEnvelope = envelope;
    do {
        if outboundSecurity.decryptionAlgorithm !is () {
            crypto:PrivateKey|crypto:PublicKey? clientPrivateKey = outboundSecurity.decryptionKey;
            if clientPrivateKey !is () {
                byte[] encData = check wssec:getEncryptedData(soapEnvelope);
                byte[] decryptDataResult = check wssec:decryptData(encData, wssec:RSA_ECB, clientPrivateKey);
                string decryptedBody = "<soap:Body >" + check string:fromBytes(decryptDataResult) + "</soap:Body>";
                string decryptedEnv = regex:replace(soapEnvelope.toString(), string `<soap:Body .*>.*</soap:Body>`, decryptedBody);
                soapEnvelope = check xml:fromString(decryptedEnv);
            }
        }
        if outboundSecurity.signatureAlgorithm !is () {
            crypto:PublicKey? serverPublicKey = outboundSecurity.verificationKey;
            if serverPublicKey !is () {
                byte[] signatureData = check wssec:getSignatureData(soapEnvelope);
                boolean verify = check crypto:verifyRsaSha256Signature((soapEnvelope/<soap:Body>/*).toBalString().toBytes(),
                                                                        signatureData, serverPublicKey);
                if !verify {
                    return error Error("Signature verification of the SOAP envelope has been failed");
                }
            }
        }
        return soapEnvelope;
    } on fail var e {
        return error Error("Outbound security configurations do not match with the SOAP response. ", e.cause());
    }
}

string path = "";

public function sendReceive(xml|mime:Entity[] body, http:Client httpClient, string? soapAction = (),
                            map<string|string[]> headers = {}, boolean soap12 = true) returns xml|Error {
    http:Request req;
    if soap12 {
        req = createSoap12HttpRequest(body, soapAction, headers);
    } else {
        req = createSoap11HttpRequest(body, <string>soapAction, headers);
    }
    http:Response response;
    do {
        response = check httpClient->post(path, req);
        if soap12 {
            return check createSoap12Response(response);
        }
        return check createSoap11Response(response);
    } on fail var err {
        return error Error(SOAP_RESPONSE_ERROR, err);
    }
}

public function sendOnly(xml|mime:Entity[] body, http:Client httpClient, string? soapAction = (),
                         map<string|string[]> headers = {}, boolean soap12 = true) returns Error? {
    http:Request req;
    if soap12 {
        req = createSoap12HttpRequest(body, soapAction, headers);
    } else {
        req = createSoap11HttpRequest(body, <string>soapAction, headers);
    }
    do {
        http:Response _ = check httpClient->post(path, req);
    } on fail var err {
        return error Error(SOAP_RESPONSE_ERROR, err);
    }
}

function createSoap11HttpRequest(xml|mime:Entity[] body,
                                 string soapAction, map<string|string[]> headers = {}) returns http:Request {
    http:Request req = new;
    if body is xml {
        req.setXmlPayload(body);
    } else {
        req.setBodyParts(body);
    }
    req.setHeader(mime:CONTENT_TYPE, mime:TEXT_XML);
    req.addHeader(SOAP_ACTION, soapAction);
    foreach string key in headers.keys() {
        req.addHeader(key, headers[key].toBalString());
    }
    return req;
}

function createSoap12HttpRequest(xml|mime:Entity[] body, string? soapAction,
                                 map<string|string[]> headers = {}) returns http:Request {
    http:Request req = new;
    if body is xml {
        req.setXmlPayload(body);
    } else {
        req.setBodyParts(body);
    }
    if soapAction is string {
        map<string> stringMap = {};
        stringMap[ACTION] = "\"" + soapAction + "\"";
        var mediaType = mime:getMediaType(mime:APPLICATION_SOAP_XML);
        if mediaType is mime:MediaType {
            mediaType.parameters = stringMap;
            req.setHeader(mime:CONTENT_TYPE, mediaType.toString());
        }
    } else {
        req.setHeader(mime:CONTENT_TYPE, mime:APPLICATION_SOAP_XML);
    }
    foreach string key in headers.keys() {
        req.addHeader(key, headers[key].toBalString());
    }
    return req;
}

function createSoap12Response(http:Response response) returns xml|error {
    xml payload = check response.getXmlPayload();
    xmlns "http://www.w3.org/2003/05/soap-envelope" as soap12;

    return payload/<soap12:Body>;
}

function createSoap11Response(http:Response response) returns xml|error {
    xml payload = check response.getXmlPayload();
    xmlns "http://schemas.xmlsoap.org/soap/envelope/" as soap11;
    return payload/<soap11:Body>;
}
