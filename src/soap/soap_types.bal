// Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
//
// WSO2 Inc. licenses this file to you under the Apache License,
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
import ballerina/http;

public type SoapVersion SOAP11 | SOAP12;

public const SOAP11 = "SOAP11";
public const SOAP12 = "SOAP12";

public const PASSWORD_DIGEST = "PasswordDigest";
public const PASSWORD_TEXT = "PasswordText";
public type PasswordType PASSWORD_DIGEST | PASSWORD_TEXT;

# Represents the SOAP request.
#
# + headers - The array of SOAP headers that will be sent to the endpoint via the SOAP envelope 
# + wsAddressing - SOAP WS-Addressing related options
# + usernameToken - SOAP WS-Username token related options
# + httpHeaders - Headers to be included in the HTTP request
public type Options record {|
    xml[] headers?;
    WsAddressing wsAddressing?;
    UsernameToken usernameToken?;
    map<string> httpHeaders?;
|};

# Represents UsernameToken WS-Security.
#
# + username - The value of the username parameter used for the WS-Security Username Token
# + password - The value of the password parameter used for the WS-Security Username Token
# + passwordType - The value of the password type parameter used for the WS-Security Username Token
public type UsernameToken record {|
    string username;
    string password;
    PasswordType passwordType = PASSWORD_TEXT;
|};

# Represents WsAddressing related properties.
#
# + requestFrom - The value of the source endpoint parameter used for WS-Addressing
# + requestTo - The value of the destination parameter used for WS-Addressing
# + wsaAction - The value of the action parameter used for WS-Addressing
# + relatesTo - The value of the relationship parameter used for WS-Addressing (i.e., in the form of a (URI, QName) pair)
# + relationshipType - The value of the relationship type parameter used for WS-Addressing
# + replyTo - The value of the reply endpoint parameter used for WS-Addressing. This element must be present if a reply
#             is expected. If this element is present, messageId must be present
# + faultTo - The value of the fault endpoint parameter used for WS-Addressing. If this element is present, the messageId
#             must be present
# + messageId - The value of the messageId parameter used for WS-Addressing
public type WsAddressing record {|
    string requestFrom?;
    string requestTo?;
    string wsaAction?;
    string relatesTo?;
    string relationshipType?;
    string replyTo?;
    string faultTo?;
    string messageId?;
|};

# Represents the SOAP response.
#
# + soapVersion - The version of SOAP
# + headers - The array of SOAP headers, which the SOAP envelope receives from the endpoint
# + payload - The XML of the SOAP payload, which the SOAP envelope receives from the endpoint
# + httpResponse - The HTTP response
public type SoapResponse record {|
    SoapVersion soapVersion = SOAP11;
    xml[] headers?;
    xml payload?;
    http:Response httpResponse;
|};
