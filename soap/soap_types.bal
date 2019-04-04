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

public type SoapVersion SOAP11|SOAP12;

public const SOAP11 = "SOAP11";
public const SOAP12 = "SOAP12";

# Represents SOAP request.
#
# + headers - The array of SOAP headers for the SOAP envelop to send to the endpoint
# + wsAddressing - Soap WS-Addressing related options.
# + usernameToken - Soap WS-Username token related options.
public type Options record {|
    xml[] headers?;
    WsAddressing wsAddressing?;
    UsernameToken usernameToken?;
|};

# Represents UsernameToken WS-Security.
#
# + username - The value for the username parameter used for WS-Security Username Token
# + password - The value for the password parameter used for WS-Security Username Token
# + passwordType - The value for the password type parameter used for WS-Security Username Token
public type UsernameToken record {|
    string username;
    string password;
    string passwordType?;
|};

# Represents WsAddressing related properties.
#
# + requestFrom - The value for the source endpoint parameter used for WS-Addressing
# + requestTo - The value for the destination parameter used for WS-Addressing
# + wsaAction - The value for the action parameter used for WS-Addressing
# + relatesTo - The value for the relationship parameter used for WS-Addressing. In the form of a (URI, QName) pair
# + relationshipType - The value for the relationship type parameter used for WS-Addressing
# + replyTo - The value for the reply endpoint parameter used for WS-Addressing. This element must be present if a reply
#             is expected. If this element is present, messageId must be present
# + faultTo - The value for the fault endpoint parameter used for WS-Addressing. If this element is present, messageId
#             must be present
# + messageId - The value for the messageId parameter used for WS-Addressing
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

# Represents SOAP response.
#
# + soapVersion - The version of SOAP
# + headers - The array of SOAP headers for the SOAP envelop receives from the endpoint
# + payload - The xml of SOAP payload for the SOAP envelop receives from the endpoint
public type SoapResponse record {|
    SoapVersion soapVersion = SOAP11;
    xml[] headers?;
    xml payload?;
|};
