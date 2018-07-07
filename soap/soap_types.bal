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
// under the License.package soap;

public type SoapVersion "SOAP11"|"SOAP12";

@final public SoapVersion SOAP11 = "SOAP11";
@final public SoapVersion SOAP12 = "SOAP12";

documentation {
    F{{headers}} The array of SOAP headers for the SOAP envelop to send to the endpoint
    F{{payload}} The xml of SOAP payload for the SOAP envelop to send to the endpoint
    F{{soapVersion}} The version of SOAP
    F{{soapAction}} The value of SOAP Action to send to the endpoint
    F{{^"from"}} The value for the source endpoint parameter used for WS-Addressing
    F{{to}} The value for the destination parameter used for WS-Addressing
    F{{wsaAction}} The value for the action parameter used for WS-Addressing
    F{{relatesTo}} The value for the relationship parameter used for WS-Addressing. In the form of a (URI, QName) pair
    F{{relationshipType}} The value for the relationship type parameter used for WS-Addressing
    F{{replyTo}} The value for the reply endpoint parameter used for WS-Addressing. This element must be present if a reply is expected. If this element is present, messageId must be present
    F{{faultTo}} The value for the fault endpoint parameter used for WS-Addressing. If this element is present, messageId must be present
    F{{messageId}} The value for the messageId parameter used for WS-Addressing
    F{{username}} The value for the username parameter used for WS-Security Username Token
    F{{password}} The value for the password parameter used for WS-Security Username Token
    F{{passwordType}} The value for the password type parameter used for WS-Security Username Token
}
public type SoapRequest record {
    xml[] headers;
    xml payload;
    SoapVersion soapVersion = SOAP11;
    string soapAction;
    string ^"from";
    string to;
    string wsaAction;
    string relatesTo;
    string relationshipType;
    string replyTo;
    string faultTo;
    string messageId;
    string username;
    string password;
    string passwordType;
};

documentation {
    F{{headers}} The array of SOAP headers for the SOAP envelop receives from the endpoint
    F{{payload}} The xml of SOAP payload for the SOAP envelop receives from the endpoint
    F{{soapVersion}} The version of SOAP
}
public type SoapResponse record {
    xml[] headers;
    xml payload;
    SoapVersion soapVersion;
};

documentation {
    F{{message}} The value for the error message
    F{{cause}} The value for the cause
}
public type SoapError record {
    string message;
    error? cause;
};
