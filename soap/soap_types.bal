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

public type Request {
    xml[] headers;
    xml payload;
    SoapVersion soapVersion = SOAP11;
    string soapAction;
    string ^"from";
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
};

public type Response {
    xml[] headers;
    xml payload;
    SoapVersion soapVersion;
    string ^"from";
    string to;
    string wsaAction;
    string replyTo;
    string faultTo;
    string messageId;
    string relatesTo;
};

public type SoapError {
    string message;
    error? cause;
};