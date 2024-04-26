// Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

import ballerina/http;

service / on new http:Listener(9091) {

    resource function post .() returns xml|error {
        return xml `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><soap:Body><soap:Fault><faultcode>soap:MustUnderstand</faultcode><faultstring>System.Web.Services.Protocols.SoapHeaderException: SOAP header Security was not understood.
   at System.Web.Services.Protocols.SoapHeaderHandling.SetHeaderMembers(SoapHeaderCollection headers, Object target, SoapHeaderMapping[] mappings, SoapHeaderDirection direction, Boolean client)
   at System.Web.Services.Protocols.SoapServerProtocol.CreateServerInstance()
   at System.Web.Services.Protocols.WebServiceHandler.Invoke()
   at System.Web.Services.Protocols.WebServiceHandler.CoreProcessRequest()</faultstring></soap:Fault></soap:Body></soap:Envelope>`;
    }
}
