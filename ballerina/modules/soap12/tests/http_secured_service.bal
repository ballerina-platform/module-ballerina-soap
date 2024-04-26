// Copyright (c) 2024, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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

    resource function post .(http:Request request) returns http:Response|error {
        http:Response response = new;
        xml payload = xml `<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><soap:Body><soap:Fault><soap:Code><soap:Value>soap:Sender</soap:Value></soap:Code><soap:Reason><soap:Text xml:lang="en">System.Web.Services.Protocols.SoapException: Unable to handle request without a valid action parameter. Please supply a valid soap action.
   at System.Web.Services.Protocols.Soap12ServerProtocolHelper.RouteRequest()
   at System.Web.Services.Protocols.SoapServerProtocol.RouteRequest(SoapServerMessage message)
   at System.Web.Services.Protocols.SoapServerProtocol.Initialize()
   at System.Web.Services.Protocols.ServerProtocol.SetContext(Type type, HttpContext context, HttpRequest request, HttpResponse response)
   at System.Web.Services.Protocols.ServerProtocolFactory.Create(Type type, HttpContext context, HttpRequest request, HttpResponse response, Boolean&amp; abortProcessing)</soap:Text></soap:Reason><soap:Detail/></soap:Fault></soap:Body></soap:Envelope>`;
        response.setPayload(payload);
        return response;
    }
}
