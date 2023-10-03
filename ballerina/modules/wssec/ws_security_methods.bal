// Copyright (c) 2023, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import ballerina/crypto;
import ballerina/regex;
# Apply username token security policy to the SOAP envelope.
#
# + envelope - The SOAP envelope
# + usernameToken - The `UsernameTokenConfig` record with the required parameters
# + return - A `xml` type of SOAP envelope if the security binding is successfully added or else `wssec:Error`
public function applyUsernameToken(xml envelope, *UsernameTokenConfig usernameToken) returns xml|Error {
    Document document = check new (envelope);
    WSSecurityHeader wsSecurityHeader = check addSecurityHeader(document);
    WsSecurity wsSecurity = new;
    string securedEnvelope = check wsSecurity.applyUsernameTokenPolicy(wsSecurityHeader, usernameToken.username,
                                                                       usernameToken.password, usernameToken.passwordType);
    return convertStringToXml(securedEnvelope);
}
