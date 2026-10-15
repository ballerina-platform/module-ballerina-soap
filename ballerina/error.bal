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

# Defines the common error type for the module.
public type Error distinct error;

# Detail record for SOAP fault errors.
#
# + httpStatusCode - The HTTP status code of the response
# + soapFault - The SOAP fault XML payload
public type SoapFaultDetail record {|
    int httpStatusCode;
    xml soapFault;
|};

# Represents a SOAP fault returned by the server.
public type SoapFaultError distinct Error & error<SoapFaultDetail>;

# Detail record for network errors.
#
# + httpStatusCode - The HTTP status code of the response
public type NetworkErrorDetail record {|
    int httpStatusCode?;
|};

# Represents an error that occurs when a SOAP response cannot be interpreted as a SOAP fault.
# This includes transport-level failures (e.g., connection refused) and server error responses
# with non-XML bodies that cannot be parsed as SOAP faults.
public type NetworkError distinct Error & error<NetworkErrorDetail>;

const SOAP_RESPONSE_ERROR = "Failed to create SOAP response";
const INVALID_PROTOCOL_ERROR = "Invalid protocol detected: Please use the `https` protocol instead of `http`.";
