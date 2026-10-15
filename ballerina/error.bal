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

# Detail record for SOAP 1.1 fault errors per the SOAP 1.1 specification.
#
# + faultcode - The fault code identifying the fault (e.g., `soap:Server`)
# + faultstring - A human-readable explanation of the fault
# + faultactor - The URI of the SOAP actor that caused the fault, or nil if the fault
# source is the ultimate destination
# + detail - Application-specific error information, or nil if the fault is not related to
# Body processing
public type Soap11FaultDetail record {|
    string faultcode;
    string faultstring;
    string? faultactor;
    xml? detail;
|};

# Represents a SOAP 1.1 fault returned by the server.
public type Soap11FaultError distinct Error & error<Soap11FaultDetail>;

# Detail record for SOAP 1.2 fault errors per the SOAP 1.2 specification.
#
# + codeValue - The fault code value (e.g., `soap:Receiver`)
# + codeSubcode - The application-defined subcode value, or nil if not present
# + reasonText - A human-readable explanation of the fault
# + node - The URI of the SOAP node that generated the fault, or nil if not specified
# + role - The role the node was operating in when the fault occurred, or nil if not specified
# + detail - Application-specific error information, or nil if not present
public type Soap12FaultDetail record {|
    string codeValue;
    string? codeSubcode;
    string reasonText;
    string? node;
    string? role;
    xml? detail;
|};

# Represents a SOAP 1.2 fault returned by the server.
public type Soap12FaultError distinct Error & error<Soap12FaultDetail>;

# Union type representing any SOAP fault error.
public type SoapFaultError Soap11FaultError|Soap12FaultError;

# Represents a transport-level error (e.g., connection refused, DNS failure).
public type TransportError distinct Error;

# Detail record for HTTP application errors.
#
# + statusCode - The HTTP status code of the response
# + responseBody - The response body text, or nil if the body could not be read
public type HttpErrorDetail record {|
    int statusCode;
    string? responseBody;
|};

# Represents a non-2xx HTTP response that could not be parsed as a SOAP fault.
public type HttpApplicationError distinct Error & error<HttpErrorDetail>;

const SOAP_RESPONSE_ERROR = "Failed to create SOAP response";
const INVALID_PROTOCOL_ERROR = "Invalid protocol detected: Please use the `https` protocol instead of `http`.";
