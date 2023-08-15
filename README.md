Ballerina SOAP Library
===================

[![Build](https://github.com/ballerina-platform/module-ballerina-soap/actions/workflows/build-timestamped-master.yml/badge.svg)](https://github.com/ballerina-platform/module-ballerina-soap/actions/workflows/build-timestamped-master.yml)
[![codecov](https://codecov.io/gh/ballerina-platform/module-ballerina-soap/branch/main/graph/badge.svg)](https://codecov.io/gh/ballerina-platform/module-ballerina-soap)
[![Trivy](https://github.com/ballerina-platform/module-ballerina-soap/actions/workflows/trivy-scan.yml/badge.svg)](https://github.com/ballerina-platform/module-ballerina-soap/actions/workflows/trivy-scan.yml)
[![GraalVM Check](https://github.com/ballerina-platform/module-ballerina-soap/actions/workflows/build-with-bal-test-graalvm.yml/badge.svg)](https://github.com/ballerina-platform/module-ballerina-soap/actions/workflows/build-with-bal-test-graalvm.yml)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/ballerina-platform/module-ballerina-soap.svg)](https://github.com/ballerina-platform/module-ballerina-soap/commits/main)
[![Github issues](https://img.shields.io/github/issues/ballerina-platform/ballerina-standard-library/module/soap.svg?label=Open%20Issues)](https://github.com/ballerina-platform/ballerina-standard-library/labels/module%2Fyaml)
[![codecov](https://codecov.io/gh/ballerina-platform/module-ballerina-soap/branch/main/graph/badge.svg)](https://codecov.io/gh/ballerina-platform/module-ballerina-soap)

This library provides APIs to send an ordinary XML request to a SOAP backend by specifying the necessary details to construct a SOAP envelope.

Soap module abstracts out the details of the creation of a SOAP envelope, headers, and the body in a SOAP message.

## Issues and projects

The **Issues** and **Projects** tabs are disabled for this repository as this is part of the Ballerina Standard Library. To report bugs, request new features, start new discussions, view project boards, etc., go to the Ballerina Standard Library [parent repository](https://github.com/ballerina-platform/ballerina-standard-library).

This repository contains only the source code of the package.

## Build from the source

### Set up the prerequisites

1. Download and install Java SE Development Kit (JDK) version 17 (from one of the following locations).
    * [Oracle](https://www.oracle.com/java/technologies/downloads/)

    * [OpenJDK](https://adoptium.net/)

      > **Note:** Set the JAVA_HOME environment variable to the path name of the directory into which you installed JDK.

2. Export your Github Personal access token with the read package permissions as follows.

              export packageUser=<Username>
              export packagePAT=<Personal access token>

### Build the source

Execute the commands below to build from source.

1. To build the library:
   ```    
   ./gradlew clean build
   ```

2. To run the integration tests:
   ```
   ./gradlew clean test
   ```
3. To build the module without the tests:
   ```
   ./gradlew clean build -x test
   ```
4. To debug module implementation:
   ```
   ./gradlew clean build -Pdebug=<port>
   ./gradlew clean test -Pdebug=<port>
   ```
5. To debug the module with Ballerina language:
   ```
   ./gradlew clean build -PbalJavaDebug=<port>
   ./gradlew clean test -PbalJavaDebug=<port>
   ```
6. Publish ZIP artifact to the local `.m2` repository:
   ```
   ./gradlew clean build publishToMavenLocal
   ```
7. Publish the generated artifacts to the local Ballerina central repository:
   ```
   ./gradlew clean build -PpublishToLocalCentral=true
   ```
8. Publish the generated artifacts to the Ballerina central repository:
   ```
   ./gradlew clean build -PpublishToCentral=true
   ```

## Contribute to Ballerina

As an open source project, Ballerina welcomes contributions from the community.

For more information, go to the [contribution guidelines](https://github.com/ballerina-platform/ballerina-lang/blob/master/CONTRIBUTING.md).

## Code of conduct

All contributors are encouraged to read the [Ballerina Code of Conduct](https://ballerina.io/code-of-conduct).

## Useful links

* Chat live with us via our [Discord server](https://discord.gg/ballerinalang).
* Post all technical questions on Stack Overflow with the [#ballerina](https://stackoverflow.com/questions/tagged/ballerina) tag.
* For more information go to the [`soap` library](https://lib.ballerina.io/ballerina/soap/latest).
* For example demonstrations of the usage, go to [Ballerina By Examples](https://ballerina.io/swan-lake/learn/by-example/).
