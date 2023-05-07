# JavaKeyStore
Basic Security Stuff

[![Build](https://github.com/lcappuccio/java-keystore/actions/workflows/build.yml/badge.svg)](https://github.com/lcappuccio/java-keystore/actions/workflows/build.yml)
[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=lcappuccio_java-keystore)](https://sonarcloud.io/summary/new_code?id=lcappuccio_java-keystore)

## Installation
Run the shell script and generate the root key and the key that will be signed by the root key. Create the keystore with this key in it.

## Usage
Modify Main.main -> byte[] keyStorePasswd with your keystore password

Modify Main.main -> String keyAlias with the key alias

Modify Main.main -> char[] keyPasswd with the key password

## Run
Run the project, signature validation in console, files to target/output.zip
