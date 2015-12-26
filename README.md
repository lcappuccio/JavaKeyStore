#JavaKeyStore
Basic Security Stuff

**Master**

[![Build Status](https://travis-ci.org/lcappuccio/java-keystore.svg?branch=master)](https://travis-ci.org/lcappuccio/java-keystore)
[![codecov.io](https://codecov.io/github/lcappuccio/java-keystore/coverage.svg?branch=master)](https://codecov.io/github/lcappuccio/java-keystore?branch=master)
[![Codacy Badge](https://api.codacy.com/project/badge/grade/0790c624be0c45c2ab481c307e294f93)](https://www.codacy.com/app/leo_4/java-keystore)

**Develop**

[![Build Status](https://travis-ci.org/lcappuccio/java-keystore.svg?branch=develop)](https://travis-ci.org/lcappuccio/java-keystore)
[![codecov.io](https://codecov.io/github/lcappuccio/java-keystore/coverage.svg?branch=develop)](https://codecov.io/github/lcappuccio/java-keystore?branch=develop)

##Installation
Run the shell script and generate the root key and the key that will be signed by the root key. Create the keystore with this key in it.

##Usage
Modify Main.main -> byte[] keyStorePasswd with the your keystore password

Modify Main.main -> String keyAlias with the key alias

Modify Main.main -> char[] keyPasswd with the key password

##Run
Run the project, signature validation in console, files to target/output.zip
