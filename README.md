## Welcome to GitHub Pages

This page provide documentation on various technical aspects worked on by @gnsuryan

###  SSL configuration and setup of WebLogic Server

This section provides details on how a WebLogic Server can be configured to run on HTTPS/SSL 

WebLogic Application Servers can be configured to run in both SSL/non-SSL modes.
If configured to run in SSL mode, Weblogic Servers. By default, use the demo-cert configuration. 
These demonstration digital certificates, private keys, and trusted CA certificates should be used in a development environment only.
This document provides information on how to configure a WebLogic Server to use custom/user specific  SSL certificates in Microsoft Azure cloud platform.

Asbsumption:
This document assumes that the user has already obtained the ssl certificates/private key from a valid Certification Authority (CA).

The Certification Authority usually provides a zip file containing the following:
   * Your Server SSL Certificate
   * Your Root/Intermediate Certificates
   * Your Private Key

Note: The CA can provide a combined or separate root/intermediate certificates.  Also, there can be multiple intermediate certificates.
The root and intermediate certificates need to be combined to form a single combined certificate which would then be used to setup the SSL configuration on the WebLogic Server.

### Create and validate Combined Certificate

To create the combined certificate, copy the contents of the root certificates (including -----BEGIN CERTIFICATE----- and -----END CERTIFICATE----- ) and paste them one below the other in a text editor and save it as combined.crt

To validate the combined certificate, use the following command:
```
bash>openssl verify -CAfile combined.crt certificate.crt
certificate.crt: OK
```

### TrustStore  and IdentityStore

To configure SSL on WebLogic Server, we would require two kinds of security files.

  * TrustStore
  * IdentityStore

The TrustStore file contains the certificates from the intermediate/Root CA or other trusted third parties that is used in the SSL communication.

The IdentityStore or the KeyStore file contains the private key and the server SSL certificates
These files are usually stored in either JKS or PKCS12 formats.

### Create Trust Store

To create a truststore file, use the following command:
```
keytool -noprompt -import -alias <serveralias> -file <CA_Certificate> -keystore <truststorefile> -storepass <truststorepassword>
```

Example:
```
keytool -noprompt -import -alias trustcert -file ca_bundle.crt -keystore trust.jks -storepass mypassword
```

If there are multiple root/CA certificates, import then individually onto the same keystore file.
Example:

```
keytool -import -file /u01/app/cascerts/rootCA.cert -alias rootCA -keystore myTrustStore.jks
keytool -import -file /u01/app/cascerts/firstCA.cert -alias firstCA -keystore myTrustStore.jks
keytool -import -file /u01/app/cascerts/secondCA.cert -alias secondCA -keystore myTrustStore.jks
keytool -import -file /u01/app/cascerts/thirdCA.cert -alias thirdCA -keystore myTrustStore.jks
```

### Create Identity Store

Before creating the identity store, ensure that you merge the intermediate certificates all into one file.
Example:
```
cat ca_1.crt ca_2.crt > combined.crt
```

Now, create the identity.jks file using the following commands:

```
openssl pkcs12 -export -in certificate.crt -inkey private.key -chain -CAfile combined.crt -name servercert -out mycert.p12
keytool -noprompt -importkeystore -deststorepass mypassword -destkeystore identity.jks -srckeystore mycert.p12 -srcstoretype PKCS12 -srcalias servercert -destalias servercert -srckeypass mypassword
```

Once the identity store is created, you can validate the certificate chain using the following command:
```
java -Dssl.debug=true utils.ValidateCertChain -jks servercert identity.jks
```
