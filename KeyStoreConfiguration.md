###  TLS/SSL: Introduction

 TLS/SSL provides secure connections by allowing two applications connecting over a network to authenticate each other's identity and by encrypting the data exchanged between the applications.

Authentication allows a server and optionally a client to verify the identity of the application on the other end of a network connection. Encryption makes data transmitted over the network intelligible only to the intended recipient.


###  TLS/SSL on WebLogic Server

 TLS/SSL in WebLogic Server is an implementation of the Secure Sockets Layer (SSL) and Transport Layer Security (TLS) specifications. 
 WebLogic Server supports TLS/SSL on a dedicated listen port which defaults to 7002.

For detailed documentation on configuring TLS/SSL on WebLogic Server, please refer to the documentation available at https://docs.oracle.com/en/middleware/fusion-middleware/weblogic-server/12.2.1.4/secmg/ssl.html#GUID-5274E688-51EC-4A63-A35E-FC718B35C897

WebLogic Server, by default, provides demo certificates/keystores for working in a development/test environment. However, it is very important to note that these certificates should not be used in a production environment. 

Self Signed Certificates are usually created and configured on WebLogic Server on Development/Test Environments. However, for Production environment, one will have to procure CA signed TLS/SSL Certificates from a valid Certificate Authority (CA) such as Verisign, Let’s Encrypt, GoDaddy etc and create keystores from it.

### KeyStores

Keystore is a storage facility to store cryptographic keys and certificates.
The following are the two most import Keystore types used.

* JKS  - Java Key Store
* PKCS12 – Public Key Cryptography Standards

### Keypass v/s Storepass

*	Keypass is a password used to protect the private key of the generated key pair. If Keypass is not provided, then the Keypass value is set to the same value as the Storepass value.

*	Storepass is used to protect the integrity of the keystore.


### Steps to create Identity and Trust Keystores for Self Signed Certificate using Java Keytool

The below sections outline the details on how to create Keystores for both Self Signed and CA signed Certificates.

**1.	Create Identity Keystore**

```
keytool -genkey -alias <privatekeyAlias> -keyalg <keyAlgorithm> -keysize <keysize> -sigalg <signatureAlgorithm> -validity <validityPeriodInDays> -keystore <keyStoreFileName> -keypass <keyPassPhrase> -storepass <IdentityKeyStorePassPhrase>
```

Example: 

```
keytool -genkey -alias servercert -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -validity 365 -keystore identity.jks -keypass identityKeyPassword -storepass identityStorePassword
```

**2.	Convert a JKS keystore to PKCS12**

To use the keystore in PKCS12 format, convert a JKS keystore in to a PKCS12 keystore using the following command:

```
keytool -importkeystore -srckeystore <keystoreFileInJKSFormat> -destkeystore <keystoreFileInPKCS12Format> -deststoretype pkcs12
```

Example:

```
keytool -importkeystore -srckeystore identity.jks -destkeystore identity.p12 -deststoretype pkcs12
```

**3.	Export Identity KeyStore to create Certificate**

```
keytool -export -alias <privateKeyAlias> -noprompt -file <certificateName> -keystore <IdentityKeyStoreFileName> -storepass <IdentityKeyStorePassPhrase>
```

Example:

```
keytool -export -alias servercert -noprompt -file server.cert -keystore identity.jks -storepass identityStorePassword
```


**4.	Import the certificate into Trust Keystore**

```
keytool -import -alias <trustStoreAlias> -noprompt -file <certificateName> -keystore <TrustKeyStoreFileName> -storepass <trustKeyStorePassPhrase>
```

Example:

```
keytool -import -alias trustcert -noprompt -file root.cert -keystore trust.jks -storepass trustKeyStorePassword
```

To convert the Trust Keystore from a JKS to PKCS12 format, use the same command which is specified in Step 2.

### Validating KeyStores

Use the following command to validate the keystore file (both identity and trust keystores can be validated).

```
keytool  -list -v -keystore <keystorefile>
```

Example:

```
keytool -list -v -keystore identity.jks -storepass identityStorePassword  
keytool -list -v -keystore trust.jks -storepass trustKeyStorePassword
```

### Steps to create Identity and Trust Keystores for CA Signed Certificate using Java Keytool

The following diagram shows the complete process of creating/requesting for a new TLS/SSL Certificate from a Certificate Authority and configuring them on the WebLogic Server.

![SSL Certificate Generation and Configuration Process](https://github.com/gnsuryan/WebLogic-SSL-Configuration/raw/master/images/Cert_Process.png)

The following steps provide details on how each of the steps shown in the diagram is implemented.

**1. Create a Keystore using keytool**

```
keytool –keystore clientkeystore –genkey –alias client

Enter keystore password:  javacaps
What is your first and last name?
[Unknown]:  some.org.com
What is the name of your organizational unit?
[Unknown]:  Development
What is the name of your organization?
[Unknown]:  Some Org
What is the name of your City or Locality?
[Unknown]:  San Francisco
What is the name of your State or Province?
[Unknown]:  California
What is the two-letter country code for this unit?
[Unknown]:  US
Is <CN=some.org.com, OU=Development, O=Some Org, L=San Francisco, ST=California, 
C=US> correct?
[no]:  yes

Enter key password for <client>
(RETURN if same as keystore password):

```

**2. Generate a CSR using keytool**

```
keytool –keystore clientkeystore –certreq –alias client –keyalg rsa –file client.csr
```

**3. Submit the CSR to CA (Certification Authority)**

Submission of CSR (Certificate Signing Request) to CA can be done using online submissions or through email.
Once the CSR is received by the Certification Authority, the request will be verified and then a TLS/SSL certificate will be issued.
Once the verification process is completed, the Certification Authority can either send the TLS/SSL certificate over an email or can be downloaded by the client using online account.  

The Certification Authority usually provides a zip file containing the following:
   * Your Server SSL Certificate
   * Your Root/Intermediate Certificates
   * Your Private Key

Note: The CA can provide a combined or separate root/intermediate certificates.  Also, there can be multiple intermediate certificates.
The root and intermediate certificates need to be combined to form a single combined certificate which would then be used to setup the TLS/SSL configuration on the WebLogic Server.

**4. Create and validate Combined Certificate**

To create the combined certificate, copy the contents of the root certificates (including -----BEGIN CERTIFICATE----- and -----END CERTIFICATE----- ) and paste them one below the other in a text editor and save it as combined.crt

To validate the combined certificate, use the following command:
```
bash>openssl verify -CAfile combined.crt certificate.crt
certificate.crt: OK
```

**5. TrustStore  and IdentityStore**

To configure SSL on WebLogic Server, we would require two kinds of security files.

  * TrustStore
  * IdentityStore

The TrustStore file contains the certificates from the intermediate/Root CA or other trusted third parties that is used in the TLS/SSL communication.

The IdentityStore or the KeyStore file contains the private key and the server TLS/SSL certificates
These files are usually stored in either JKS or PKCS12 formats.

**5.1 Create Trust Store**

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

**5.2 Create Identity Store**

Before creating the identity store, ensure to merge the intermediate certificates all into one file.
Example:
```
cat ca_1.crt ca_2.crt > combined.crt
```

Now, create the identity.jks file using the following commands:

```
openssl pkcs12 -export -in certificate.crt -inkey private.key -chain -CAfile combined.crt -name servercert -out mycert.p12
keytool -noprompt -importkeystore -deststorepass mypassword -destkeystore identity.jks -srckeystore mycert.p12 -srcstoretype PKCS12 -srcalias servercert -destalias servercert -srckeypass mypassword
```

###6 Store keystores and passphrases in Azure KeyVault

Secure key management is essential to protected data in the cloud.

Azure Key Vault allows for storage of TLS/SSL certificates, confidential keys and other small secrets like passwords.

The following commands show how tls/ssl certifiates and keystores can be stored in Azure key vault securely.

```
az keyvault secret set --vault-name mySecureKeyVault  --encoding base64 --description text/plain --name identityKeyStoreData --file identity.jks
az keyvault secret set --vault-name mySecureKeyVault  --name "identityKeyPassPhrase" --value "identityKeyPassword"
az keyvault secret set --vault-name mySecureKeyVault  --encoding base64 --description text/plain --name trustKeyStoreData --file trust.jks
az keyvault secret set --vault-name mySecureKeyVault  --name "trustKeyPassPhrase" --value "trustKeyPassword"
az keyvault secret set --vault-name mySecureKeyVault  --name "privateKeyAlias" --value "servercert"
az keyvault secret set --vault-name mySecureKeyVault  --name "privateKeyPassPhrase" --value "myPrivateKey"

```
