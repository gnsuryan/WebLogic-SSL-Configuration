**SSL: Introduction**

SSL provides secure connections by allowing two applications connecting over a network to authenticate each other's identity and by encrypting the data exchanged between the applications.

Authentication allows a server and optionally a client to verify the identity of the application on the other end of a network connection. Encryption makes data transmitted over the network intelligible only to the intended recipient.


**SSL on WebLogic Server**

SSL in WebLogic Server is an implementation of the SSL and Transport Layer Security (TLS) specifications. WebLogic Server supports SSL on a dedicated listen port which defaults to 7002.

For detailed documentation on configuring SSL in WebLogic Server, please refer to the documentation available at https://docs.oracle.com/en/middleware/fusion-middleware/weblogic-server/12.2.1.4/secmg/ssl.html#GUID-5274E688-51EC-4A63-A35E-FC718B35C897

WebLogic Server, by default, provides demo certificates/keystores for working in a development/test environment. However, it is very important that these certificates not be used in a production environment. 

We can also use self Signed Certificates for configuring WebLogic Server on Development/Test Environments. However, for Production environment, you will have to procure CA signed SSL Certificates from Certificate Authority (CA) such as Verisign, Let’s Encrypt, GoDaddy etc and create keystores from it.

**KeyStores**

Keystore is a storage facility to store cryptographic keys and certificates. <br/>
The following are the two most import Keystore types used.

<ul>
<li>JKS  - Java Key Store</li>
<li>PKCS12 – Public Key Cryptography Standards </li>
</ul>

**Keypass v/s Storepass**

•	Keypass is a password used to protect the private key of the generated key pair. If Keypass is not provided, then the Keypass value is set to the same value as the Storepass value.

•	Storepass is used to protect the integrity of the keystore.


**Steps to create Identity and Trust Keystores for Self Signed Certificate using Java Keytool**

The below sections outline the details on how to create Keystores for both Self Signed and CA signed Certificates.

**1.	Create Identity Keystore**

<pre>keytool -genkey -alias <privatekeyAlias> -keyalg <keyAlgorithm> -keysize <keysize> -sigalg <signatureAlgorithm> -validity <validityPeriodInDays> -keystore <keyStoreFileName> -keypass <keyPassPhrase> -storepass < IdentityKeyStorePassPhrase></pre>

Example: 

<pre>keytool -genkey -alias servercert -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -validity 365 -keystore identity.jks -keypass identityKeyPassword -storepass identityStorePassword</pre>


**2.	Convert a JKS keystore to PKCS12**

If you would like to use the keystore in PKCS12 format, you can convert a JKS keystore in to a PKCS12 keystore using the following command:

<pre>keytool -importkeystore -srckeystore <keystoreFileInJKSFormat> -destkeystore <keystoreFileInPKCS12Format> -deststoretype pkcs12</pre>

Example:

<pre>keytool -importkeystore -srckeystore identity.jks -destkeystore identity.p12 -deststoretype pkcs12</pre>


**3.	Export Identity KeyStore to create Certificate**

<pre>keytool -export -alias <privateKeyAlias> -noprompt -file <certificateName> -keystore <IdentityKeyStoreFileName> -storepass <IdentityKeyStorePassPhrase></pre>

Example:

<pre>keytool -export -alias servercert -noprompt -file server.cert -keystore identity.jks -storepass identityStorePassword</pre>


4.	Import the certificate into Trust Keystore

<pre>keytool -import -alias <trustStoreAlias> -noprompt -file <certificateName> -keystore <TrustKeyStoreFileName> -storepass <trustKeyStorePassPhrase></pre>

Example:

<pre>keytool -import -alias trustcert -noprompt -file root.cert -keystore trust.jks -storepass trustKeyStorePassword</pre>

You can convert the Trust Keystore from a JKS to PKCS12 format, using the same command which is specified in Step 2.

**Validating KeyStores**

Use the following command to validate the keystore file. Using this both the identity and trust keystores can be validated.

<pre>keytool  -list -v -keystore <keystorefile> </pre>

Example:

<pre>keytool -list -v -keystore identity.jks -storepass identityStorePassword  
keytool -list -v -keystore trust.jks -storepass trustKeyStorePassword   </pre>


**Steps to create Identity and Trust Keystores for CA Signed Certificate using Java Keytool**


