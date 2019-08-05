![Android Logo](img/android-logo.png)
# EOSIO SDK for Java: Android KeyStore Signature Provider ![EOSIO Alpha](https://img.shields.io/badge/EOSIO-Alpha-blue.svg)

[![Software License](https://img.shields.io/badge/license-MIT-lightgrey.svg)](https://github.com/EOSIO/eosio-java-softkey-signature-provider/blob/master/LICENSE)
![Language Kotlin](https://img.shields.io/badge/Language-Kotlin-yellow.svg)
![](https://img.shields.io/badge/Deployment%20Target-Android-blue.svg)

Android KeyStore Signature Provider is an example pluggable signature provider for [EOSIO SDK for Java](https://github.com/EOSIO/eosio-java) written in Kotlin. It allows for signing transactions using Android KeyStore keys.

*All product and company names are trademarks™ or registered® trademarks of their respective holders. Use of them does not imply any affiliation with or endorsement by them.*

## Contents

- [About Signature Providers](#about-signature-providers)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Android Example App](#android-example-app)
- [Library Methods](#library-methods)
- [Want to Help?](#want-to-help)
- [License & Legal](#license)

## About Signature Providers

The Signature Provider abstraction is arguably the most useful of all of the [EOSIO SDK for Java](https://github.com/EOSIO/eosio-java) providers. It is responsible for:

* finding out what keys are available for signing (`getAvailableKeys`), and
* requesting and obtaining transaction signatures with a subset of the available keys (`signTransaction`).

By simply switching out the signature provider on a transaction, signature requests can be routed any number of ways. 

All signature providers must conform to the [ISignatureProvider](https://github.com/EOSIO/eosio-java/blob/master/eosiojava/src/main/java/one/block/eosiojava/interfaces/ISignatureProvider.java) Protocol.

### Prerequisites

* Android (minimum SDK version 23, compile SDK version 29, target SDK version 29)
* Kotlin 1.3.31+
* Gradle 4.10.1+

Since EOSIO SDK for Java: Android KeyStore Signature Provider is an Android specific project, we recommend using Android Studio if you are going to work on it.  

## Installation

This provider is intended to be used in conjunction with [EOSIO SDK for Java](https://github.com/EOSIO/eosio-java) as a provider plugin.

To use Android KeyStore Signature Provider with EOSIO SDK for Java in your app, add the following modules to your `build.gradle`:

```java
implementation 'one.block:eosiojava:0.1.0'
implementation 'one.block:eosioandroidkeystoresignatureprovider:0.1.0'
```

If you are using Android KeyStore Signature Provider, or any library that depends on it, in an Android application you must also add the following to your application's `build.gradle` file in the `android` section:

```groovy
// Needed to get bitcoin-j to produce a valid apk for android.
packagingOptions {
    exclude 'lib/x86_64/darwin/libscrypt.dylib'
    exclude 'lib/x86_64/freebsd/libscrypt.so'
    exclude 'lib/x86_64/linux/libscrypt.so'
}
```
The `build.gradle` files for the project currently include configurations for publishing the project to Artifactory.  These should be removed if you are not planning to use Artifactory or you will encounter build errors.  To do so, make the changes marked by comments throughout the files.

Then refresh your gradle project. Then you're all set for the [Basic Usage](#basic-usage) example!

## Basic Usage

Generally, signature providers are called by the [TransactionProcessor](https://github.com/EOSIO/eosio-java/blob/master/eosiojava/src/main/java/one/block/eosiojava/session/TransactionProcessor.java) during signing. (See an [example here](https://github.com/EOSIO/eosio-java#basic-usage).) If you find, however, that you need to get available keys or request signing directly, this library can be invoked as follows:

```kotlin
val eosioAndroidKeyStoreSignatureProvider: EosioAndroidKeyStoreSignatureProvider =
            EosioAndroidKeyStoreSignatureProvider.Builder().build()

val allKeyInKeyStore: List<String> = eosioAndroidKeyStoreSignatureProvider.availableKeys
```

And to generate a private key:

```kotlin
val isKeyCreated:Boolean = EosioAndroidKeyStoreUtility.generateKeyInAndroidStore("key_alias")
```

To sign an `EosioTransactionSignatureRequest`, you should first create it with your serialized transaction and list of public keys. EOSIO SDK for Java handles the creation of the object for you.

Finally, call `signTransaction` to sign.

```kotlin
val transactionSignatureRequest: EosioTransactionSignatureRequest =
            EosioTransactionSignatureRequest(
                serializedTransaction,
                signingPublicKeys,
                chainID,
                abis,
                isModifiable
            )

val eosioAndroidKeyStoreSignatureProvider: EosioAndroidKeyStoreSignatureProvider =
            EosioAndroidKeyStoreSignatureProvider.Builder().build()

eosioAndroidKeyStoreSignatureProvider.signTransaction(transactionSignatureRequest)
```

## Android Example App

If you'd like to see an example implementation that uses a different Signature Provider, check out our open source [Android Example App](https://github.com/EOSIO/eosio-java-android-example-app)-a working application that fetches an account's token balance and pushes a transfer action.

## Library Methods

This library is an example implementation of [ISignatureProvider](https://github.com/EOSIO/eosio-java/blob/master/eosiojava/src/main/java/one/block/eosiojava/interfaces/ISignatureProvider.java). It implements the following protocol methods:

* `signTransaction(EosioTransactionSignatureRequest eosioTransactionSignatureRequest)` signs a `Transaction`
* `getAvailableKeys()` returns an array containing the public keys associated with the private keys that the object is initialized with

The library also includes a utility class that allows the user to manage keys in the Android Keystore (e.g. query, add, or delete).  Key management includes the ability to add password protection and use user-defined aliases to label and query the keys.  The keys that are queried are automatically converted to the EOS format so that they are automatically compatible with EOS mainnet applications.  The class is called EosioAndroidKeyStoreUtility and can be referenced as follows:

Generate a key by calling:

* `EosioAndroidKeyStoreUtility.generateAndroidKeyStoreKey(alias:String)`

Query all keys in KeyStore by calling:

* `EosioAndroidKeyStoreUtility.getAllAndroidKeyStoreKeysInEOSIOFormat(
            password: KeyStore.ProtectionParameter?,
            loadStoreParameter: KeyStore.LoadStoreParameter?)`
        
Query a specific key in the KeyStore by calling:

* `EosioAndroidKeyStoreUtility.getAndroidKeyStoreKeyInEOSIOFormat(
            alias: String,
            password: KeyStore.ProtectionParameter?,
            loadStoreParameter: KeyStore.LoadStoreParameter?)`
            
Sign any data with a specific key in the KeyStore by calling:

* `EosioAndroidKeyStoreUtility.sign(
            data: ByteArray,
            alias: String,
            password: KeyStore.ProtectionParameter?,
            loadStoreParameter: KeyStore.LoadStoreParameter?)`
            
Delete a key in the KeyStore by its alias by calling:

* `EosioAndroidKeyStoreUtility.deleteKeyByAlias(
            keyAliasToDelete: String,
            loadStoreParameter: KeyStore.LoadStoreParameter?)`
            
Delete all keys in the KeyStore by calling:

* `EosioAndroidKeyStoreUtility.deleteAllKeys(loadStoreParameter: KeyStore.LoadStoreParameter?)`

## Want to help?

Interested in contributing? That's awesome! Here are some [Contribution Guidelines](./CONTRIBUTING.md) and the [Code of Conduct](./CONTRIBUTING.md#conduct).

## License

[MIT](./LICENSE)

## Important

See LICENSE for copyright and license terms.  Block.one makes its contribution on a voluntary basis as a member of the EOSIO community and is not responsible for ensuring the overall performance of the software or any related applications.  We make no representation, warranty, guarantee or undertaking in respect of the software or any related documentation, whether expressed or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall we be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or documentation or the use or other dealings in the software or documentation. Any test results or performance figures are indicative and will not reflect performance under all conditions.  Any reference to any third party or third-party product, service or other resource is not an endorsement or recommendation by Block.one.  We are not responsible, and disclaim any and all responsibility and liability, for your use of or reliance on any of these resources. Third-party resources may be updated, changed or terminated at any time, so the information here may be out of date or inaccurate.  Any person using or offering this software in connection with providing software, goods or services to third parties shall advise such third parties of these license terms, disclaimers and exclusions of liability.  Block.one, EOSIO, EOSIO Labs, EOS, the heptahedron and associated logos are trademarks of Block.one.

Wallets and related components are complex software that require the highest levels of security.  If incorrectly built or used, they may compromise users’ private keys and digital assets. Wallet applications and related components should undergo thorough security evaluations before being used.  Only experienced developers should work with this software.
