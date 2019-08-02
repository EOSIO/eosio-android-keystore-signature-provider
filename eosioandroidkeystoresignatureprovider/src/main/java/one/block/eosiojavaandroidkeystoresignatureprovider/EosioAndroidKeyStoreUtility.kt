package one.block.eosiojavaandroidkeystoresignatureprovider

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import one.block.eosiojava.utilities.EOSFormatter
import one.block.eosiojavaandroidkeystoresignatureprovider.errors.*
import one.block.eosiojavaandroidkeystoresignatureprovider.errors.ErrorString.Companion.CONVERT_EC_TO_EOS_INVALID_INPUT_KEY
import one.block.eosiojavaandroidkeystoresignatureprovider.errors.ErrorString.Companion.DELETE_KEY_KEYSTORE_GENERIC_ERROR
import one.block.eosiojavaandroidkeystoresignatureprovider.errors.ErrorString.Companion.GENERATE_KEY_ECGEN_MUST_USE_SECP256R1
import one.block.eosiojavaandroidkeystoresignatureprovider.errors.ErrorString.Companion.GENERATE_KEY_KEYGENSPEC_MUST_USE_EC
import one.block.eosiojavaandroidkeystoresignatureprovider.errors.ErrorString.Companion.GENERATE_KEY_MUST_HAS_PURPOSE_SIGN
import one.block.eosiojavaandroidkeystoresignatureprovider.errors.ErrorString.Companion.QUERY_ANDROID_KEYSTORE_GENERIC_ERROR
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemWriter
import java.io.ByteArrayInputStream
import java.io.StringWriter
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.*

/**
 * Utility class provides cryptographic methods to manage keys in the AndroidKeyStore provider and use the keys to sign transactions.
 */
class EosioAndroidKeyStoreUtility {

    companion object {
        private const val ANDROID_PUBLIC_KEY_OID_ID: Int = 0
        private const val EC_PUBLICKEY_OID_INDEX: Int = 0
        private const val SECP256R1_OID_INDEX: Int = 1
        private const val ANDROID_KEYSTORE: String = "AndroidKeyStore"
        private const val ANDROID_ECDSA_SIGNATURE_ALGORITHM: String = "SHA256withECDSA"
        private const val SECP256R1_CURVE_NAME = "secp256r1"
        private const val PEM_OBJECT_TYPE_PUBLIC_KEY = "PUBLIC KEY"

        /**
         * Generate a new key inside AndroidKeyStore by the given [keyGenParameterSpec] and return the new key in EOS format
         *
         * The given [keyGenParameterSpec] is the parameter specification to generate new key, identity of the key could be set with it. This spec has to follow:
         *
         * - [KeyGenParameterSpec] must includes [KeyProperties.PURPOSE_SIGN]
         * - [KeyGenParameterSpec.getAlgorithmParameterSpec] must be [ECGenParameterSpec]
         * - [KeyGenParameterSpec.getAlgorithmParameterSpec]'s curve name must be [SECP256R1_CURVE_NAME]
         */
        @JvmStatic
        fun generateAndroidKeyStoreKey(keyGenParameterSpec: KeyGenParameterSpec): String {
            // Parameter Spec must includes PURPOSE_SIGN
            if (KeyProperties.PURPOSE_SIGN and keyGenParameterSpec.purposes != KeyProperties.PURPOSE_SIGN) {
                throw InvalidKeyGenParameter(GENERATE_KEY_MUST_HAS_PURPOSE_SIGN)
            }

            // Parameter Spec's algorithm spec must be ECGenParameterSpec
            if (keyGenParameterSpec.algorithmParameterSpec !is ECGenParameterSpec) {
                throw InvalidKeyGenParameter(GENERATE_KEY_KEYGENSPEC_MUST_USE_EC)
            }

            // The curve of Parameter Spec's algorithm must be SECP256R1
            if ((keyGenParameterSpec.algorithmParameterSpec as ECGenParameterSpec).name != SECP256R1_CURVE_NAME) {
                throw InvalidKeyGenParameter(GENERATE_KEY_ECGEN_MUST_USE_SECP256R1)
            }

            val kpg: KeyPairGenerator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)

            kpg.initialize(keyGenParameterSpec)

            val newKeyPair: KeyPair = kpg.generateKeyPair()
            return convertAndroidKeyStorePublicKeyToEOSFormat(
                androidECPublicKey = newKeyPair.public as ECPublicKey
            )
        }

        /**
         * Generate a new key inside AndroidKeyStore by the given [alias] and return the new key in EOS format
         *
         * The given [alias] is the identity of the key. The new key will be generated with the Default [KeyGenParameterSpec] from the [generateDefaultKeyGenParameterSpecBuilder]
         */
        @JvmStatic
        fun generateAndroidKeyStoreKey(alias: String): String {
            // Create a default KeyGenParameterSpec
            val keyGenParameterSpec: KeyGenParameterSpec = this.generateDefaultKeyGenParameterSpecBuilder(alias).build()

            return this.generateAndroidKeyStoreKey(keyGenParameterSpec)
        }

        /**
         * Convert ECPublic Key (SECP256R1) that reside in AndroidKeyStore to EOS format
         * @param androidECPublicKey ECPublicKey - the ECPublic Key (SECP256R1) to convert
         * @return String - EOS format of the input key
         */
        @JvmStatic
        fun convertAndroidKeyStorePublicKeyToEOSFormat(androidECPublicKey: ECPublicKey): String {
            // Read the byte array content of the public without curve types
            val bIn: ASN1InputStream = ASN1InputStream(ByteArrayInputStream(androidECPublicKey.encoded))
            val asn1Sequence: ASN1Sequence = (bIn.readObject()).toASN1Primitive() as ASN1Sequence

            // Verify if the key is ECPublicKey and SECP256R1
            val publicKeyOID: Array<ASN1Encodable> =
                (asn1Sequence.getObjectAt(ANDROID_PUBLIC_KEY_OID_ID) as ASN1Sequence).toArray()
            if (X9ObjectIdentifiers.id_ecPublicKey.id != publicKeyOID[EC_PUBLICKEY_OID_INDEX].toString()
                || X9ObjectIdentifiers.prime256v1.id != publicKeyOID[SECP256R1_OID_INDEX].toString()
            ) {
                throw PublicKeyConversionError(CONVERT_EC_TO_EOS_INVALID_INPUT_KEY)
            }

            val stringWriter: StringWriter = StringWriter()
            val pemWriter: PemWriter = PemWriter(stringWriter)
            val pemObject: PemObject = PemObject(PEM_OBJECT_TYPE_PUBLIC_KEY, asn1Sequence.encoded)
            pemWriter.writeObject(pemObject)
            pemWriter.flush()

            val pemFormattedPublicKey: String = stringWriter.toString()

            return EOSFormatter.convertPEMFormattedPublicKeyToEOSFormat(pemFormattedPublicKey, false)
        }

        /**
         * Get all key (SECP256R1) in EOS format inside AndroidKeyStore
         * @param password KeyStore.ProtectionParameter? - the password to load all the key
         * @param loadStoreParameter KeyStore.LoadStoreParameter? - the KeyStore Parameter to load the KeyStore instance
         *
         * @return List<String> - List of SECP256R1 keys inside AndroidKeyStore
         */
        @JvmStatic
        fun getAllAndroidKeyStoreKeysInEOSFormat(
            password: KeyStore.ProtectionParameter?,
            loadStoreParameter: KeyStore.LoadStoreParameter?
        ): List<Pair<String, String>> {
            val aliasKeyPair: MutableList<Pair<String, String>> = ArrayList()
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(loadStoreParameter) }
            val aliases = keyStore.aliases()

            for (alias in aliases) {
                val keyEntry = keyStore.getEntry(alias, password) as KeyStore.PrivateKeyEntry
                val ecPublicKey = KeyFactory.getInstance(keyEntry.certificate.publicKey.algorithm).generatePublic(
                    X509EncodedKeySpec(keyEntry.certificate.publicKey.encoded)
                ) as ECPublicKey

                aliasKeyPair.add(
                    Pair(
                        alias,
                        this.convertAndroidKeyStorePublicKeyToEOSFormat(androidECPublicKey = ecPublicKey)
                    )
                )
            }

            return aliasKeyPair
        }

        /**
         * Get all keys (SECP256R1) in EOS format inside AndroidKeyStore
         * @param alias String - the key's identity
         * @param password KeyStore.ProtectionParameter? - the password to load all the key
         * @param loadStoreParameter KeyStore.LoadStoreParameter? - the KeyStore Parameter to load the KeyStore instance
         * @return String - the SECP256R1 key in AndroidKeyStore
         */
        @Throws(QueryAndroidKeyStoreError::class)
        @JvmStatic
        fun getAndroidKeyStoreKeyInEOSFormat(
            alias: String,
            password: KeyStore.ProtectionParameter?,
            loadStoreParameter: KeyStore.LoadStoreParameter?
        ): String {
            try {
                val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(loadStoreParameter) }
                val keyEntry = keyStore.getEntry(alias, password) as KeyStore.PrivateKeyEntry
                val ecPublicKey = KeyFactory.getInstance(keyEntry.certificate.publicKey.algorithm).generatePublic(
                    X509EncodedKeySpec(keyEntry.certificate.publicKey.encoded)
                ) as ECPublicKey

                return this.convertAndroidKeyStorePublicKeyToEOSFormat(ecPublicKey)
            } catch (ex: Exception) {
                throw QueryAndroidKeyStoreError(QUERY_ANDROID_KEYSTORE_GENERIC_ERROR, ex)
            }
        }

        /**
         * Sign data with a key in the keystore.
         *
         * @param data ByteArray - data to be signed
         * @param alias String - identity of the key to be used for signing
         * @param password KeyStore.ProtectionParameter - password of the key
         * @return Binary version of the signature
         * @throws AndroidKeyStoreSigningError
         */
        @Throws(AndroidKeyStoreSigningError::class)
        @JvmStatic
        fun sign(
            data: ByteArray,
            alias: String,
            password: KeyStore.ProtectionParameter?,
            loadStoreParameter: KeyStore.LoadStoreParameter?
        ): ByteArray? {
            try {
                val ks: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
                    load(loadStoreParameter)
                }

                val key = ks.getEntry(alias, password) as KeyStore.PrivateKeyEntry

                return Signature.getInstance(ANDROID_ECDSA_SIGNATURE_ALGORITHM).run {
                    initSign(key.privateKey)
                    update(data)
                    sign()
                }
            } catch (ex: Exception) {
                throw AndroidKeyStoreSigningError(ex)
            }
        }

        /**
         * Delete a key inside AndroidKeyStore by its alias
         *
         * @param keyAliasToDelete String - the alias of the key to delete
         * @param loadStoreParameter KeyStore.LoadStoreParameter? - the KeyStore Parameter to load the KeyStore instance
         * @throws AndroidKeyStoreDeleteError
         */
        @Throws(AndroidKeyStoreDeleteError::class)
        @JvmStatic
        fun deleteKeyByAlias(keyAliasToDelete: String, loadStoreParameter: KeyStore.LoadStoreParameter?): Boolean {
            try {
                val ks: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
                    load(loadStoreParameter)
                }

                ks.deleteEntry(keyAliasToDelete)

                // If the key is still exist, return false. Otherwise, return true
                return !ks.containsAlias(keyAliasToDelete)
            } catch (ex: Exception) {
                throw AndroidKeyStoreDeleteError(DELETE_KEY_KEYSTORE_GENERIC_ERROR, ex)
            }
        }

        /**
         * Delete all keys in AndroidKeyStore
         *
         * @param loadStoreParameter KeyStore.LoadStoreParameter? - the KeyStore Parameter to load the KeyStore instance
         */
        @Throws(AndroidKeyStoreDeleteError::class)
        @JvmStatic
        fun deleteAllKeys(loadStoreParameter: KeyStore.LoadStoreParameter?) {
            try {
                val ks: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
                    load(loadStoreParameter)
                }

                ks.aliases().toList().forEach { ks.deleteEntry(it) }
            } catch (ex: Exception) {
                throw AndroidKeyStoreDeleteError(DELETE_KEY_KEYSTORE_GENERIC_ERROR, ex)
            }
        }

        /**
         * Generate a default [KeyGenParameterSpec.Builder] with
         *
         * [KeyProperties.DIGEST_SHA256] as its digest
         *
         * [ECGenParameterSpec] as its algorithm parameter spec
         *
         * [SECP256R1_CURVE_NAME] as its EC curve
         *
         * @return KeyGenParameterSpec
         */
        @JvmStatic
        private fun generateDefaultKeyGenParameterSpecBuilder(alias: String): KeyGenParameterSpec.Builder {
            return KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAlgorithmParameterSpec(ECGenParameterSpec(SECP256R1_CURVE_NAME))
        }
    }
}