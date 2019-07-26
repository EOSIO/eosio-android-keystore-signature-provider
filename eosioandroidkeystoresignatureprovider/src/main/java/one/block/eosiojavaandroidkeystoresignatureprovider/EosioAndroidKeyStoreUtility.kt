package one.block.eosiojavaandroidkeystoresignatureprovider

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import one.block.eosiojava.enums.AlgorithmEmployed
import one.block.eosiojava.utilities.EOSFormatter
import one.block.eosiojavaandroidkeystoresignatureprovider.errors.AndroidKeyStoreDeleteError
import one.block.eosiojavaandroidkeystoresignatureprovider.errors.AndroidKeyStoreSigningError
import one.block.eosiojavaandroidkeystoresignatureprovider.errors.ErrorString.Companion.CONVERT_EC_TO_EOS_INVALID_DER_SIZE
import one.block.eosiojavaandroidkeystoresignatureprovider.errors.ErrorString.Companion.CONVERT_EC_TO_EOS_INVALID_FIRST_3_BYTES
import one.block.eosiojavaandroidkeystoresignatureprovider.errors.ErrorString.Companion.CONVERT_EC_TO_EOS_INVALID_INPUT_KEY
import one.block.eosiojavaandroidkeystoresignatureprovider.errors.ErrorString.Companion.DELETE_KEY_KEYSTORE_GENERIC_ERROR
import one.block.eosiojavaandroidkeystoresignatureprovider.errors.ErrorString.Companion.QUERY_ANDROID_KEYSTORE_GENERIC_ERROR
import one.block.eosiojavaandroidkeystoresignatureprovider.errors.PublicKeyConversionError
import one.block.eosiojavaandroidkeystoresignatureprovider.errors.QueryAndroidKeyStoreError
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.util.encoders.Hex
import java.io.ByteArrayInputStream
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.*

/**
 * Utility class provides cryptographic methods to generate, sign digital signature and query all key in AndroidKeyStore provider for EOSIO
 */
class EosioAndroidKeyStoreUtility {

    companion object {
        private const val ANDROID_PUBLIC_KEY_OID_ID: Int = 0
        private const val ANDROID_PUBLIC_KEY_DER: Int = 1
        private const val EC_PUBLICKEY_OID_INDEX: Int = 0
        private const val SECP256R1_OID_INDEX: Int = 1
        private const val ANDROID_PUBLIC_KEY_DER_SIZE: Int = 68
        private const val ANDROID_KEYSTORE: String = "AndroidKeyStore"
        private const val ANDROID_ECDSA_SIGNATURE_ALGORITHM: String = "SHA256withECDSA"
        private const val ANDROID_KEYSTORE_PUBLIC_KEY_FIRST_3_BYTES: String = "034200"

        /**
         * Generate a new key inside AndroidKeyStore
         *
         * @param keyGenParameterSpec KeyGenParameterSpec - Parameter specification to generate new key, identity of the key could be set with it
         * @return Public key in EOS format
         */
        @JvmStatic
        fun generateAndroidKeyStoreKey(keyGenParameterSpec: KeyGenParameterSpec): String {
            val kpg: KeyPairGenerator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)

            kpg.initialize(keyGenParameterSpec)

            val newKeyPair: KeyPair = kpg.generateKeyPair()
            return convertAndroidKeyStorePublicKeyToEOSFormat(
                androidECPublicKey = newKeyPair.public as ECPublicKey
            )
        }

        /**
         * Convert ECPublic Key (SECP256R1) that reside in AndroidKeyStore to EOSIO format
         * @param androidECPublicKey ECPublicKey - the ECPublic Key (SECP256R1) to convert
         * @return String - EOSIO format of the input key
         */
        @JvmStatic
        fun convertAndroidKeyStorePublicKeyToEOSFormat(androidECPublicKey: ECPublicKey): String {
            // Read the byte array content of the public without curve types
            val bIn: ASN1InputStream = ASN1InputStream(ByteArrayInputStream(androidECPublicKey.encoded))
            val obj: ASN1Sequence = (bIn.readObject()).toASN1Primitive() as ASN1Sequence

            // Verify if the key is ECPublicKey and SECP256R1
            val publicKeyOID: Array<ASN1Encodable> =
                (obj.getObjectAt(ANDROID_PUBLIC_KEY_OID_ID) as ASN1Sequence).toArray()
            if (X9ObjectIdentifiers.id_ecPublicKey.id != publicKeyOID[EC_PUBLICKEY_OID_INDEX].toString()
                || X9ObjectIdentifiers.prime256v1.id != publicKeyOID[SECP256R1_OID_INDEX].toString()
            ) {
                throw PublicKeyConversionError(CONVERT_EC_TO_EOS_INVALID_INPUT_KEY)
            }

            val publicKeyDERContent: ASN1Encodable = obj.getObjectAt(ANDROID_PUBLIC_KEY_DER)

            // Check if the point is compressed
            var qPoint: ByteArray = publicKeyDERContent.toASN1Primitive().encoded

            if (qPoint.size != ANDROID_PUBLIC_KEY_DER_SIZE) {
                // Invalid or Unknown, the size the public key has to be 3 ("034200") + 1 ("04") + 32 (X array) + 32 (Y array)
                throw PublicKeyConversionError(
                    String.format(
                        CONVERT_EC_TO_EOS_INVALID_DER_SIZE,
                        ANDROID_KEYSTORE_PUBLIC_KEY_FIRST_3_BYTES
                    )
                )
            }

            // Check first 3 bytes
            val first3BytesOfPointEncoding: ByteArray = qPoint.sliceArray(IntRange(0, 2))

            if (Hex.toHexString(first3BytesOfPointEncoding) != ANDROID_KEYSTORE_PUBLIC_KEY_FIRST_3_BYTES) {
                // Invalid or Unknown
                throw PublicKeyConversionError(
                    String.format(
                        CONVERT_EC_TO_EOS_INVALID_FIRST_3_BYTES,
                        ANDROID_KEYSTORE_PUBLIC_KEY_FIRST_3_BYTES
                    )
                )
            }

            // Remove the first 3 bytes
            qPoint = qPoint.slice(IntRange(3, qPoint.size - 1)).toByteArray()

            // The pointEncoding structure is "04" + 32 (X array) + 32 (Y array)
            qPoint = EOSFormatter.compressPublickey(qPoint, AlgorithmEmployed.SECP256R1)

            // Finally, encode the compressed Q point to EOSIO format public key
            return EOSFormatter.encodePublicKey(
                qPoint,
                AlgorithmEmployed.SECP256R1,
                false
            )
        }

        /**
         * Get all key (SECP256R1) in EOS format inside AndroidKeyStore
         * @param password KeyStore.ProtectionParameter? - the password to load all the key
         * @param loadStoreParameter KeyStore.LoadStoreParameter? - the KeyStore Parameter to load the KeyStore instance
         *
         * @return List<String> - List of SECP256R1 keys inside AndroidKeyStore
         */
        @JvmStatic
        fun getAllAndroidKeyStoreKeyInEOSIOFormat(
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
         * Get all key (SECP256R1) in EOS format inside AndroidKeyStore
         * @param alias String - the key's identity
         * @param password KeyStore.ProtectionParameter? - the password to load all the key
         * @param loadStoreParameter KeyStore.LoadStoreParameter? - the KeyStore Parameter to load the KeyStore instance
         * @return String - the SECP256R1 key in AndroidKeyStore
         */
        @Throws(QueryAndroidKeyStoreError::class)
        @JvmStatic
        fun getAndroidKeyStoreKeyInEOSIOFormat(
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
         * Sign a digital signature into a binary data
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
        fun deleteKeyByAlias(keyAliasToDelete: String, loadStoreParameter: KeyStore.LoadStoreParameter?) {
            try {
                val ks: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
                    load(loadStoreParameter)
                }

                ks.deleteEntry(keyAliasToDelete)
            } catch (ex: Exception) {
                throw AndroidKeyStoreDeleteError(DELETE_KEY_KEYSTORE_GENERIC_ERROR, ex)
            }
        }

        /**
         * Delete all key in AndroidKeyStore
         *
         * @param loadStoreParameter KeyStore.LoadStoreParameter? - the KeyStore Parameter to load the KeyStore instance
         */
        @JvmStatic
        fun deleteAllKey(loadStoreParameter: KeyStore.LoadStoreParameter?) {
            try {
                val ks: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
                    load(loadStoreParameter)
                }

                ks.aliases().toList().forEach { ks.deleteEntry(it) }
            } catch (ex: Exception) {
                throw AndroidKeyStoreDeleteError(DELETE_KEY_KEYSTORE_GENERIC_ERROR, ex)
            }
        }
    }
}