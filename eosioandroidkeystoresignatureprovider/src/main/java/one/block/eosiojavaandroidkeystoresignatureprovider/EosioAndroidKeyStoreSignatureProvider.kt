package one.block.eosiojavaandroidkeystoresignatureprovider

import one.block.eosiojava.error.signatureProvider.SignTransactionError
import one.block.eosiojava.error.utilities.EOSFormatterError
import one.block.eosiojava.interfaces.ISignatureProvider
import one.block.eosiojava.models.signatureProvider.EosioTransactionSignatureRequest
import one.block.eosiojava.models.signatureProvider.EosioTransactionSignatureResponse
import one.block.eosiojava.utilities.EOSFormatter
import one.block.eosiojavaandroidkeystoresignatureprovider.errors.ErrorString
import one.block.eosiojavaandroidkeystoresignatureprovider.errors.ErrorString.Companion.SIGN_TRANSACTION_PREPARE_FOR_SIGNING_GENERIC_ERROR
import one.block.eosiojavaandroidkeystoresignatureprovider.errors.ErrorString.Companion.SIGN_TRANSACTION_RAW_SIGNATURE_IS_NULL
import one.block.eosiojavaandroidkeystoresignatureprovider.errors.ErrorString.Companion.SIGN_TRANSACTION_UNABLE_TO_FIND_KEY_TO_SIGN
import org.bouncycastle.util.encoders.Hex
import java.security.KeyStore

/**
 * EOSIO signature provider for AndroidKeyStore
 * <p/>
 * This provider works only with SECP256R1 curve
 * <p/>
 * Key get generated/imported in AndroidKeyStore wil be protected. Its private key will never been exposed to any processes outside of the KeyStore
 *
 * @property password ProtectionParameter?
 * @property loadStoreParameter LoadStoreParameter?
 */
class EosioAndroidKeyStoreSignatureProvider private constructor() : ISignatureProvider {
    private var password: KeyStore.ProtectionParameter? = null
    private var loadStoreParameter: KeyStore.LoadStoreParameter? = null

    override fun signTransaction(eosioTransactionSignatureRequest: EosioTransactionSignatureRequest): EosioTransactionSignatureResponse {
        if (eosioTransactionSignatureRequest.chainId.isNullOrEmpty()) {
            throw SignTransactionError(ErrorString.SIGN_TRANS_EMPTY_CHAIN_ID)
        }

        // Preparing message's items for sigining
        // Getting serializedTransaction and preparing signable transaction
        val serializedTransaction: String = eosioTransactionSignatureRequest.serializedTransaction

        // This is the un-hashed message which is used to recover public key
        val message: ByteArray

        try {
            message = Hex.decode(
                EOSFormatter.prepareSerializedTransactionForSigning(
                    serializedTransaction,
                    eosioTransactionSignatureRequest.chainId
                ).toUpperCase()
            )
        } catch (eosFormatterError: EOSFormatterError) {
            throw SignTransactionError(
                String.format(
                    SIGN_TRANSACTION_PREPARE_FOR_SIGNING_GENERIC_ERROR,
                    serializedTransaction
                ), eosFormatterError
            )
        }

        val aliasKeyPairs: List<Pair<String, String>> =
            EosioAndroidKeyStoreUtility.getAllAndroidKeyStoreKeyInEOSIOFormat(
                password = this.password,
                loadStoreParameter = this.loadStoreParameter
            )
        val signingPublicKeys: List<String> = eosioTransactionSignatureRequest.signingPublicKeys
        val signatures: MutableList<String> = emptyList<String>().toMutableList()

        for (signingPublicKey in signingPublicKeys) {
            var keyAlias: String = ""

            for (aliasKeyPair in aliasKeyPairs) {
                if (signingPublicKey == aliasKeyPair.second) {
                    keyAlias = aliasKeyPair.first
                    break
                }
            }

            if (keyAlias.isEmpty()) {
                throw SignTransactionError(SIGN_TRANSACTION_UNABLE_TO_FIND_KEY_TO_SIGN)
            }

            val rawSignature =
                EosioAndroidKeyStoreUtility.sign(
                    data = message,
                    alias = keyAlias,
                    password = this.password,
                    loadStoreParameter = this.loadStoreParameter
                )
                    ?: throw SignTransactionError(SIGN_TRANSACTION_RAW_SIGNATURE_IS_NULL)
            signatures.add(
                EOSFormatter.convertDERSignatureToEOSFormat(
                    rawSignature,
                    message,
                    EOSFormatter.convertEOSPublicKeyToPEMFormat(signingPublicKey)
                )
            )
        }

        return EosioTransactionSignatureResponse(serializedTransaction, signatures, null)
    }

    override fun getAvailableKeys(): MutableList<String> {
        return EosioAndroidKeyStoreUtility.getAllAndroidKeyStoreKeyInEOSIOFormat(
            password = this.password,
            loadStoreParameter = this.loadStoreParameter
        )
            .map { it.second }.toMutableList()
    }

    /**
     * Builder class of AndroidKeyStore signature provider
     *
     * @property androidKeyStoreSignatureProvider AndroidKeyStoreSignatureProvider
     */
    class Builder {

        private val androidKeyStoreSignatureProvider: EosioAndroidKeyStoreSignatureProvider =
            EosioAndroidKeyStoreSignatureProvider()

        /**
         * Set password protection for adding, using and removing key
         *
         * @param password KeyStore.ProtectionParameter
         * @return Builder
         */
        fun setPassword(password: KeyStore.ProtectionParameter): Builder {
            this.androidKeyStoreSignatureProvider.password = password
            return this
        }

        /**
         * Set Load KeyStore Parameter to load the KeyStore instance
         *
         * @param loadStoreParameter KeyStore.LoadStoreParameter
         * @return Builder
         */
        fun setLoadStoreParameter(loadStoreParameter: KeyStore.LoadStoreParameter): Builder {
            this.androidKeyStoreSignatureProvider.loadStoreParameter = loadStoreParameter
            return this
        }

        /**
         * Build and return the provider instance
         *
         * @return AndroidKeyStoreSignatureProvider
         */
        fun build(): EosioAndroidKeyStoreSignatureProvider {
            return this.androidKeyStoreSignatureProvider
        }
    }
}