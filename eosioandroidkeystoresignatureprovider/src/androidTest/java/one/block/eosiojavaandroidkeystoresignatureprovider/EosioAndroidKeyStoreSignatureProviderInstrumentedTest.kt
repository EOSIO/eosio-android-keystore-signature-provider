package one.block.eosiojavaandroidkeystoresignatureprovider

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.runner.AndroidJUnit4
import one.block.eosiojava.error.signatureProvider.SignTransactionError
import one.block.eosiojava.models.signatureProvider.EosioTransactionSignatureRequest
import one.block.eosiojava.models.signatureProvider.EosioTransactionSignatureResponse
import one.block.eosiojavaandroidkeystoresignatureprovider.errors.ErrorString
import one.block.eosiojavaandroidkeystoresignatureprovider.errors.ErrorString.Companion.QUERY_ANDROID_KEYSTORE_GENERIC_ERROR
import one.block.eosiojavaandroidkeystoresignatureprovider.errors.QueryAndroidKeyStoreError
import org.junit.Assert
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException
import org.junit.runner.RunWith
import java.security.spec.ECGenParameterSpec

/**
 * Test class for [EosioAndroidKeyStoreSignatureProvider]
 */
@RunWith(AndroidJUnit4::class)
class EosioAndroidKeyStoreSignatureProviderInstrumentedTest {

    companion object {
        const val TEST_CONST_TEST_KEY_NAME = "test_key"
        const val TEST_CONST_GET_AVAILABLE_KEY_MULTIPLE_KEY_AMOUNT: Int = 5
        const val TEST_CONST_GET_AVAILABLE_KEY_MULTIPLE_KEY_AMOUNT_MAX_TO_STRESS: Int = 1000
        const val TEST_CONST_SECP256R1_EOSIO_PREFIX = "PUB_R1_"
        const val TEST_CONST_SECP256R1_CURVE_NAME = "secp256r1"
        const val TEST_CONST_SERIALIZED_TRANSACTION: String =
            "8BC2A35CF56E6CC25F7F000000000100A6823403EA3055000000572D3CCDCD01000000000000C03400000000A8ED32322A000000000000C034000000000000A682A08601000000000004454F530000000009536F6D657468696E6700"
        const val TEST_CONST_CHAIN_ID: String = "687fa513e18843ad3e820744f4ffcf93b1354036d80737db8dc444fe4b15ad17"
    }

    @Rule
    @JvmField
    val exceptionRule: ExpectedException = ExpectedException.none()

    /**
     * Test [EosioAndroidKeyStoreSignatureProvider.getAvailableKeys] method
     * Add a test key
     * <p/>
     * Expect to get 1 available key in the AndroidKeyStore with EOSIO format
     * <p/>
     * Remove the test key
     */
    @Test
    fun getAvailableKeyTest() {
        this.generateKeyInAndroidStore(alias = TEST_CONST_TEST_KEY_NAME)

        val keyStoreProvider: EosioAndroidKeyStoreSignatureProvider =
            EosioAndroidKeyStoreSignatureProvider.Builder().build()

        val allKeyInKeyStore: List<String> = keyStoreProvider.availableKeys

        Assert.assertEquals(1, allKeyInKeyStore.size)
        Assert.assertNotNull(allKeyInKeyStore[0])
        Assert.assertNotEquals("", allKeyInKeyStore[0])
        Assert.assertTrue(allKeyInKeyStore[0].contains(other = TEST_CONST_SECP256R1_EOSIO_PREFIX, ignoreCase = true))

        this.deleteKeyInAndroidKeyStore(alias = TEST_CONST_TEST_KEY_NAME)
    }

    /**
     * Test [EosioAndroidKeyStoreSignatureProvider.getAvailableKeys] method
     * <p/>
     * Clear all the key before calling the method
     * <p/>
     * Expect to get empty list from AndroidKeyStore
     */
    @Test
    fun getAvailableKeyWithNoKey_expectEmpty() {
        EosioAndroidKeyStoreUtility.deleteAllKey(null)

        val keyStoreProvider: EosioAndroidKeyStoreSignatureProvider =
            EosioAndroidKeyStoreSignatureProvider.Builder().build()

        val allKeyInKeyStore: List<String> = keyStoreProvider.availableKeys
        Assert.assertEquals(0, allKeyInKeyStore.size)
    }

    /**
     * Test [EosioAndroidKeyStoreSignatureProvider.getAvailableKeys] method
     * <p/>
     * Clear all key
     * <p/>
     * Generate [TEST_CONST_GET_AVAILABLE_KEY_MULTIPLE_KEY_AMOUNT] keys
     * <p/>
     * Expect to get [TEST_CONST_GET_AVAILABLE_KEY_MULTIPLE_KEY_AMOUNT] keys with EOSIO format
     * <p/> Clear all key
     */
    @Test
    fun getAvailableKeyWithMultipleKeyAdded_expectMultipleKey() {
        // Clear all key to make sure we get the exact amount
        EosioAndroidKeyStoreUtility.deleteAllKey(null)

        // Generate keys
        for (i in 0 until TEST_CONST_GET_AVAILABLE_KEY_MULTIPLE_KEY_AMOUNT) {
            this.generateKeyInAndroidStore(alias = "${TEST_CONST_TEST_KEY_NAME}_$i")
        }

        // Test
        val keyStoreProvider: EosioAndroidKeyStoreSignatureProvider =
            EosioAndroidKeyStoreSignatureProvider.Builder().build()

        val allKeyInKeyStore: List<String> = keyStoreProvider.availableKeys

        Assert.assertEquals(TEST_CONST_GET_AVAILABLE_KEY_MULTIPLE_KEY_AMOUNT, allKeyInKeyStore.size)

        allKeyInKeyStore.forEach {
            Assert.assertTrue(it.contains(other = TEST_CONST_SECP256R1_EOSIO_PREFIX, ignoreCase = true))
        }

        // Clear keys
        EosioAndroidKeyStoreUtility.deleteAllKey(loadStoreParameter = null)
    }

    /**
     * Test [EosioAndroidKeyStoreSignatureProvider.getAvailableKeys] method
     * <p/>
     * Clear all key
     * <p/>
     * Generate [TEST_CONST_GET_AVAILABLE_KEY_MULTIPLE_KEY_AMOUNT_MAX_TO_STRESS] keys
     * <p/>
     * Expect to get [TEST_CONST_GET_AVAILABLE_KEY_MULTIPLE_KEY_AMOUNT_MAX_TO_STRESS] keys with EOSIO format
     * <p/> Clear all key
     */
    @Test
    fun getAvailableKeyWithStressOutMaxMultipleKeyAdded_expectMultipleKeyStressOutMax() {
        // Clear all key to make sure we get the exact amount
        EosioAndroidKeyStoreUtility.deleteAllKey(null)

        // Generate keys
        for (i in 0 until TEST_CONST_GET_AVAILABLE_KEY_MULTIPLE_KEY_AMOUNT_MAX_TO_STRESS) {
            this.generateKeyInAndroidStore(alias = "${TEST_CONST_TEST_KEY_NAME}_$i")
        }

        // Test
        val keyStoreProvider: EosioAndroidKeyStoreSignatureProvider =
            EosioAndroidKeyStoreSignatureProvider.Builder().build()

        val allKeyInKeyStore: List<String> = keyStoreProvider.availableKeys

        Assert.assertEquals(TEST_CONST_GET_AVAILABLE_KEY_MULTIPLE_KEY_AMOUNT_MAX_TO_STRESS, allKeyInKeyStore.size)

        allKeyInKeyStore.forEach {
            Assert.assertTrue(it.contains(other = TEST_CONST_SECP256R1_EOSIO_PREFIX, ignoreCase = true))
        }

        // Clear keys
        EosioAndroidKeyStoreUtility.deleteAllKey(null)
    }

    /**
     * Test [EosioAndroidKeyStoreSignatureProvider.signTransaction] method
     * <p/>
     * Generate new key
     * <p/>
     * Making a mocked transaction request
     * <p/>
     * Sign transaction
     * <p/>
     * Verify transaction with public key
     * <p/>
     * Clean key
     */
    @Test
    fun signTransaction() {
        val signingPublicKeys: MutableList<String> = ArrayList()

        // Get just added key to the signing key to request the KeyStore to sign
        this.generateKeyInAndroidStore(TEST_CONST_TEST_KEY_NAME)
        signingPublicKeys.add(
            EosioAndroidKeyStoreUtility.getAndroidKeyStoreKeyInEOSIOFormat(
                alias = TEST_CONST_TEST_KEY_NAME,
                password = null,
                loadStoreParameter = null
            )
        )

        val transactionSignatureRequest: EosioTransactionSignatureRequest =
            EosioTransactionSignatureRequest(
                TEST_CONST_SERIALIZED_TRANSACTION,
                signingPublicKeys,
                TEST_CONST_CHAIN_ID,
                ArrayList(),
                false
            )

        val eosioAndroidKeyStoreSignatureProvider: EosioAndroidKeyStoreSignatureProvider =
            EosioAndroidKeyStoreSignatureProvider.Builder().build()
        val transactionSignatureResponse: EosioTransactionSignatureResponse =
            eosioAndroidKeyStoreSignatureProvider.signTransaction(transactionSignatureRequest)

        Assert.assertNull(transactionSignatureResponse.error)
        Assert.assertEquals(TEST_CONST_SERIALIZED_TRANSACTION, transactionSignatureResponse.serializeTransaction)
        Assert.assertEquals(1, transactionSignatureResponse.signatures.size)
        Assert.assertNotEquals("", transactionSignatureResponse.signatures[0])
        Assert.assertTrue(transactionSignatureResponse.signatures[0].contains("SIG_R1_", true))

        EosioAndroidKeyStoreUtility.deleteAllKey(loadStoreParameter = null)

    }

    /**
     * Test [EosioAndroidKeyStoreSignatureProvider.signTransaction] method to sign with [TEST_CONST_GET_AVAILABLE_KEY_MULTIPLE_KEY_AMOUNT] keys
     * <p/>
     * Generate new [TEST_CONST_GET_AVAILABLE_KEY_MULTIPLE_KEY_AMOUNT] keys
     * <p/>
     * Making a mocked transaction request
     * <p/>
     * Sign transaction
     * <p/>
     * Verify transaction with public keys
     * <p/>
     * Clean keys
     */
    @Test
    fun signTransactionWithMultipleKey_expectMultipleSignature() {
        EosioAndroidKeyStoreUtility.deleteAllKey(loadStoreParameter = null)

        val signingPublicKeys: MutableList<String> = ArrayList()

        // Get just added key to the signing key to request the KeyStore to sign
        // Generate keys
        for (i in 0 until TEST_CONST_GET_AVAILABLE_KEY_MULTIPLE_KEY_AMOUNT) {
            this.generateKeyInAndroidStore(alias = "${TEST_CONST_TEST_KEY_NAME}_$i")
            signingPublicKeys.add(
                EosioAndroidKeyStoreUtility.getAndroidKeyStoreKeyInEOSIOFormat(
                    alias = "${TEST_CONST_TEST_KEY_NAME}_$i",
                    password = null,
                    loadStoreParameter = null
                )
            )
        }

        val transactionSignatureRequest: EosioTransactionSignatureRequest =
            EosioTransactionSignatureRequest(
                TEST_CONST_SERIALIZED_TRANSACTION,
                signingPublicKeys,
                TEST_CONST_CHAIN_ID,
                ArrayList(),
                false
            )

        val eosioAndroidKeyStoreSignatureProvider: EosioAndroidKeyStoreSignatureProvider =
            EosioAndroidKeyStoreSignatureProvider.Builder().build()
        val transactionSignatureResponse: EosioTransactionSignatureResponse =
            eosioAndroidKeyStoreSignatureProvider.signTransaction(transactionSignatureRequest)

        Assert.assertNull(transactionSignatureResponse.error)
        Assert.assertEquals(TEST_CONST_SERIALIZED_TRANSACTION, transactionSignatureResponse.serializeTransaction)
        Assert.assertEquals(
            TEST_CONST_GET_AVAILABLE_KEY_MULTIPLE_KEY_AMOUNT,
            transactionSignatureResponse.signatures.size
        )

        transactionSignatureResponse.signatures.forEach {
            Assert.assertTrue(it.contains("SIG_R1_", true))
        }


        EosioAndroidKeyStoreUtility.deleteAllKey(loadStoreParameter = null)
    }

    /**
     * Signing with empty serialized transaction
     * <p/>
     * Expect to fail and throw SignTransactionError
     *
     * @throws SignTransactionError
     */
    @Throws(SignTransactionError::class)
    @Test
    fun signTransactionWithEmptySerializedTransaction_expectedSignTransactionError() {
        exceptionRule.expect(SignTransactionError::class.java)
        exceptionRule.expectMessage(String.format(ErrorString.SIGN_TRANSACTION_PREPARE_FOR_SIGNING_GENERIC_ERROR, ""))

        EosioAndroidKeyStoreUtility.deleteAllKey(loadStoreParameter = null)
        val signingPublicKeys: MutableList<String> = ArrayList()

        // Get just added key to the signing key to request the KeyStore to sign
        this.generateKeyInAndroidStore(TEST_CONST_TEST_KEY_NAME)
        signingPublicKeys.add(
            EosioAndroidKeyStoreUtility.getAndroidKeyStoreKeyInEOSIOFormat(
                alias = TEST_CONST_TEST_KEY_NAME,
                password = null,
                loadStoreParameter = null
            )
        )

        val transactionSignatureRequest: EosioTransactionSignatureRequest =
            EosioTransactionSignatureRequest(
                "",
                signingPublicKeys,
                TEST_CONST_CHAIN_ID,
                ArrayList(),
                false
            )

        val eosioAndroidKeyStoreSignatureProvider: EosioAndroidKeyStoreSignatureProvider =
            EosioAndroidKeyStoreSignatureProvider.Builder().build()

        eosioAndroidKeyStoreSignatureProvider.signTransaction(transactionSignatureRequest)
    }

    @Test
    fun signTransactionWithNoKey_expectFail() {
        exceptionRule.expect(QueryAndroidKeyStoreError::class.java)
        exceptionRule.expectMessage(QUERY_ANDROID_KEYSTORE_GENERIC_ERROR)

        EosioAndroidKeyStoreUtility.deleteAllKey(loadStoreParameter = null)
        val signingPublicKeys: MutableList<String> = ArrayList()

        // Get just added key to the signing key to request the KeyStore to sign
        signingPublicKeys.add(
            EosioAndroidKeyStoreUtility.getAndroidKeyStoreKeyInEOSIOFormat(
                alias = TEST_CONST_TEST_KEY_NAME,
                password = null,
                loadStoreParameter = null
            )
        )

        val transactionSignatureRequest: EosioTransactionSignatureRequest =
            EosioTransactionSignatureRequest(
                TEST_CONST_SERIALIZED_TRANSACTION,
                signingPublicKeys,
                TEST_CONST_CHAIN_ID,
                ArrayList(),
                false
            )

        val eosioAndroidKeyStoreSignatureProvider: EosioAndroidKeyStoreSignatureProvider =
            EosioAndroidKeyStoreSignatureProvider.Builder().build()

        eosioAndroidKeyStoreSignatureProvider.signTransaction(transactionSignatureRequest)
    }

    /**
     * Generate a new key in AndroidKeyStore for testing
     *
     * @param alias String
     */
    private fun generateKeyInAndroidStore(alias: String) {
        EosioAndroidKeyStoreUtility.generateAndroidKeyStoreKey(
            keyGenParameterSpec =
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAlgorithmParameterSpec(ECGenParameterSpec(TEST_CONST_SECP256R1_CURVE_NAME))
                .build()
        )
    }

    /**
     * Delete a key in AndroidKeyStore for testing
     */
    private fun deleteKeyInAndroidKeyStore(alias: String) {
        EosioAndroidKeyStoreUtility.deleteKeyByAlias(keyAliasToDelete = alias, loadStoreParameter = null)
    }
}