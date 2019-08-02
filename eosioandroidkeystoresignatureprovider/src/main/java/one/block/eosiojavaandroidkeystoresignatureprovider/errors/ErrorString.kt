package one.block.eosiojavaandroidkeystoresignatureprovider.errors

/**
 * Error content definition for EOSIO Signature Provider for AndroidKeyStore and EOSIO AndroidKeyStore Utility
 */
class ErrorString {
    companion object {
        const val CONVERT_EC_TO_EOS_INVALID_INPUT_KEY = "Input key is invalid! It must be an EC Public key in a SECP256R1 curve!"
        const val SIGN_TRANSACTION_PREPARE_FOR_SIGNING_GENERIC_ERROR = "Something went wrong on preparing transaction for signing! serialized transaction content = [%s]"
        const val SIGN_TRANSACTION_UNABLE_TO_FIND_KEY_TO_SIGN = "The requested key for signing is not available in the Android KeyStore."
        const val SIGN_TRANSACTION_RAW_SIGNATURE_IS_NULL = "Signature from Android KeyStore is NULL!"
        const val SIGN_TRANS_EMPTY_CHAIN_ID = "Chain id cannot be empty!"
        const val QUERY_ANDROID_KEYSTORE_GENERIC_ERROR = "Something went wrong while querying key(s) in Android KeyStore!"
        const val DELETE_KEY_KEYSTORE_GENERIC_ERROR = "Something went wrong while deleting key(s) in AndroidKeyStore!"
        const val GENERATE_KEY_KEYGENSPEC_MUST_USE_EC = "KeyGenParameterSpec must use ECGenParameterSpec for its algorithm!"
        const val GENERATE_KEY_ECGEN_MUST_USE_SECP256R1 = "ECGenParameterSpec must use a SECP256R1 curve!"
        const val GENERATE_KEY_MUST_HAS_PURPOSE_SIGN = "KeyGenParameterSpec must include KeyProperties.PURPOSE_SIGN!"
    }
}