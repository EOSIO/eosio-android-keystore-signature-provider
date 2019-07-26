package one.block.eosiojavaandroidkeystoresignatureprovider.errors

class ErrorString {
    companion object {
        const val CONVERT_EC_TO_EOS_INVALID_INPUT_KEY = "Input key is invalid! It must be an EC Public key in SECP256R1 curve"
        const val CONVERT_EC_TO_EOS_INVALID_DER_SIZE = "Invalid or Unknown, the size the public key has to be 3 (\"%s\") + 1 (\"04\") + 32 (X array) + 32 (Y array)"
        const val CONVERT_EC_TO_EOS_INVALID_FIRST_3_BYTES = "Invalid key or unknown, First 3 bytes are not %s"
        const val SIGN_TRANSACTION_PREPARE_FOR_SIGNING_GENERIC_ERROR = "Something went wrong on preparing transaction for signing, serialized transaction content [%s]"
        const val SIGN_TRANSACTION_UNABLE_TO_FIND_KEY_TO_SIGN = "The requested key for signing is not available in the AndroidKeyStore."
        const val SIGN_TRANSACTION_RAW_SIGNATURE_IS_NULL = "Signature from AndroidKeyStore is NULL"
        const val SIGN_TRANS_EMPTY_CHAIN_ID = "Chain id can't be empty!"
        const val QUERY_ANDROID_KEYSTORE_GENERIC_ERROR = "Something went wrong on querying key in AndroidKeyStore"
        const val DELETE_KEY_KEYSTORE_GENERIC_ERROR = "Soemthing went wrong on deleting key(s) in AndroidKeyStore"
    }
}