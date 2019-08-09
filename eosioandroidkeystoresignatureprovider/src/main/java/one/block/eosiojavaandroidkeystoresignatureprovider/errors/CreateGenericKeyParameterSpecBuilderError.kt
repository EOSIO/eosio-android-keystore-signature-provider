package one.block.eosiojavaandroidkeystoresignatureprovider.errors

import one.block.eosiojava.error.signatureProvider.SignatureProviderError
import org.jetbrains.annotations.NotNull
import java.lang.Exception

/**
 *  Error class that will be thrown from [one.block.eosiojavaandroidkeystoresignatureprovider.EosioAndroidKeyStoreUtility.createGenericKeyParametersSpecBuilder]
 */
class CreateGenericKeyParameterSpecBuilderError : SignatureProviderError {
    constructor() : super()
    constructor(message: @NotNull String) : super(message)
    constructor(message: @NotNull String, exception: @NotNull Exception) : super(message, exception)
    constructor(exception: @NotNull Exception) : super(exception)
}