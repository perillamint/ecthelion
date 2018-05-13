package org.arewesecureyet.vpnkit.ecthelion.stamper

import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.security.KeyPair

class CSRBuilder {
    private var state: String
    private val x500NameBuilder: X500NameBuilder
    constructor(hashAlgo: String, keypair: KeyPair) {
        if(hashAlgo == "SHA1" || hashAlgo == "NONE" || keypair.private.algorithm == "DSA") {
            throw IllegalArgumentException("ERROR: cannot sign with vulnerable algorithm.")
        }

        val sigAlgoName = keypair.private.algorithm
        x500NameBuilder = X500NameBuilder(BCStyle.INSTANCE);

        JcaContentSignerBuilder
    }

    setRDN(nameX500NameStyle)

}