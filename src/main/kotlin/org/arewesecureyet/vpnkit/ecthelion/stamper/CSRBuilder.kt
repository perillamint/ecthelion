package org.arewesecureyet.vpnkit.ecthelion.stamper

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import java.security.KeyPair

class CSRBuilder {
    private val sigAlgo: String;
    private val x500NameBuilder: X500NameBuilder
    private val kp: KeyPair
    constructor(hashAlgo: String, keypair: KeyPair) {
        if(hashAlgo == "SHA1" || hashAlgo == "NONE" || keypair.private.algorithm == "DSA") {
            throw IllegalArgumentException("ERROR: cannot sign with vulnerable algorithm.")
        }

        kp = keypair
        sigAlgo = hashAlgo + "with" + keypair.private.algorithm
        x500NameBuilder = X500NameBuilder(BCStyle.INSTANCE);

    }

    fun addRDN(oid: ASN1ObjectIdentifier, value: String) {
        x500NameBuilder.addRDN(oid, value)
    }

    fun build(): PKCS10CertificationRequest {
        val p10builder = JcaPKCS10CertificationRequestBuilder(
                x500NameBuilder.build(), kp.public
        )

        val csBuilder = JcaContentSignerBuilder(sigAlgo)
        val signer = csBuilder.build(kp.private)

        return p10builder.build(signer)
    }
}