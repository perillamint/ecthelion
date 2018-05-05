package org.arewesecureyet.vpnkit.ectheloion.stamper

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.cert.X509v3CertificateBuilder
import java.math.BigInteger

class CertificateBuilder {
    private lateinit var cb: X509v3CertificateBuilder;
    constructor() {
        val caname = X500NameBuilder();

        caname.addRDN(BCStyle.)

        val x500str = "CN=Future Software Laboratory";
        cb = X509v3CertificateBuilder(
                X500Name(x500str),
                BigInteger.ONE, // We are Issueing our first CA. TODO: Move this out of CertFactory
        )
    }

    //?
}
