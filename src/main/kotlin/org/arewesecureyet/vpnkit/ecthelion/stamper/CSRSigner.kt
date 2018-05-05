package org.arewesecureyet.vpnkit.ecthelion

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import java.security.KeyPair

class CSRSigner {
    private lazyinit var certAlgo;
    constructor (hashAlgo: String, caKey: KeyPair) {
        val sigAlgo = caKey.private.algorithm;

        if (hashAlgo == "SHA1" || hashAlgo == "NONE" || sigAlgo == "DSA") {
            // We are living in 21C, not 20C
            throw IllegalArgumentException("ERROR: cannot sign with vulnerable algorithm.")
        }

        certAlgo = DefaultSignatureAlgorithmIdentifierFinder()
                .find(hashAlgo + "with" + sigAlgo);
    }

    fun signCSR(csr: PKCS10CertificationRequest) {
        val csrPubk = csr.subjectPublicKeyInfo;
        val csrPubkParam = PublicKeyFactory.createKey(csrPubk);

        // TODO: Extract pubkey, build cert.
    }
}
