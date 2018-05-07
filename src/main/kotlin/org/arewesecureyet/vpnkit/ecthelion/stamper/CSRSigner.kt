package org.arewesecureyet.vpnkit.ecthelion

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import java.security.KeyPair

class CSRSigner {
    private lazyinit var sigAlgoId;
    private lazyinit var digAlgoId;
    private lazyinit var caPrivKeyParam;
    constructor (hashAlgo: String, caKey: KeyPair) {
        val sigAlgo = caKey.private.algorithm;

        if (hashAlgo == "SHA1" || hashAlgo == "NONE" || sigAlgo == "DSA") {
            // We are living in 21C, not 20C
            throw IllegalArgumentException("ERROR: cannot sign with vulnerable algorithm.")
        }

        sigAlgoId = DefaultSignatureAlgorithmIdentifierFinder()
                .find(hashAlgo + "with" + sigAlgo);

        digAlgoId = DefaultDigestAlgorithmIdentifierFinder()
                .find(sigAlgoId);

        caPrivKeyParam = PrivateKeyFactory.createKey(caKey.private.encoded);
    }

    fun signCSR(csr: PKCS10CertificationRequest) {
        val csrPubk = csr.subjectPublicKeyInfo;
        val certBuilder = X509v3CertificateBuilder(
                //
        )

        // TODO: build cert.
    }
}
