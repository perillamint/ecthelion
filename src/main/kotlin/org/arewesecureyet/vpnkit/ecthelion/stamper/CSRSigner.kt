package org.arewesecureyet.vpnkit.ecthelion

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
import org.bouncycastle.operator.bc.BcECContentSignerBuilder
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*

class CSRSigner {
    private val sigAlgoName: String;
    private val hashAlgoName: String;
    private val sigAlgoId: AlgorithmIdentifier;
    private val digAlgoId: AlgorithmIdentifier;
    private val caPrivKeyParam: AsymmetricKeyParameter;
    private val caCertificate: X509Certificate?;
    constructor (hashAlgo: String, caKey: KeyPair, caCert: X509Certificate?) {
        if (hashAlgo == "SHA1" || hashAlgo == "NONE" || caKey.private.algorithm == "DSA") {
            // We are living in 21C, not 20C
            throw IllegalArgumentException("ERROR: cannot sign with vulnerable algorithm.")
        }

        sigAlgoName = caKey.private.algorithm;
        hashAlgoName = hashAlgo;
        sigAlgoId = DefaultSignatureAlgorithmIdentifierFinder()
                .find(hashAlgo + "with" + sigAlgoName);

        digAlgoId = DefaultDigestAlgorithmIdentifierFinder()
                .find(sigAlgoId);

        caPrivKeyParam = PrivateKeyFactory.createKey(caKey.private.encoded)
        caCertificate = caCert;
    }

    fun signCSR(csr: PKCS10CertificationRequest, certId: BigInteger,
                notBefore: Date, notAfter: Date): Certificate {
        val caName = if (caCertificate != null) {
            X500Name(caCertificate.subjectX500Principal.name)
        } else {
            // Selfsig mode
            csr.subject
        }

        val certBuilder = X509v3CertificateBuilder(
                caName, certId,
                notBefore, notAfter,
                csr.subject,
                csr.subjectPublicKeyInfo
        )

        val sigGen: ContentSigner = (if (sigAlgoName == "RSA") {// todo: Check RSA or not
            BcRSAContentSignerBuilder(sigAlgoId, digAlgoId)
        } else if (sigAlgoName == "ECDSA") {
            BcECContentSignerBuilder(sigAlgoId, digAlgoId)
        } else {
            throw IllegalArgumentException("Error! Unsupported sigAlgoId")
        }).build(caPrivKeyParam)

        val certHolder = certBuilder.build(sigGen);
        val certStructure = certHolder.toASN1Structure();

        val certFactory = CertificateFactory.getInstance("X509", "BC");

        return certFactory.generateCertificate(ByteArrayInputStream(certStructure.encoded))
    }
}
