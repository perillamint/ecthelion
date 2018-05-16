package org.arewesecureyet.vpnkit.ecthelion

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
import org.bouncycastle.operator.bc.BcECContentSignerBuilder
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
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
                notBefore: Date, notAfter: Date,
                csrX500NameOverride: X500Name?, extensions: List<Extension>?): Certificate {
        val vp = JcaContentVerifierProviderBuilder().build(csr.subjectPublicKeyInfo)
        if(!csr.isSignatureValid(vp)) {
            throw SecurityException("ERROR: CSR signature verification failure.")
        }

        var csrName = if (csrX500NameOverride != null) {
            csrX500NameOverride
        } else {
            // Note: It is dangerous to use subject from csr
            csr.subject
        }

        val caName = if (caCertificate != null) {
            X500Name(caCertificate.subjectX500Principal.name)
        } else {
            // Selfsig mode
            csrName
        }

        val certBuilder = X509v3CertificateBuilder(
                caName, certId,
                notBefore, notAfter,
                csrName,
                csr.subjectPublicKeyInfo
        )

        if (extensions != null) {
            for(ext in extensions) {
                certBuilder.addExtension(ext)
            }
        }

        val sigGen: ContentSigner = when (sigAlgoName) {
            "RSA" -> BcRSAContentSignerBuilder(sigAlgoId, digAlgoId)
            "ECDSA" -> BcECContentSignerBuilder(sigAlgoId, digAlgoId)
            else -> throw IllegalArgumentException("Error! Unsupported sigAlgoName")
        }.build(caPrivKeyParam)

        val certHolder = certBuilder.build(sigGen);
        val certStructure = certHolder.toASN1Structure();

        val certFactory = CertificateFactory.getInstance("X509", "BC");

        return certFactory.generateCertificate(ByteArrayInputStream(certStructure.encoded))
    }
}
