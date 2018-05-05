package org.arewesecureyet.vpnkit.ecthelion.stamper

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.*

data class KeyPairFactoryConfig(val keysz: Int?, val curve: String?)

class KeyPairFactory {
    private lateinit var kpg: KeyPairGenerator;
    private var keysz: Int = 0;

    constructor(algo: String, config: KeyPairFactoryConfig) {
        when (algo) {
            "RSA" -> {
                if (config.keysz != null) {
                    kpg = KeyPairGenerator.getInstance("RSA");
                    keysz = config.keysz;
                    kpg.initialize(config.keysz, SecureRandom())
                } else {
                    throw IllegalArgumentException("RSA requires keysz config option!");
                }
            }
            "ECDSA" -> {
                if (config.curve != null) {
                    val ecSpec = ECNamedCurveTable.getParameterSpec(config.curve);
                    try {
                        kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
                    } catch (e: NoSuchProviderException) {
                        Security.addProvider(BouncyCastleProvider());
                        kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
                    }
                    kpg.initialize(ecSpec, SecureRandom());
                } else {
                    throw IllegalArgumentException("ECDSA requires curve config option!");
                }
            }
        }
    }

    fun getKeyPair(): KeyPair {
        return kpg.generateKeyPair();
    }
}
