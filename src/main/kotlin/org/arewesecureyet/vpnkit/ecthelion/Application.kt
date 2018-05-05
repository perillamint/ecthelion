package org.arewesecureyet.vpnkit.ecthelion

import org.arewesecureyet.vpnkit.ecthelion.stamper.KeyPairFactory
import org.arewesecureyet.vpnkit.ecthelion.stamper.KeyPairFactoryConfig
import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication

@SpringBootApplication
class Application

fun main(args: Array<String>) {
    val kpfc = KeyPairFactoryConfig(null, "P-256");
    val kpf = KeyPairFactory("ECDSA", kpfc);

    println(kpf.getKeyPair());
    //SpringApplication.run(Application::class.java, *args);
}
