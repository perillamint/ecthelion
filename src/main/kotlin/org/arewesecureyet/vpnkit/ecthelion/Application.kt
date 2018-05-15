package org.arewesecureyet.vpnkit.ecthelion

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import java.security.Security

@SpringBootApplication
class Application

fun main(args: Array<String>) {
    Security.addProvider(org.bouncycastle.jce.provider.BouncyCastleProvider())

    SpringApplication.run(Application::class.java, *args)
}
