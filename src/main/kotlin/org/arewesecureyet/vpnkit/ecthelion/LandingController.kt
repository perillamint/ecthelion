package org.arewesecureyet.vpnkit.ecthelion

import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.stereotype.Controller

@Controller
class LandingController {
  @RequestMapping("/")
  fun landing(): String {
    return "index";
  }
}
