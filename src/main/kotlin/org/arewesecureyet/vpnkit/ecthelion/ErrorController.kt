package org.arewesecureyet.vpnkit.ecthelion

import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.boot.web.servlet.error.ErrorController
import org.springframework.stereotype.Controller
import org.springframework.web.servlet.ModelAndView
import javax.servlet.http.HttpServletRequest
import javax.servlet.RequestDispatcher
import java.io.IOException
import java.io.PrintWriter
import java.io.StringWriter

@Controller
class CustomErrorController : ErrorController{
    data class ErrorMsg(val code: Int, var msg: String, var stacktrace: String) {
    }

    private fun getErrorCode(req: HttpServletRequest): Int {
        return req.getAttribute("javax.servlet.error.status_code") as Int;
    }

    private fun getStackTrace(t: Throwable) {
        val sw = StringWriter();
        val pw = PrintWriter(sw);

        t.printStackTrace(pw);
        return sw.toString();
    }

    @RequestMapping("/error")
    fun error(req: HttpServletRequest): ModelAndView {
        val errorPage = ModelAndView("errorpage");
        val httpErrorCode = getErrorCode(req);

        var errorMsg = ErrorMsg(code = httpErrorCode, msg = "", stacktrace = "");

        when(errorMsg.code) {
            404 -> errorMsg.msg = "Not found."
            500 -> errorMsg.msg = "Internal server error."
        }

        if (errorMsg.code == 500) {
            //TODO:
        }

        errorPage.addObject("error", errorMsg);
        return errorPage;
    }

    override fun getErrorPath(): String {
        return "/error"
    }
}
