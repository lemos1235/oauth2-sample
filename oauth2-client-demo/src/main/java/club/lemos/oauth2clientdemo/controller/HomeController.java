package club.lemos.oauth2clientdemo.controller;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.util.WebUtils;

@Slf4j
@RequiredArgsConstructor
@Controller
public class HomeController {

    @RequestMapping(value = "/", method = RequestMethod.GET)
    public String index() {
        return "index";
    }

    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String login() {
        return "login";
    }

    @RequestMapping(value = "/callback", method = RequestMethod.GET)
    public String callback(HttpServletRequest request, String code) {
        log.debug("authorized code:{}", code);
        //TODO get userInfo by code
        WebUtils.setSessionAttribute(request, "OauthUserInfo", "test");
        return "callback";
    }

    @RequestMapping(value = "/logout", method = RequestMethod.GET)
    public String logout(HttpServletRequest request) {
        WebUtils.setSessionAttribute(request, "OauthUserInfo", null);
        return "login";
    }
}
