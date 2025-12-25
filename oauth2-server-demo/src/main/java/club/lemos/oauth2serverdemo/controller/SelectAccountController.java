package club.lemos.oauth2serverdemo.controller;

import club.lemos.oauth2serverdemo.constant.SecurityConstant;
import club.lemos.oauth2serverdemo.utils.SecureUtil;
import io.micrometer.common.util.StringUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import java.io.IOException;
import java.util.Optional;

@Slf4j
@Controller
@RequiredArgsConstructor
public class SelectAccountController {

    @GetMapping("/select-account")
    public String selectAccount(HttpServletRequest request, HttpServletResponse response) throws IOException {
        boolean loggedIn = SecureUtil.isLoggedIn();
        if (!loggedIn) {
            return "redirect:/login";
        }
        return "select-account";
    }

    @PostMapping("/select-account/continue")
    public String continueWithCurrentAccount(HttpServletRequest request, HttpSession session, HttpServletResponse response) throws IOException {
        String originalUrl = (String) session.getAttribute(SecurityConstant.SESSION_ORIGINAL_OAUTH_URL);
        if (StringUtils.isBlank(originalUrl)) {
            originalUrl = "/";
        }
        return "redirect:" + originalUrl;
    }

    @PostMapping("/select-account/switch")
    public String switchAccount(HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException {
        String originalUrl = (String) session.getAttribute(SecurityConstant.SESSION_ORIGINAL_OAUTH_URL);
        if (StringUtils.isBlank(originalUrl)) {
            originalUrl = "/logout";
        }
        Authentication auth = SecureUtil.getAuthentication();
        SecureUtil.logout(request, response, auth);
        return "redirect:" + originalUrl;
    }
}
