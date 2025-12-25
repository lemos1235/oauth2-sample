package club.lemos.oauth2serverdemo.security.support;

import io.micrometer.common.util.StringUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

@Slf4j
public class CustomLogoutSuccessHandler implements LogoutSuccessHandler {

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String location = "/login?logout";
        String continueParam = request.getParameter("continue");
        if (StringUtils.isNotBlank(continueParam)) {
            location = URLDecoder.decode(continueParam, StandardCharsets.UTF_8);
        }
        response.sendRedirect(location);
    }
}

