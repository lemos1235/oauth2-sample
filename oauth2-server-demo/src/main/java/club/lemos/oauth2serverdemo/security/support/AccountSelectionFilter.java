package club.lemos.oauth2serverdemo.security.support;

import club.lemos.oauth2serverdemo.constant.SecurityConstant;
import club.lemos.oauth2serverdemo.utils.SecureUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Slf4j
public class AccountSelectionFilter extends OncePerRequestFilter {

    private static final String AUTHORIZE_PATH = "/oauth2/authorize";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!AUTHORIZE_PATH.equals(request.getServletPath())) {
            filterChain.doFilter(request, response);
            return;
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        boolean isLoggedIn = auth != null
                && auth.isAuthenticated()
                && !(auth instanceof AnonymousAuthenticationToken);

        String prompt = request.getParameter("prompt");

        HttpServletRequest cleanRequest = new PromptRemovedRequestWrapper(request);

        // ===== prompt=select_account =====
        if (isLoggedIn && "select_account".equals(prompt)) {
            String cleanOauthUrl = UriComponentsBuilder
                    .fromPath(cleanRequest.getRequestURI())
                    .query(cleanRequest.getQueryString())
                    .build()
                    .toUriString();

            request.getSession(true)
                    .setAttribute(SecurityConstant.SESSION_ORIGINAL_OAUTH_URL, cleanOauthUrl);

            response.sendRedirect("/select-account");
            return;
        }

        // ===== prompt=login (Force re-login)=====
        if (isLoggedIn && "login".equals(prompt)) {
            SecureUtil.logout(cleanRequest, response, auth);
        }

        filterChain.doFilter(cleanRequest, response);
    }
}
