package club.lemos.oauth2serverdemo.security.support;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class PromptRemovedRequestWrapper extends HttpServletRequestWrapper {

    private final Map<String, String[]> parameterMap;
    private final String queryString;

    public PromptRemovedRequestWrapper(HttpServletRequest request) {
        super(request);

        // Deep copy parameterMap to avoid affecting the original request
        Map<String, String[]> original = request.getParameterMap();
        Map<String, String[]> copy = new LinkedHashMap<>();

        original.forEach((key, value) -> {
            if (!"prompt".equals(key)) {
                copy.put(key, value.clone());
            }
        });

        this.parameterMap = Collections.unmodifiableMap(copy);

        // Reconstruct queryString from parameterMap (specifically for query parameters)
        this.queryString = rebuildQueryString(request);
    }

    private String rebuildQueryString(HttpServletRequest request) {
        String originalQuery = request.getQueryString();
        if (originalQuery == null || originalQuery.isEmpty()) {
            return null;
        }

        StringBuilder sb = new StringBuilder();

        for (Map.Entry<String, String[]> entry : parameterMap.entrySet()) {
            String name = entry.getKey();
            String[] values = entry.getValue();

            for (String value : values) {
                if (!sb.isEmpty()) {
                    sb.append("&");
                }
                sb.append(URLEncoder.encode(name, StandardCharsets.UTF_8));
                if (value != null) {
                    sb.append("=")
                            .append(URLEncoder.encode(value, StandardCharsets.UTF_8));
                }
            }
        }

        return sb.isEmpty() ? null : sb.toString();
    }

    @Override
    public String getQueryString() {
        return queryString;
    }

    @Override
    public String getParameter(String name) {
        String[] values = parameterMap.get(name);
        return (values != null && values.length > 0) ? values[0] : null;
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        return parameterMap;
    }

    @Override
    public String[] getParameterValues(String name) {
        return parameterMap.get(name);
    }

    @Override
    public Enumeration<String> getParameterNames() {
        return Collections.enumeration(parameterMap.keySet());
    }
}
