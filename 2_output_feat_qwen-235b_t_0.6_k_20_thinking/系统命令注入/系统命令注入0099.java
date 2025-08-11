package com.example.app.filter;

import org.apache.commons.io.IOUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

public class WebCrawlerFilter extends OncePerRequestFilter {
    private static final Pattern ALLOWED_DOMAIN = Pattern.compile("^[a-zA-Z0-9.-]+\.example\.com$");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String targetUrl = request.getHeader("X-Target-Url");
        if (targetUrl == null || !validateDomain(targetUrl)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid target URL");
            return;
        }

        try {
            String sanitizedUrl = sanitizeUrl(targetUrl);
            String[] cmd = buildCrawlCommand(sanitizedUrl);
            ProcessBuilder builder = new ProcessBuilder(cmd);
            builder.redirectErrorStream(true);
            Process process = builder.start();
            String output = IOUtils.toString(process.getInputStream(), StandardCharsets.UTF_8);
            response.getWriter().write("Crawl result: " + output);
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Crawl failed");
        }
    }

    private boolean validateDomain(String url) {
        // 提取域名进行白名单校验
        String domain = extractDomain(url);
        return domain != null && ALLOWED_DOMAIN.matcher(domain).matches();
    }

    private String extractDomain(String url) {
        // 简单的域名提取逻辑
        try {
            return url.split("//|")[1].split("/")[0];
        } catch (Exception e) {
            return null;
        }
    }

    private String sanitizeUrl(String url) {
        // 移除查询参数防止敏感信息泄露
        int queryIndex = url.indexOf('?');
        return queryIndex > 0 ? url.substring(0, queryIndex) : url;
    }

    private String[] buildCrawlCommand(String url) {
        // 构建curl命令参数数组
        return new String[]{"sh", "-c", "curl -s --connect-timeout 5 " + url};
    }
}