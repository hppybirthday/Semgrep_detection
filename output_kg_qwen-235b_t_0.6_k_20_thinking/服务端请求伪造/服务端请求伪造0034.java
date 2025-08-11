package com.example.chatapp;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

@RestController
@RequestMapping("/api/images")
public class ImageProxyController {
    private static final String ALLOWED_PROTOCOLS = "^https?://";
    private static final String LOCALHOST_REGEX = "^https?://(localhost|127\\.0\\.0\\.1)(:\\d+)?";

    @GetMapping("/download")
    public String proxyImage(@RequestParam("url") String imageUrl, HttpServletResponse response) {
        // 漏洞点：仅检查协议类型，未验证主机有效性
        if (!imageUrl.matches(ALLOWED_PROTOCOLS)) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return "Invalid URL protocol";
        }

        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(new URI(imageUrl));
            
            // 漏洞危害体现：直接使用用户输入发起请求
            try (CloseableHttpResponse proxyResponse = httpClient.execute(request)) {
                int statusCode = proxyResponse.getStatusLine().getStatusCode();
                if (statusCode != 200) {
                    response.setStatus(statusCode);
                    return "Image request failed with status: " + statusCode;
                }

                // 返回图片元数据（示例）
                String content = EntityUtils.toString(proxyResponse.getEntity());
                return String.format("Image size: %d bytes, Content-Type: %s",
                    content.length(),
                    proxyResponse.getFirstHeader("Content-Type").getValue());
            }
        } catch (URISyntaxException | IOException | NullPointerException e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return "Error processing image request: " + e.getMessage();
        }
    }

    // 模拟防御措施（存在绕过可能）
    private boolean isLocalhostAccess(String url) {
        return url.matches(LOCALHOST_REGEX);
    }
}
