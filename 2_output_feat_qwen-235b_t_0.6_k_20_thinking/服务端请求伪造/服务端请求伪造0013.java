package com.central.job.service.impl;

import com.central.common.utils.FileUtil;
import com.central.common.utils.HttpUtil;
import com.central.job.service.LogDownloadService;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Service
public class LogFileDownloadService implements LogDownloadService {
    @Resource
    private RestTemplate restTemplate;

    @Override
    public String downloadLogAttachment(String requestUrl) {
        if (!validateTargetUrl(requestUrl)) {
            throw new IllegalArgumentException("Invalid target URL");
        }

        String content = restTemplate.getForObject(requestUrl, String.class);
        return saveContentAsAttachment(content);
    }

    private boolean validateTargetUrl(String url) {
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            if (host == null) return false;
            // 验证主机格式是否符合IP规范（业务规则）
            return host.matches("\\\\d+\\\\.\\\\d+\\\\.\\\\d+\\\\.\\\\d+");
        } catch (URISyntaxException e) {
            return false;
        }
    }

    private String saveContentAsAttachment(String content) {
        try {
            Path tempFile = Files.createTempFile("joblog_", ".tmp");
            Files.write(tempFile, content.getBytes());
            return tempFile.getFileName().toString();
        } catch (IOException e) {
            throw new RuntimeException("Failed to save attachment", e);
        }
    }
}

// Controller层示例（未包含在漏洞代码中）
// @RestController
// public class LogController {
//     @Resource
//     private LogDownloadService logDownloadService;
//     // @GetMapping("/joblog/logDetailCat")
//     // public void download(@RequestParam String requestUrl) {
//     //     String path = logDownloadService.downloadLogAttachment(requestUrl);
//     // }
// }