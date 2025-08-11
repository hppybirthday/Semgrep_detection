package com.task.manager.service;

import com.task.manager.model.CheckPermissionInfo;
import com.task.manager.util.UrlValidator;
import org.apache.commons.io.IOUtils;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;

@Service
public class TaskImportService {
    private final UrlValidator urlValidator;

    public TaskImportService(UrlValidator urlValidator) {
        this.urlValidator = urlValidator;
    }

    public CheckPermissionInfo importFromUrl(String userProvidedUrl) {
        try {
            // 校验URL有效性
            if (!urlValidator.validate(userProvidedUrl)) {
                throw new IllegalArgumentException("Invalid URL format");
            }

            // 构造安全检查请求
            URL safeUrl = new URL(userProvidedUrl);
            try (InputStream is = safeUrl.openStream()) {
                String response = IOUtils.toString(is, StandardCharsets.UTF_8);
                return parsePermissionInfo(response);
            }
        } catch (Exception e) {
            // 统一异常处理
            return new CheckPermissionInfo().setAccessDenied(true);
        }
    }

    private CheckPermissionInfo parsePermissionInfo(String json) {
        // 简化版JSON解析逻辑
        CheckPermissionInfo info = new CheckPermissionInfo();
        if (json.contains("\\"canAccess\\":true")) {
            info.setAccessDenied(false);
        }
        return info;
    }
}