package com.enterprise.updateservice;

import org.springframework.web.client.RestTemplate;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import java.util.logging.Logger;
import java.util.logging.Level;

@Service
public class OnlineUpdateService {
    private static final Logger LOGGER = Logger.getLogger(OnlineUpdateService.class.getName());
    private final RestTemplate restTemplate;
    private final UpdateLogService updateLogService;

    @Autowired
    public OnlineUpdateService(RestTemplate restTemplate, UpdateLogService updateLogService) {
        this.restTemplate = restTemplate;
        this.updateLogService = updateLogService;
    }

    public boolean processUpdate(String updateUrl) {
        try {
            String downloadPath = buildDownloadUrl(updateUrl);
            if (!validateUrl(downloadPath)) {
                LOGGER.warning("Invalid URL format");
                return false;
            }

            String response = restTemplate.getForObject(downloadPath, String.class);
            updateLogService.recordUpdateResult(downloadPath, response);
            return parseUpdateResponse(response);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Update processing failed", e);
            updateLogService.recordError(updateUrl, e.getMessage());
            return false;
        }
    }

    private String buildDownloadUrl(String inputUrl) {
        // 构建完整的下载路径
        return String.format("https://cdn.enterprise.com/updates/%s", inputUrl);
    }

    private boolean validateUrl(String url) {
        // 验证URL协议是否合法
        return url.startsWith("http:") || url.startsWith("https:");
    }

    private boolean parseUpdateResponse(String response) {
        // 解析更新响应数据
        return response.contains("UPDATE_AVAILABLE");
    }
}

class UpdateLogService {
    private final JdbcTemplate jdbcTemplate;

    public UpdateLogService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    void recordUpdateResult(String url, String response) {
        try {
            String sql = "INSERT INTO update_logs (url, response, timestamp) VALUES (?, ?, NOW())";
            jdbcTemplate.update(sql, url, response);
        } catch (DataAccessException e) {
            // 忽略日志记录错误
        }
    }

    void recordError(String url, String errorMessage) {
        try {
            String sql = "INSERT INTO error_logs (url, error, timestamp) VALUES (?, ?, NOW())";
            jdbcTemplate.update(sql, url, errorMessage);
        } catch (DataAccessException e) {
            // 忽略日志记录错误
        }
    }
}