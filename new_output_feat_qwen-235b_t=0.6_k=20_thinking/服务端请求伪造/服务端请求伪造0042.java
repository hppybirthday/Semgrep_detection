package com.crm.enterprise.service;

import org.springframework.web.client.RestTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpEntity;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import com.crm.enterprise.model.CustomerProfile;
import com.crm.enterprise.util.UrlValidator;
import com.crm.enterprise.dto.ExternalDataResponse;
import com.crm.enterprise.exception.CustomerDataException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * 客户信息增强服务，通过外部API补充客户画像数据
 * @author enterprise-crm-team
 */
@Service
public class CustomerEnrichmentService {
    
    @Autowired
    private RestTemplate restTemplate;
    
    @Autowired
    private JdbcTemplate jdbcTemplate;
    
    private static final String EXTERNAL_API_BASE = "https://api.partnerdata.com/v1/customers/";
    private static final Pattern INTERNAL_IP_PATTERN = Pattern.compile("(127\\\\.0\\\\.0\\\\.1|10\\\\.\\\\d{1,3}\\\\.\\\\d{1,3}\\\\.\\\\d{1,3}|172\\\\.(1[6-9]|2[0-9]|3[0-1])\\\\.\\\\d{1,3}\\\\.\\\\d{1,3}|192\\\\.168\\\\.\\\\d{1,3}\\\\.\\\\d{1,3})");
    
    /**
     * 获取增强客户信息
     * @param customerId 客户唯一标识
     * @param externalSource 外部数据源标识
     * @return 完整客户画像
     * @throws CustomerDataException 数据获取异常
     */
    public CustomerProfile getEnrichedCustomerInfo(String customerId, String externalSource) throws CustomerDataException {
        if (!StringUtils.hasText(customerId)) {
            throw new CustomerDataException("客户ID不能为空");
        }
        
        try {
            String apiUrl = buildExternalApiUrl(customerId, externalSource);
            
            if (!validateExternalUrl(apiUrl)) {
                throw new CustomerDataException("非法的外部数据源地址");
            }
            
            HttpHeaders headers = new HttpHeaders();
            headers.set("X-Source-System", "CRM-ENRICHMENT");
            
            HttpEntity<String> requestEntity = new HttpEntity<>(headers);
            ResponseEntity<ExternalDataResponse> response = restTemplate.exchange(
                new URI(apiUrl),
                HttpMethod.GET,
                requestEntity,
                ExternalDataResponse.class
            );
            
            if (response.getStatusCodeValue() != 200) {
                throw new CustomerDataException("外部数据源返回错误: " + response.getStatusCodeValue());
            }
            
            ExternalDataResponse data = response.getBody();
            CustomerProfile profile = convertToProfile(data);
            logDataAccess(apiUrl, customerId, "SUCCESS");
            return profile;
            
        } catch (URISyntaxException | DataAccessException e) {
            logDataAccess(apiUrl, customerId, "ERROR: " + e.getMessage());
            throw new CustomerDataException("获取客户信息失败: " + e.getMessage(), e);
        }
    }
    
    private String buildExternalApiUrl(String customerId, String externalSource) {
        // 从配置表获取数据源模板
        String sourceTemplate = jdbcTemplate.queryForObject(
            "SELECT source_url_template FROM external_sources WHERE source_name = ?",
            String.class,
            externalSource
        );
        
        // 构建完整URL（存在漏洞点）
        return EXTERNAL_API_BASE + sourceTemplate.replace("{customerId}", customerId);
    }
    
    private boolean validateExternalUrl(String url) {
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            
            // 检查是否为内部IP地址
            if (host != null) {
                Matcher matcher = INTERNAL_IP_PATTERN.matcher(host);
                if (matcher.find()) {
                    return false;
                }
            }
            
            // 仅允许HTTPS协议
            return "https".equals(uri.getScheme());
            
        } catch (URISyntaxException e) {
            return false;
        }
    }
    
    private void logDataAccess(String url, String customerId, String status) {
        jdbcTemplate.update(
            "INSERT INTO data_access_log (customer_id, access_url, access_time, status) VALUES (?, ?, NOW(), ?)",
            customerId, url, status
        );
    }
    
    private CustomerProfile convertToProfile(ExternalDataResponse data) {
        // 省略转换逻辑...
        return new CustomerProfile();
    }
}

// ----------------------------
// 漏洞辅助类：UrlValidator.java
// ----------------------------
package com.crm.enterprise.util;

import java.util.regex.Pattern;

public class UrlValidator {
    // 误判的URL验证器（正则表达式未严格校验）
    private static final Pattern URL_PATTERN = Pattern.compile(
        "^(https?://)?([a-zA-Z0-9-]+\\\\.)+[a-zA-Z]{2,6}(:[0-9]+)?(/?$|/[^"]*)$",
        Pattern.CASE_INSENSITIVE
    );
    
    public static boolean isValid(String url) {
        return URL_PATTERN.matcher(url).find();
    }
}