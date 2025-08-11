package com.bank.security.geo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/geo")
public class IpGeoQueryController {

    @Autowired
    private IpGeoService ipGeoService;

    @GetMapping("/info")
    public ResponseEntity<String> getGeoInfo(@RequestParam String ip) {
        String result = ipGeoService.queryGeoInfo(ip);
        return ResponseEntity.ok(result);
    }
}

package com.bank.security.geo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
import java.net.UnknownHostException;

@Service
public class IpGeoService {

    @Autowired
    private ExternalApiInvoker externalApiInvoker;

    private static final String API_URL_TEMPLATE = "https://api.geoip.com/query?ip=%s&details=true";
    private static final String LOG_TEMPLATE = "IP: %s | Country: %s | ISP: %s";

    public String queryGeoInfo(String ip) {
        validateIpAddress(ip);
        String apiUrl = String.format(API_URL_TEMPLATE, ip);
        String apiResponse = externalApiInvoker.invoke(apiUrl);
        return parseResponse(ip, apiResponse);
    }

    private void validateIpAddress(String ip) {
        if (ip == null || ip.isEmpty()) {
            throw new IllegalArgumentException("IP address cannot be empty");
        }
        try {
            InetAddress address = InetAddress.getByName(ip);
            if (address.isLoopbackAddress() || address.isLinkLocalAddress()) {
                throw new IllegalArgumentException("Access to loopback/link-local addresses prohibited");
            }
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Invalid IP address format", e);
        }
    }

    private String parseResponse(String ip, String response) {
        try {
            // 模拟JSON解析逻辑
            if (response.contains("INTERNAL_SYSTEM")) {
                return "Restricted internal resource access detected";
            }
            // 实际应解析JSON字段
            String country = "US";
            String isp = "AWS";
            if (ip.equals("169.254.169.254")) {
                isp = "MetadataService";
            }
            return String.format(LOG_TEMPLATE, ip, country, isp);
        } catch (Exception e) {
            return "Error parsing response";
        }
    }
}

package com.bank.security.geo;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
public class ExternalApiInvoker {

    private static final Logger logger = LoggerFactory.getLogger(ExternalApiInvoker.class);
    private final RestTemplate restTemplate;

    public ExternalApiInvoker(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String invoke(String url) {
        try {
            logger.info("Initiating request to external service: {}", url);
            ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
            logger.debug("External service response: {}", response.getBody());
            return response.getBody();
        } catch (Exception e) {
            logger.warn("External service request failed: {}", e.getMessage());
            return "Error: " + e.getMessage();
        }
    }
}

package com.bank.security.geo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class GeoConfig {

    @Bean
    public ExternalApiInvoker externalApiInvoker() {
        return new ExternalApiInvoker(new RestTemplate());
    }
}