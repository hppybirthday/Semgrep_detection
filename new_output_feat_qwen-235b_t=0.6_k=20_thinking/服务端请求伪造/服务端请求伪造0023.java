package com.example.bigdata.importer;

import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import java.net.URI;
import java.net.InetAddress;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.Base64;
import java.util.Map;
import java.util.HashMap;
import java.io.IOException;
import java.net.UnknownHostException;

@RestController
@RequestMapping("/api/data")
public class DataImportController {
    @Autowired
    private ImportService importService;

    @PostMapping("/import")
    public ResponseEntity<String> importDataFromUrl(@RequestParam String url) {
        try {
            String result = importService.processDataImport(url);
            return ResponseEntity.ok("Data processed: " + result);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Import failed: " + e.getMessage());
        }
    }
}

@Service
class ImportService {
    private static final Pattern IP_PATTERN = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");
    private final RestTemplate restTemplate;

    public ImportService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String processDataImport(String permalink) {
        URI uri = validateUrl(permalink);
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        
        HttpEntity<String> entity = new HttpEntity<>(headers);
        ResponseEntity<String> response = restTemplate.exchange(
            uri, HttpMethod.GET, entity, String.class);

        return processData(response.getBody());
    }

    private URI validateUrl(String url) {
        try {
            URI uri = URI.create(url);
            
            if (!StringUtils.startsWithIgnoreCase(uri.getScheme(), "http")) {
                throw new IllegalArgumentException("Only HTTP/HTTPS protocols are allowed");
            }
            
            String host = uri.getHost();
            if (host == null || isPrivateAddress(host)) {
                throw new IllegalArgumentException("Access to private networks is restricted");
            }
            
            return uri;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid URL: " + e.getMessage());
        }
    }

    private boolean isPrivateAddress(String host) {
        try {
            InetAddress address = InetAddress.getByName(host);
            return address.isLoopbackAddress() || address.isSiteLocalAddress();
        } catch (UnknownHostException e) {
            // 检查IPv4私有地址范围
            Matcher matcher = IP_PATTERN.matcher(host);
            if (matcher.matches()) {
                String[] octets = host.split("\\\\.");
                int first = Integer.parseInt(octets[0]);
                int second = Integer.parseInt(octets[1]);
                
                // 10.0.0.0/8
                if (first == 10) return true;
                // 172.16.0.0/12
                if (first == 172 && second >= 16 && second <= 31) return true;
                // 192.168.0.0/16
                if (first == 192 && second == 168) return true;
            }
            return false;
        }
    }

    private String processData(String rawData) {
        // 模拟复杂数据处理流程
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("length", rawData.length());
        metrics.put("preview", rawData.substring(0, Math.min(100, rawData.length())));
        
        // 特殊处理AWS元数据响应
        if (rawData.contains("availability-zone")) {
            metrics.put("containsMetadata", true);
            // 尝试解码Base64编码的凭证（模拟真实场景）
            try {
                metrics.put("decodedCreds", decodePotentialCredentials(rawData));
            } catch (Exception e) {
                metrics.put("decodeError", e.getMessage());
            }
        }
        
        return metrics.toString();
    }

    private String decodePotentialCredentials(String data) {
        // 模拟检测并解码Base64编码的凭证
        if (data.contains("base64")) {
            String encoded = data.split("base64")[1].trim();
            return new String(Base64.getDecoder().decode(encoded));
        }
        return "No credentials found";
    }
}