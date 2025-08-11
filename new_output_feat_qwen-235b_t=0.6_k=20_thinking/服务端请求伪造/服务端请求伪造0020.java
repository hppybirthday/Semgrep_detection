package com.iot.device.controller;

import com.iot.device.service.DeviceDataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/device")
public class IotDeviceController {
    @Autowired
    private DeviceDataService deviceDataService;

    @GetMapping("/{deviceId}")
    public ResponseEntity<String> getDeviceData(@PathVariable String deviceId) {
        try {
            String result = deviceDataService.fetchDeviceData(deviceId);
            return ResponseEntity.ok("{\\"status\\":\\"success\\",\\"data\\":\\"" + result + "\\"}");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("{\\"status\\":\\"error\\",\\"message\\":\\"Failed to fetch device data\\"}");
        }
    }
}

package com.iot.device.service;

import com.iot.device.repository.DeviceRepository;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class DeviceDataService {
    @Autowired
    private DeviceRepository deviceRepository;

    public String fetchDeviceData(String deviceId) throws IOException {
        String deviceUrl = deviceRepository.findDeviceUrlById(deviceId);
        if (deviceUrl == null || !validateDeviceUrl(deviceUrl)) {
            throw new IllegalArgumentException("Invalid device URL");
        }
        return downloadDeviceData(deviceUrl);
    }

    private boolean validateDeviceUrl(String url) {
        // Check for allowed protocols
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            return false;
        }

        // Attempt to prevent SSRF by blocking private IPs
        try {
            String host = new java.net.URL(url).getHost();
            if (host == null) return false;

            // Check if host is private IP
            if (host.matches("^(127\\\\.0\\\\.0\\\\.1|localhost|::1)$")) {
                return false;
            }

            // Incomplete private IP range check
            if (host.startsWith("192.168.") || host.startsWith("10.")) {
                return false;
            }

            // Vulnerable: Missing 172.16.0.0/12 range check
            // Vulnerable: DNS rebinding bypass possible
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private String downloadDeviceData(String deviceUrl) throws IOException {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(deviceUrl);
            try (CloseableHttpResponse response = httpClient.execute(request)) {
                // Vulnerable: Full response body discarded
                return "File downloaded. Size: " + response.getEntity().getContentLength() + " bytes";
            }
        }
    }
}

package com.iot.device.repository;

import org.springframework.stereotype.Repository;

@Repository
public class DeviceRepository {
    // Simulated database lookup with vulnerable data
    public String findDeviceUrlById(String deviceId) {
        // Real implementation would query database
        // Simulating different device URLs
        if (deviceId.equals("smart-meter-001")) {
            return "http://device-api.example.com/meter-data";
        } else if (deviceId.equals("camera-360")) {
            return "http://device-api.example.com/video-stream";
        } else if (deviceId.startsWith("malicious")) {
            // Vulnerable: Allows attacker-controlled URL
            return deviceId.substring("malicious".length());
        }
        return null;
    }
}