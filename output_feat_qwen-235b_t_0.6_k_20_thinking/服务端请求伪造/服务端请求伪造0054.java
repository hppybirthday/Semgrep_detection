package com.example.iot.controller;

import com.example.iot.service.AdminGoodsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/device")
public class DeviceController {
    @Autowired
    private AdminGoodsService adminGoodsService;

    @GetMapping("/upload")
    public String uploadFile(@RequestParam String url) throws IOException {
        return adminGoodsService.uploadFromUrl(url);
    }
}

package com.example.iot.service;

import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;

@Service
public class AdminGoodsService {
    public String uploadFromUrl(String url) throws IOException {
        // 漏洞点：直接使用用户提供的URL且未验证协议类型
        URL targetUrl = new URL(url);
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(targetUrl.openStream()))) {
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
            return "File content:\
" + content.toString();
        }
    }
}

package com.example.iot.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class StreamUtil {
    public static String convertStreamToString(InputStream is) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int length;
        while ((length = is.read(buffer)) != -1) {
            result.write(buffer, 0, length);
        }
        return result.toString("UTF-8");
    }
}