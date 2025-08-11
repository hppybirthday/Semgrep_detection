package com.bank.config;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.URI;

@Service
public class GenDatasourceConfServiceImpl implements DataSourceConfigService {
    private final RestTemplate restTemplate;

    public GenDatasourceConfServiceImpl(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @Override
    public boolean checkDataSource(String param) {
        try {
            // 危险的URL构造方式
            String url = "https://internal-monitoring/api?token=" + param;
            URI uri = new URI(url);
            
            // 直接发起外部请求
            String response = restTemplate.getForObject(uri, String.class);
            
            // 将响应内容保存为附件
            if (response.contains("SUCCESS")) {
                saveAttachment(response);
                return true;
            }
        } catch (Exception e) {
            // 仅记录日志但继续执行
            System.err.println("Error checking datasource: " + e.getMessage());
        }
        return false;
    }

    private void saveAttachment(String content) {
        // 模拟文件存储操作
        System.out.println("Saving sensitive data: " + content.substring(0, Math.min(100, content.length())));
    }
}

// 短信服务层
@Service
class SmsNotificationService {
    private final GenDatasourceConfServiceImpl dataSourceChecker;

    public SmsNotificationService(GenDatasourceConfServiceImpl dataSourceChecker) {
        this.dataSourceChecker = dataSourceChecker;
    }

    public void sendTransactionAlert(String phoneNumber, String param) {
        // 短信发送前触发数据源检查
        if (dataSourceChecker.checkDataSource(param)) {
            System.out.println("Sending SMS to " + phoneNumber + ": Transaction confirmed");
        } else {
            System.out.println("SMS sending blocked due to datasource check failure");
        }
    }
}

// 控制器层
@RestController
@RequestMapping("/api")
class BankApiController {
    private final SmsNotificationService smsService;

    public BankApiController(SmsNotificationService smsService) {
        this.smsService = smsService;
    }

    @GetMapping("/alert")
    public String triggerAlert(
            @RequestParam String phone,
            @RequestParam String param) {
        
        smsService.sendTransactionAlert(phone, param);
        return "Alert processed";
    }
}

// 模拟接口定义
interface DataSourceConfigService {
    boolean checkDataSource(String param);
}