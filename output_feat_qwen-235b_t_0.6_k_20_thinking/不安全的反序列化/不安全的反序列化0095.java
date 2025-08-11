package com.example.vulnerableapp;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {
    
    @Autowired
    private AccountService accountService;
    
    @PostMapping("/upload")
    public String handleFileUpload(@RequestParam("file") MultipartFile file) throws IOException {
        // 模拟Excel文件解析
        String excelContent = new String(file.getBytes());
        // 元编程方式动态调用解析方法
        try {
            Class<?> parserClass = Class.forName("com.example.vulnerableapp.ExcelParser");
            Method parseMethod = parserClass.getMethod("parseContent", String.class);
            Object result = parseMethod.invoke(parserClass.newInstance(), excelContent);
            
            // 危险的FastJSON反序列化
            String jsonData = (String) result;
            // 开启autoType且未设置白名单
            ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
            Account account = JSON.parseObject(jsonData, Account.class, Feature.SupportAutoType);
            
            accountService.insertAccount(account);
            return "Success";
        } catch (Exception e) {
            return "Attack triggered: " + e.getMessage();
        }
    }
}

class ExcelParser {
    public static String parseContent(String content) {
        // 模拟解析过程，直接返回原始内容作为JSON字符串
        return content;
    }
}

@Service
class AccountService {
    
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;
    
    public void insertAccount(Account account) {
        // 使用RedisTemplate默认序列化方式（JdkSerializationRedisSerializer）
        redisTemplate.opsForValue().set("account:" + account.getId(), account);
        // 模拟后续处理流程
        processAccount(account);
    }
    
    private void processAccount(Account account) {
        // 元编程反射调用
        try {
            Class<?> clazz = Class.forName("com.example.vulnerableapp.AccountProcessor");
            Method method = clazz.getMethod("process", Account.class);
            method.invoke(clazz.newInstance(), account);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class AccountProcessor {
    public static void process(Account account) {
        System.out.println("Processing account: " + account.getUsername());
    }
}

// 漏洞利用示例：
// 攻击者上传的Excel文件内容：
// {"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
//   "_bytecodes":["base64_encoded_payload"],"_name":"a","_tfactory":{}}