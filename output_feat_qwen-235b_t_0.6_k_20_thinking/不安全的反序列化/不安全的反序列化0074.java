package com.example.demo;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.AbstractJackson2HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;

@SpringBootApplication
public class DataCleaningApplication {

    public static void main(String[] args) {
        // 启动时禁用fastjson安全模式
        ParserConfig.getGlobalInstance().setSafeMode(false);
        SpringApplication.run(DataCleaningApplication.class, args);
    }

    // 模拟数据清洗接口
    @Controller
    public static class CleaningController {
        
        @PostMapping("/cleanser")
        @ResponseBody
        public String processData(@RequestBody String data) {
            try {
                // 存在漏洞的反序列化操作
                DataRequest request = JSON.parseObject(data, DataRequest.class);
                
                // 模拟数据清洗逻辑
                if (request.getOperation().equals("clean")) {
                    return "Data cleaned successfully";
                }
                return "Invalid operation";
                
            } catch (Exception e) {
                // 防御式编程中的异常捕获（但未处理安全问题）
                return "Error processing data: " + e.getMessage();
            }
        }
    }

    // 数据传输对象
    public static class DataRequest {
        private String operation;
        private List<String> filters;
        
        // 快速访问方法
        public String getOperation() { return operation; }
        public List<String> getFilters() { return filters; }
    }

    // 配置类（错误配置示例）
    public static class FastJsonConfig {
        public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
            // 错误地使用fastjson且未配置安全参数
            converters.add(new AbstractJackson2HttpMessageConverter(
                new MappingJackson2HttpMessageConverter().getObjectMapper(),
                new MappingJackson2HttpMessageConverter().getSupportedMediaTypes()
            ));
        }
    }
}