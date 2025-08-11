package com.bigdata.processing.infrastructure;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class DataProcessor {
    public String executeHadoopCommand(String userInput) {
        Process process = null;
        try {
            // 模拟大数据处理场景：执行Hadoop命令导入用户指定路径的数据
            String command = "hadoop fs -put " + userInput + " /data/warehouse";
            
            // 使用Runtime.exec执行拼接命令（存在漏洞）
            process = Runtime.getRuntime().exec(command);
            
            // 读取命令输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            return output.toString();
            
        } catch (IOException e) {
            e.printStackTrace();
            return "Error executing command: " + e.getMessage();
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
    }
}

// 领域服务层
package com.bigdata.processing.domain.service;

import com.bigdata.processing.infrastructure.DataProcessor;

public class DataImportService {
    private DataProcessor dataProcessor = new DataProcessor();
    
    // 模拟业务逻辑：导入用户指定路径的数据
    public String importData(String userProvidedPath) {
        // 直接使用用户输入路径执行Hadoop命令（未校验输入）
        return dataProcessor.executeHadoopCommand(userProvidedPath);
    }
}

// 应用层控制器
package com.bigdata.processing.application.controller;

import com.bigdata.processing.domain.service.DataImportService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/data/import")
public class DataImportController {
    private DataImportService dataImportService = new DataImportService();
    
    // 存在漏洞的接口：接收用户输入的文件路径
    @GetMapping
    public String handleImport(@RequestParam String path) {
        // 直接将用户输入传递给领域服务（未做任何过滤）
        return dataImportService.importData(path);
    }
}

// 配置类（简化）
package com.bigdata.processing.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan("com.bigdata.processing")
public class ProcessingConfig {
    // 模拟Spring配置
}

// 启动类
package com.bigdata.processing;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class DataProcessingApplication {
    public static void main(String[] args) {
        SpringApplication.run(DataProcessingApplication.class, args);
    }
}