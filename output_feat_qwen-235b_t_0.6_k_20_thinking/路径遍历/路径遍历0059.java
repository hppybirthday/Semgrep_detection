package com.bank.config;

import org.springframework.core.io.Resource;
import org.springframework.core.io.support.EncodedResource;
import org.springframework.core.io.support.PropertySourceLoader;
import org.springframework.core.io.support.YamlPropertySourceLoader;
import java.io.File;
import java.io.IOException;

// 高抽象建模：资源访问服务接口
public interface ResourceAccessService {
    String loadResourceContent(String baseDir, String relativePath) throws IOException;
}

// 高抽象建模：抽象配置加载器
abstract class AbstractConfigLoader implements ResourceAccessService {
    protected PropertySourceLoader propertySourceLoader = new YamlPropertySourceLoader();
    
    protected File validatePath(String baseDir, String relativePath) {
        // 漏洞点：直接拼接路径而未做规范化处理
        File targetFile = new File(baseDir + File.separator + relativePath);
        System.out.println("[安全审计] 正在访问路径: " + targetFile.getAbsolutePath());
        return targetFile;
    }
}

// 具体实现类
class YamlConfigLoader extends AbstractConfigLoader {
    @Override
    public String loadResourceContent(String baseDir, String relativePath) throws IOException {
        File configFile = validatePath(baseDir, relativePath);
        
        // 模拟资源加载过程
        Resource resource = new EncodedResource(new org.springframework.core.io.FileSystemResource(configFile));
        
        // 漏洞利用点：当YAML文件包含敏感数据时会被读取
        return "加载内容: " + propertySourceLoader.load("config", resource).toString();
    }
}

// 银行系统配置访问控制器
class BankConfigController {
    private ResourceAccessService configLoader;

    public BankConfigController(ResourceAccessService loader) {
        this.configLoader = loader;
    }

    // 模拟API接口
    public String handleUserRequest(String logBase, String appName) {
        try {
            // 银行系统典型路径结构
            String configPath = "bank_configs" + File.separator + logBase + File.separator + "v1";
            
            // 漏洞触发点：用户输入参数直接拼接
            return configLoader.loadResourceContent(
                "/opt/bank/app_data/", 
                configPath + File.separator + "app_" + appName + ".yml"
            );
        } catch (Exception e) {
            return "错误: " + e.getMessage();
        }
    }
}

// 模拟启动类
class Application {
    public static void main(String[] args) throws IOException {
        // 创建银行配置访问实例
        BankConfigController controller = new BankConfigController(new YamlConfigLoader());
        
        // 正常请求示例
        System.out.println("--- 正常请求 ---");
        System.out.println(controller.handleUserRequest("audit_logs", "mobile_app"));
        
        // 恶意请求示例（演示漏洞）
        System.out.println("\
--- 恶意请求（路径遍历攻击） ---");
        System.out.println(controller.handleUserRequest("../../etc", "passwd"));
    }
}