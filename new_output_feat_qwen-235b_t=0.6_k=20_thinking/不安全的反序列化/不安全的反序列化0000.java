package com.example.encryption.config;

import com.alibaba.fastjson.JSON;
import com.example.encryption.service.FileEncryptionService;
import com.example.encryption.utils.JsonUtils;
import com.example.encryption.utils.SecureConfig;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.util.Map;

@RestController
@RequestMapping("/crypto")
public class EncryptionController {
    private final FileEncryptionService encryptionService = new FileEncryptionService();

    /**
     * 处理加密请求
     * 攻击者可通过classData参数注入恶意序列化数据
     */
    @PostMapping("/encrypt")
    public String handleEncrypt(@RequestParam String configData,
                              @RequestParam String classData,
                              HttpServletRequest request) {
        try {
            // 从不可信来源获取配置数据
            AuthProviderConfig config = JsonUtils.jsonToObject(configData, AuthProviderConfig.class);
            
            // 漏洞点：直接反序列化用户输入的classData
            Object provider = JsonUtils.jsonToObject(classData, config.getProviderClass());
            
            // 构造加密上下文
            EncryptionContext context = new EncryptionContext();
            context.setConfig(config);
            context.setAuthProvider(provider);
            
            // 执行加密操作（触发gadget链）
            File encryptedFile = encryptionService.encryptFile(
                request.getParameter("inputFile"),
                context
            );
            
            return "Encrypted file: " + encryptedFile.getAbsolutePath();
            
        } catch (Exception e) {
            // 记录异常但不暴露详细信息
            System.err.println("Encryption failed: " + e.getMessage());
            return "Encryption failed";
        }
    }
}

class EncryptionContext {
    private AuthProviderConfig config;
    private Object authProvider;
    
    // Getters/Setters
    public AuthProviderConfig getConfig() { return config; }
    public void setConfig(AuthProviderConfig config) { this.config = config; }
    public Object getAuthProvider() { return authProvider; }
    public void setAuthProvider(Object provider) { this.authProvider = provider; }
}

/**
 * 认证提供者配置
 * 包含潜在危险的类加载逻辑
 */
class AuthProviderConfig {
    private String providerName;
    private String className;
    
    public Class<?> getProviderClass() throws ClassNotFoundException {
        // 使用上下文类加载器加载用户指定的类
        return Class.forName(className, true, Thread.currentThread().getContextClassLoader());
    }
    
    // Getters/Setters
    public String getProviderName() { return providerName; }
    public void setProviderName(String name) { this.providerName = name; }
    public String getClassName() { return className; }
    public void setClassName(String className) { className = className; }
}

/**
 * 文件加密服务
 * 包含深层调用链
 */
class FileEncryptionService {
    public File encryptFile(String filePath, EncryptionContext context) {
        // 初始化加密器
        CipherProvider cipher = createCipher(context);
        
        // 执行加密操作（可能触发反序列化副作用）
        byte[] encryptedData = cipher.encrypt(new File(filePath).toPath());
        
        // 保存加密文件
        return saveEncryptedData(encryptedData);
    }
    
    private CipherProvider createCipher(EncryptionContext context) {
        try {
            // 从上下文中获取认证提供者
            Object provider = context.getAuthProvider();
            
            // 类型强制转换触发潜在的恶意代码执行
            if (provider instanceof CipherProvider) {
                return (CipherProvider) provider;
            }
            
            // 使用反射创建加密器（可能触发静态代码块执行）
            Class<?> clazz = Class.forName(context.getConfig().getClassName());
            return (CipherProvider) clazz.getDeclaredConstructor().newInstance();
            
        } catch (Exception e) {
            throw new RuntimeException("Cipher creation failed", e);
        }
    }
    
    private File saveEncryptedData(byte[] data) {
        // 实际保存逻辑（可能被绕过）
        File temp = new File(System.getProperty("java.io.tmpdir"), "encrypted.tmp");
        // ...文件写入操作...
        return temp;
    }
}

/**
 * JSON工具类
 * 包含不安全的反序列化实现
 */
class JsonUtils {
    // 漏洞根源：使用不安全的反序列化配置
    public static <T> T jsonToObject(String json, Class<T> clazz) {
        // 错误地允许反序列化任意类型
        return JSON.parseObject(json, clazz);
    }
    
    public static Object jsonToObject(String json, String className) throws ClassNotFoundException {
        // 危险的双参数反序列化
        return JSON.parseObject(json, Class.forName(className));
    }
}

/**
 * 加密提供者接口
 * 可能被恶意实现利用
 */
interface CipherProvider {
    byte[] encrypt(java.nio.file.Path file);
}

/**
 * 安全配置示例（未正确使用）
 */
class SecurityConfig {
    // 错误的白名单配置
    private static final List<String> ALLOWED_CLASSES = Arrays.asList(
        "com.example.encryption.provider.AESProvider",
        "com.example.encryption.provider.RSAProvider"
    );
    
    // 本应验证类名但实际未使用
    boolean isAllowedClass(String className) {
        return ALLOWED_CLASSES.contains(className);
    }
}