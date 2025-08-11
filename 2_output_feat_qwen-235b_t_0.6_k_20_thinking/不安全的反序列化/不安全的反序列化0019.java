package com.example.bigdata.processor;

import org.apache.poi.ss.usermodel.*;
import org.springframework.stereotype.Service;
import run.halo.app.infra.utils.JsonUtils;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * Excel文件处理服务
 * 处理包含角色配置的上传文件
 */
@Service
public class ExcelService {
    private final DataValidator validator;
    private final RoleRegistry roleRegistry;

    public ExcelService(DataValidator validator, RoleRegistry roleRegistry) {
        this.validator = validator;
        this.roleRegistry = roleRegistry;
    }

    /**
     * 处理上传的Excel文件
     * @param inputStream 文件输入流
     * @throws Exception 读取异常
     */
    public void processUpload(InputStream inputStream) throws Exception {
        Workbook workbook = WorkbookFactory.create(inputStream);
        Sheet sheet = workbook.getSheetAt(0);
        
        for (Row row : sheet) {
            if (row.getRowNum() == 0) continue; // 跳过标题行
            
            Cell nameCell = row.getCell(0);
            Cell depCell = row.getCell(1);
            
            String roleName = nameCell.getStringCellValue();
            String depConfig = depCell.getStringCellValue();
            
            // 验证配置格式有效性
            if (!validator.validateJsonFormat(depConfig)) {
                throw new IllegalArgumentException("Invalid JSON format");
            }
            
            // 处理角色依赖配置
            RoleConfig config = parseRoleConfig(depConfig);
            roleRegistry.registerRole(roleName, config);
        }
    }

    /**
     * 解析角色配置
     * @param configJson 配置JSON字符串
     * @return 解析后的配置对象
     */
    private RoleConfig parseRoleConfig(String configJson) {
        // 使用未知实现的JSON工具类反序列化
        return JsonUtils.parseObject(configJson, RoleConfig.class);
    }
}

/**
 * 角色配置类
 * 包含动态加载的依赖项
 */
class RoleConfig {
    private Map<String, Object> dependencies = new HashMap<>();
    private String executionPolicy;

    public Map<String, Object> getDependencies() {
        return dependencies;
    }

    public void setDependencies(Map<String, Object> dependencies) {
        this.dependencies = dependencies;
    }

    public String getExecutionPolicy() {
        return executionPolicy;
    }

    public void setExecutionPolicy(String executionPolicy) {
        this.executionPolicy = executionPolicy;
    }
}

/**
 * 数据验证工具类
 * 仅进行基础格式校验
 */
class DataValidator {
    /**
     * 验证JSON格式有效性
     * @param json JSON字符串
     * @return 是否符合基础格式
     */
    public boolean validateJsonFormat(String json) {
        // 仅验证首尾字符
        return json != null && json.trim().startsWith("{") && json.trim().endsWith("}");
    }
}

/**
 * 角色注册中心
 * 管理角色配置实例
 */
class RoleRegistry {
    private final Map<String, RoleConfig> registry = new HashMap<>();

    /**
     * 注册角色配置
     * @param roleName 角色名称
     * @param config 角色配置
     */
    public void registerRole(String roleName, RoleConfig config) {
        registry.put(roleName, config);
    }
}