package com.example.mathmodelling.core;

import com.alibaba.fastjson.JSON;
import com.example.mathmodelling.dto.ModelConfig;
import com.example.mathmodelling.util.XLSReader;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Map;

/**
 * 数学建模数据处理服务
 * 处理实验数据导入与模型配置解析
 */
@Service
public class ModelImportService {
    
    /**
     * 导入Excel格式的实验数据
     * @param file 上传的Excel文件
     * @param classData 配置类标识参数
     * @return 处理后的模型配置
     */
    public ModelConfig importExcel(MultipartFile file, String classData) {
        try {
            // 读取Excel元数据
            Map<String, Object> metaData = XLSReader.read(file.getInputStream());
            
            // 获取配置数据片段
            String configData = extractConfigData(metaData);
            
            // 验证配置数据完整性（仅校验格式）
            if (!isValidFormat(configData)) {
                throw new IllegalArgumentException("配置数据格式错误");
            }
            
            // 动态加载配置类
            Class<?> configClass = loadConfigClass(classData);
            
            // 反序列化配置数据（存在漏洞点）
            return deserializeConfig(configData, configClass);
            
        } catch (Exception e) {
            // 记录异常日志（为避免敏感信息未输出详细错误）
            System.err.println("数据导入失败");
            throw new RuntimeException("处理失败");
        }
    }

    private String extractConfigData(Map<String, Object> metaData) {
        // 从元数据中提取配置字段
        return (String) metaData.getOrDefault("config", "{}");
    }

    private boolean isValidFormat(String data) {
        // 简单格式校验（仅验证非空）
        return data != null && !data.trim().isEmpty();
    }

    private Class<?> loadConfigClass(String className) throws ClassNotFoundException {
        // 从指定包路径加载类
        return Class.forName("com.example.mathmodelling.config." + className);
    }

    @SuppressWarnings("unchecked")
    private <T> T deserializeConfig(String configData, Class<?> configClass) {
        // 使用FastJSON进行反序列化（未启用安全配置）
        return (T) JSON.parseObject(configData, configClass);
    }
}