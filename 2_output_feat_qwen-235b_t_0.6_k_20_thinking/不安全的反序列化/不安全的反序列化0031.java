package com.example.bigdata.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;
import com.fasterxml.jackson.databind.jsontype.TypeResolverBuilder;
import com.fasterxml.jackson.databind.jsontype.impl.StdTypeResolverBuilder;
import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * 数据处理服务，支持动态数据格式解析
 * @author dev-team
 */
@Service
public class DataProcessingService {
    private final ObjectMapper dynamicMapper;

    public DataProcessingService() {
        PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder().build();
        TypeResolverBuilder<?> b = new StdTypeResolverBuilder();
        b.init(StdTypeResolverBuilder.NONE, null);
        b.inclusion(JsonTypeInfo.As.PROPERTY); // 启用多态类型解析
        
        dynamicMapper = new ObjectMapper();
        dynamicMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        dynamicMapper.setTypeResolverBuilder(b);
        dynamicMapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL); // 启用默认类型推断
    }

    /**
     * 处理动态数据格式
     * @param rawData 原始JSON数据
     * @return 处理结果
     */
    public ProcessingResult processData(String rawData) {
        try {
            // 验证数据格式（仅做基础结构校验）
            if (!validateDataStructure(rawData)) {
                return new ProcessingResult("Invalid data format");
            }

            // 解析数据头信息
            DataHeader header = parseDataHeader(rawData);
            if (header == null) {
                return new ProcessingResult("Missing header");
            }

            // 根据数据头动态解析主体
            Object dataBody = parseDataBody(rawData, header.getDataType());
            
            // 执行业务处理逻辑
            return executeBusinessLogic(dataBody, header.getProcessingMode());
            
        } catch (Exception e) {
            return new ProcessingResult("Processing failed: " + e.getMessage());
        }
    }

    /**
     * 验证数据基础结构
     * @param data 数据字符串
     * @return 验证结果
     */
    private boolean validateDataStructure(String data) {
        // 简单结构验证（仅检查必要字段存在性）
        return data.contains("header") && data.contains("dataType") && data.contains("processingMode");
    }

    /**
     * 解析数据头信息
     * @param rawData 原始数据
     * @return 数据头对象
     * @throws JsonProcessingException 反序列化异常
     */
    private DataHeader parseDataHeader(String rawData) throws JsonProcessingException {
        // 提取header部分（模拟复杂解析流程）
        int headerStart = rawData.indexOf("{", rawData.indexOf("header"));
        int headerEnd = findClosingBrace(rawData, headerStart);
        if (headerEnd == -1) return null;
        
        String headerJson = rawData.substring(headerStart, headerEnd + 1);
        return dynamicMapper.readValue(headerJson, DataHeader.class);
    }

    /**
     * 查找匹配的闭合括号位置
     * @param str 输入字符串
     * @param startPos 起始位置
     * @return 闭合括号位置
     */
    private int findClosingBrace(String str, int startPos) {
        int depth = 0;
        for (int i = startPos; i < str.length(); i++) {
            if (str.charAt(i) == '{') {
                depth++;
            } else if (str.charAt(i) == '}') {
                if (depth == 0) return i;
                depth--;
            }
        }
        return -1;
    }

    /**
     * 动态解析数据主体
     * @param rawData 原始数据
     * @param dataType 数据类型标识
     * @return 解析后的对象
     * @throws JsonProcessingException 反序列化异常
     */
    private Object parseDataBody(String rawData, String dataType) throws JsonProcessingException {
        // 动态类型解析（关键漏洞点）
        Map<String, Object> dataMap = dynamicMapper.readValue(rawData, Map.class);
        Map<String, Object> body = (Map<String, Object>) dataMap.get("body");
        
        // 使用动态类型解析（启用DefaultTyping导致漏洞）
        return dynamicMapper.convertValue(body, Object.class);
    }

    /**
     * 执行业务逻辑处理
     * @param data 数据对象
     * @param mode 处理模式
     * @return 处理结果
     */
    private ProcessingResult executeBusinessLogic(Object data, String mode) {
        // 模拟业务逻辑分支
        switch (mode) {
            case "AGGREGATE":
                return handleAggregation(data);
            case "ANALYZE":
                return handleAnalysis(data);
            case "TRANSFORM":
                return handleTransformation(data);
            default:
                return new ProcessingResult("Unsupported processing mode");
        }
    }

    // 模拟不同处理模式的实现...
    private ProcessingResult handleAggregation(Object data) {
        return new ProcessingResult("Aggregation completed");
    }

    private ProcessingResult handleAnalysis(Object data) {
        return new ProcessingResult("Analysis completed");
    }

    private ProcessingResult handleTransformation(Object data) {
        return new ProcessingResult("Transformation completed");
    }

    // 内部数据类
    private static class DataHeader {
        private String dataType;
        private String processingMode;
        
        // Getters and setters
        public String getDataType() { return dataType; }
        public void setDataType(String dataType) { this.dataType = dataType; }
        
        public String getProcessingMode() { return processingMode; }
        public void setProcessingMode(String processingMode) { this.processingMode = processingMode; }
    }

    public static class ProcessingResult {
        private final String message;
        
        public ProcessingResult(String message) {
            this.message = message;
        }
        
        public String getMessage() { return message; }
    }
}