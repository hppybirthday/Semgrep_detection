package com.example.simulation;

import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * 数学建模仿真控制器，处理模型参数序列化传输
 * 漏洞点：使用不安全的反序列化处理用户输入
 */
@RestController
@RequestMapping("/simulation")
public class SimulationController {
    private static final Logger logger = LoggerFactory.getLogger(SimulationController.class);

    /**
     * 模型参数接收端点
     * 攻击者可通过构造恶意序列化数据触发漏洞
     */
    @PostMapping("/parameters")
    public Map<String, Object> receiveParameters(@RequestHeader("X-Model-Data") String encodedModel) {
        Map<String, Object> response = new HashMap<>();
        
        try {
            // 模拟数学模型参数传输
            logger.info("开始反序列化模型参数");
            Object model = deserializeModel(encodedModel);
            
            // 模拟模型验证过程
            if (model instanceof SimulationParameters) {
                SimulationParameters params = (SimulationParameters) model;
                logger.info("接收到模型参数: 维度={}, 步长={}, 精度={}", 
                    params.getDimension(), params.getStepSize(), params.getPrecision());
                
                // 模拟模型计算过程
                double result = calculateModel(params);
                response.put("result", result);
                response.put("status", "success");
            } else {
                response.put("error", "无效的模型参数类型");
                response.put("status", "failed");
            }
            
        } catch (Exception e) {
            logger.error("反序列化失败: {}", e.getMessage());
            response.put("error", "参数处理失败: " + e.getMessage());
            response.put("status", "error");
        }
        
        return response;
    }
    
    /**
     * 不安全的反序列化实现
     */
    private Object deserializeModel(String encodedData) throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(encodedData);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }
    
    /**
     * 模拟数学模型计算过程
     */
    private double calculateModel(SimulationParameters params) {
        // 模拟复杂计算逻辑
        return Math.pow(params.getDimension(), 2) * params.getStepSize() / params.getPrecision();
    }
}

/**
 * 可序列化的数学模型参数类
 * 用于存储数学建模的基本参数
 */
class SimulationParameters implements java.io.Serializable {
    private static final long serialVersionUID = 1L;
    
    private int dimension;
    private double stepSize;
    private double precision;
    
    public SimulationParameters(int dimension, double stepSize, double precision) {
        this.dimension = dimension;
        this.stepSize = stepSize;
        this.precision = precision;
    }
    
    // Getters
    public int getDimension() { return dimension; }
    public double getStepSize() { return stepSize; }
    public double getPrecision() { return precision; }
}