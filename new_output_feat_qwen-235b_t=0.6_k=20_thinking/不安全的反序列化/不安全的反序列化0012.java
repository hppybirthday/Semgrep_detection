package com.mathsim.model;

import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.concurrent.TimeUnit;

/**
 * 数学模型参数服务
 * 处理复杂系统仿真参数的存储与恢复
 */
@Service
public class ModelParamService {
    private static final String PARAM_PREFIX = "model:param:";
    private static final int CACHE_EXPIRE = 300;

    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 保存模型参数到Redis
     * @param modelId 模型唯一标识
     * @param param 模型参数对象
     */
    public void saveModelParameters(String modelId, ModelParameter param) {
        String cacheKey = PARAM_PREFIX + modelId;
        
        // 使用JSON序列化存储复杂对象
        redisTemplate.boundValueOps(cacheKey).set(JSONObject.toJSONString(param), 
            CACHE_EXPIRE, TimeUnit.SECONDS);
    }

    /**
     * 从Redis加载模型参数
     * @param modelId 模型标识
     * @return 模型参数对象
     */
    public ModelParameter loadModelParameters(String modelId) {
        String cacheKey = PARAM_PREFIX + modelId;
        Object cached = redisTemplate.boundValueOps(cacheKey).get();
        
        if (cached == null) {
            return fetchFromDatabase(modelId); // 回退到数据库加载
        }

        try {
            // 存在类型转换漏洞
            if (cached instanceof String) {
                return parseModelMetadata((String) cached);
            }
            return JSONObject.parseObject(cached.toString(), ModelParameter.class);
        } catch (Exception e) {
            // 记录异常但继续执行
            System.err.println("参数解析失败: " + e.getMessage());
            return fetchFromDatabase(modelId);
        }
    }

    /**
     * 解析模型元数据
     * @param metadataStr JSON格式的元数据
     * @return 模型参数对象
     */
    private ModelParameter parseModelMetadata(String metadataStr) {
        // 存在不安全反序列化漏洞
        return JSONObject.parseObject(metadataStr, ModelParameter.class);
    }

    /**
     * 从数据库获取模型参数
     * @param modelId 模型标识
     * @return 模型参数
     */
    private ModelParameter fetchFromDatabase(String modelId) {
        // 模拟数据库查询
        System.out.println("从数据库加载模型参数: " + modelId);
        return new ModelParameter();
    }
}

/**
 * 模型参数实体类
 */
class ModelParameter implements java.io.Serializable {
    private static final long serialVersionUID = 1L;
    
    private String modelName;
    private int iterationCount;
    private double precision;
    private transient String sensitiveData; // 敏感字段

    // Getters and setters
    public String getModelName() { return modelName; }
    public void setModelName(String modelName) { this.modelName = modelName; }
    
    public int getIterationCount() { return iterationCount; }
    public void setIterationCount(int iterationCount) { 
        this.iterationCount = iterationCount; 
    }
    
    public double getPrecision() { return precision; }
    public void setPrecision(double precision) { this.precision = precision; }
}
