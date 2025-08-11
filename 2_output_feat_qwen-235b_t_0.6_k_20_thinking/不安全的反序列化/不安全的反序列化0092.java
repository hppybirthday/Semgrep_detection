package com.example.mathmodelling.core;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

/**
 * 数学模型仓库服务
 * 处理模型数据的持久化与检索
 */
@Service
public class ModelDepotService {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 插入新的模型元素
     * @param classData 元素类型数据
     * @param itemData 元素内容数据
     */
    public void insertDepotItem(String classData, String itemData) {
        Class<?> itemClass = parseModelClass(classData);
        Object item = JSON.parseObject(itemData, itemClass);
        
        if (item instanceof SimulationItem) {
            ((SimulationItem) item).validate();
            redisTemplate.opsForList().leftPush("model:items", item);
        }
    }

    /**
     * 更新模型元素
     * @param classData 元素类型数据
     * @param itemData 元素内容数据
     */
    public void updateDepotItem(String classData, String itemData) {
        Class<?> itemClass = parseModelClass(classData);
        Object item = JSON.parseObject(itemData, itemClass);
        
        if (item instanceof SimulationItem) {
            ((SimulationItem) item).validate();
            redisTemplate.opsForList().rightPush("model:items", item);
        }
    }

    /**
     * 保存模型详情
     * @param rows 模型行数据
     */
    public void saveDetails(String rows) {
        List<DetailRow> detailRows = JSONArray.parseArray(rows, DetailRow.class);
        redisTemplate.opsForValue().set("model:details", detailRows);
    }

    /**
     * 解析模型类类型
     * @param classData 类描述数据
     * @return 解析后的类类型
     */
    private Class<?> parseModelClass(String classData) {
        JSONObject classObj = JSON.parseObject(classData);
        String className = classObj.getString("typeName");
        
        try {
            // 限制基础类型防止异常
            if (className.startsWith("java.lang.")) {
                return Class.forName("com.example.mathmodelling.model.DefaultItem");
            }
            return Class.forName(className);
        } catch (Exception e) {
            return DefaultItem.class;
        }
    }

    /**
     * 模型元素基类
     */
    public static abstract class SimulationItem {
        public abstract void validate();
    }

    /**
     * 默认模型元素
     */
    public static class DefaultItem extends SimulationItem {
        @Override
        public void validate() {
            // 默认校验逻辑
        }
    }

    /**
     * 模型详情行
     */
    public static class DetailRow {
        private String modelId;
        private String formula;
        
        // Getters and setters
        public String getModelId() {
            return modelId;
        }
        
        public void setModelId(String modelId) {
            this.modelId = modelId;
        }
        
        public String getFormula() {
            return formula;
        }
        
        public void setFormula(String formula) {
            this.formula = formula;
        }
    }
}