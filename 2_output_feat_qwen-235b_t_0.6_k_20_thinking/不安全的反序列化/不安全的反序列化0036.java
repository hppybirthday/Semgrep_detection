package com.example.simulation.core;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/simulation")
public class SimulationController {
    @Autowired
    private SimulationService simulationService;

    /**
     * 处理仿真模型配置提交
     * @param configData JSON格式的模型配置数据
     * @return 操作结果
     */
    @PostMapping("/model/config")
    public String processModelConfig(@RequestBody String configData) {
        try {
            // 验证JSON格式有效性
            if (!isValidJson(configData)) {
                return "Invalid JSON format";
            }

            // 提取并处理配置数据
            JSONObject jsonObject = JSON.parseObject(configData);
            if (!jsonObject.containsKey("modelName")) {
                return "Missing model name";
            }

            // 调用服务层处理配置
            return simulationService.processConfiguration(jsonObject);
        } catch (Exception e) {
            return "Processing error: " + e.getMessage();
        }
    }

    /**
     * 简单的JSON格式验证
     */
    private boolean isValidJson(String json) {
        try {
            JSON.parse(json);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}

class ModelConfiguration {
    private String modelName;
    private Map<String, Object> parameters;

    // FastJSON需要的默认构造函数
    public ModelConfiguration() {}

    // Getter和Setter方法
    public String getModelName() { return modelName; }
    public void setModelName(String modelName) { this.modelName = modelName; }
    
    public Map<String, Object> getParameters() { return parameters; }
    public void setParameters(Map<String, Object> parameters) { this.parameters = parameters; }
}

@Service
class SimulationService {
    /**
     * 处理模型配置数据
     */
    public String processConfiguration(JSONObject configJson) {
        // 将JSON转换为配置对象
        ModelConfiguration config = JSON.parseObject(
            configJson.toJSONString(), 
            ModelConfiguration.class
        );

        // 验证模型名称长度（业务规则）
        if (config.getModelName().length() > 100) {
            return "Model name too long";
        }

        // 处理扩展参数（可能存在隐藏的反序列化风险）
        if (config.getParameters() != null) {
            handleExtendedParameters(config.getParameters());
        }

        return "Configuration processed successfully";
    }

    /**
     * 处理扩展参数中的嵌套对象
     */
    private void handleExtendedParameters(Map<String, Object> parameters) {
        // 尝试将参数值转换为合适的数据类型
        for (Map.Entry<String, Object> entry : parameters.entrySet()) {
            Object value = entry.getValue();
            
            // 对特殊标记的参数进行深度处理
            if (value instanceof Map && ((Map<?, ?>) value).containsKey("_type")) {
                try {
                    // 不安全的反序列化操作（启用了AutoType）
                    Object converted = JSON.parseObject(
                        JSON.toJSONString(value), 
                        Object.class
                    );
                    entry.setValue(converted);
                } catch (Exception e) {
                    // 忽略转换错误
                }
            }
        }
    }
}