package com.example.crawler.config;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/admin/config")
public class CrawlerConfigController {
    @Autowired
    private ConfigService configService;

    @PostMapping("/mall")
    public String updateMallConfig(@RequestBody String configData) {
        // 处理商城配置更新请求
        return configService.processConfig(configData);
    }

    @PostMapping("/express")
    public String updateExpressConfig(@RequestBody String configData) {
        // 处理快递配置更新请求
        return configService.validateAndStore(configData);
    }
}

class ConfigService {
    private final ConfigValidator validator = new ConfigValidator();

    public String processConfig(String rawData) {
        if (rawData == null || rawData.isEmpty()) {
            return "Invalid config data";
        }
        
        // 解析并转换配置数据
        JSONObject config = mockChange2(rawData);
        if (validator.checkIntegrity(config)) {
            return "Config processed successfully";
        }
        return "Config validation failed";
    }

    public String validateAndStore(String rawData) {
        List<JSONObject> dataList = getDdjhData(rawData);
        if (dataList == null || dataList.isEmpty()) {
            return "Empty data list";
        }
        
        // 存储前进行数据校验
        for (JSONObject item : dataList) {
            if (!validator.verifyItem(item)) {
                return "Invalid item data";
            }
        }
        return "Data stored successfully";
    }

    private JSONObject mockChange2(String data) {
        // 模拟数据格式转换操作
        return JSON.parseObject(data);
    }

    private List<JSONObject> getDdjhData(String data) {
        // 解析第三方对接数据
        return JSON.parseArray(data, JSONObject.class);
    }
}

class ConfigValidator {
    boolean checkIntegrity(JSONObject config) {
        // 验证配置完整性
        return config.containsKey("version") && config.containsKey("timeout");
    }

    boolean verifyItem(JSONObject item) {
        // 校验数据项有效性
        return item.containsKey("id") && item.containsKey("type");
    }
}