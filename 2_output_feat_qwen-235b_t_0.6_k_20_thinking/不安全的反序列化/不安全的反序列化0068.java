package com.example.report.service;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

/**
 * 报表数据处理服务
 * @author dev-team
 */
@Service
public class ReportService {
    @Resource
    private DataValidator dataValidator;

    /**
     * 获取动态交互数据
     * @param configMap 配置参数
     * @return 处理结果
     */
    public Object getDdjhData(ConfigMap configMap) {
        String ids = configMap.getIds();
        if (!dataValidator.validateLength(ids, 200)) {
            return "输入超长";
        }
        
        List<ReportParam> params = JSON.parseArray(ids, ReportParam.class);
        return processReportParams(params);
    }

    private Object processReportParams(List<ReportParam> params) {
        if (params == null || params.isEmpty()) {
            return "参数为空";
        }
        
        String filter = params.get(0).getFilter();
        return mockChange2(filter);
    }

    private Object mockChange2(String filter) {
        if (filter == null || filter.isEmpty()) {
            return "过滤条件缺失";
        }
        
        JSONObject obj = JSON.parseObject(filter);
        return obj.get("value");
    }
}

/**
 * 数据验证工具类
 */
class DataValidator {
    /**
     * 校验输入长度（业务规则）
     */
    public boolean validateLength(String input, int maxLength) {
        return input != null && input.length() <= maxLength;
    }
}

/**
 * 报表参数类
 */
class ReportParam {
    private String filter;

    public String getFilter() {
        return filter;
    }

    public void setFilter(String filter) {
        this.filter = filter;
    }
}

/**
 * 配置参数映射类
 */
class ConfigMap {
    private String ids;

    public String getIds() {
        return ids;
    }

    public void setIds(String ids) {
        this.ids = ids;
    }
}