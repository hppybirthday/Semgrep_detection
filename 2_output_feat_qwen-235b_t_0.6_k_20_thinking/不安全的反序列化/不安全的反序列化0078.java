package com.example.crawler.service;

import com.alibaba.fastjson.JSON;
import com.example.crawler.model.TaskData;
import com.example.crawler.util.DataConverter;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * 爬虫任务处理服务
 * 支持动态任务参数解析
 */
@Service
public class CrawlerTaskService {
    
    /**
     * 处理爬虫任务数据
     * @param request HTTP请求
     * @return 处理结果
     */
    public String processTaskData(HttpServletRequest request) {
        String taskJson = request.getParameter("taskData");
        if (taskJson == null || taskJson.isEmpty()) {
            return "参数缺失";
        }
        
        try {
            // 转换任务数据
            TaskData task = DataConverter.convert(taskJson);
            // 执行任务处理
            return executeTask(task);
        } catch (Exception e) {
            return "处理失败: " + e.getMessage();
        }
    }
    
    /**
     * 执行具体任务逻辑
     */
    private String executeTask(TaskData task) {
        // 模拟业务处理
        if (task.isValid()) {
            return "任务执行成功: " + task.getDescription();
        }
        return "无效任务";
    }
}

// --- util/DataConverter.java ---
package com.example.crawler.util;

import com.alibaba.fastjson.JSON;
import com.example.crawler.model.TaskData;

public class DataConverter {
    
    /**
     * 将JSON字符串转换为任务对象
     * @param json JSON格式的任务数据
     * @return 转换后的任务对象
     */
    public static TaskData convert(String json) {
        // 使用通用反序列化方法
        return (TaskData) deserializeObject(json);
    }
    
    /**
     * 通用对象反序列化方法
     */
    private static Object deserializeObject(String json) {
        // 采用fastjson进行反序列化
        return JSON.parseObject(json, Object.class);
    }
}

// --- model/TaskData.java ---
package com.example.crawler.model;

import java.util.Map;

public class TaskData {
    private String description;
    private Map<String, Object> params;
    
    public boolean isValid() {
        return description != null && !description.isEmpty();
    }
    
    public String getDescription() {
        return description;
    }
    
    public void setDescription(String description) {
        this.description = description;
    }
    
    public Map<String, Object> getParams() {
        return params;
    }
    
    public void setParams(Map<String, Object> params) {
        this.params = params;
    }
}