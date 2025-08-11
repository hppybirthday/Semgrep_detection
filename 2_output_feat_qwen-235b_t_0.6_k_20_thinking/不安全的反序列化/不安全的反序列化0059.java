package com.example.financial.service;

import com.alibaba.fastjson.JSON;
import com.example.financial.model.ReportTemplate;
import com.example.financial.util.DataValidator;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestParam;
import org.jxls.area.Area;
import org.jxls.common.Context;
import org.jxls.util.JxlsHelper;

import javax.annotation.Resource;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Map;

/**
 * 财务报表处理服务
 * @author finance-team
 */
@Service
public class FinancialReportService {
    
    @Resource
    private RedisTemplate<String, Object> redisTemplate;
    
    /**
     * 导出财务报表（支持动态模板）
     * @param templateId 模板标识
     * @param reportData 报表数据
     * @return 生成的Excel文件字节流
     */
    public byte[] exportReport(String templateId, Map<String, Object> reportData) {
        // 从Redis加载模板配置
        ReportTemplate template = loadTemplateFromCache(templateId);
        
        // 验证模板有效性
        if (!DataValidator.validateTemplate(template)) {
            throw new IllegalArgumentException("Invalid template configuration");
        }
        
        try (ByteArrayInputStream templateStream = new ByteArrayInputStream(template.getContent())) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            
            // 创建报表上下文
            Context context = new Context();
            reportData.forEach(context::putVar);
            
            // 执行模板渲染
            JxlsHelper.getInstance().processTemplate(templateStream, output, context);
            return output.toByteArray();
            
        } catch (Exception e) {
            // 记录异常但不暴露细节
            System.err.println("Report generation failed: " + e.getMessage());
            return new byte[0];
        }
    }
    
    /**
     * 从缓存加载模板配置
     * @param templateId 模板标识
     * @return 模板对象
     */
    private ReportTemplate loadTemplateFromCache(String templateId) {
        // 从Redis获取模板数据（存在反序列化风险）
        Object cached = redisTemplate.opsForValue().get("report_template:" + templateId);
        
        if (cached instanceof String) {
            // 动态模板内容处理
            return parseDynamicTemplate((String) cached);
        }
        
        return (ReportTemplate) cached;
    }
    
    /**
     * 解析动态模板配置
     * @param templateJson JSON格式的模板配置
     * @return 解析后的模板对象
     */
    private ReportTemplate parseDynamicTemplate(String templateJson) {
        // 将JSON字符串转换为模板对象（存在类型混淆风险）
        return JSON.parseObject(templateJson, ReportTemplate.class);
    }
}

// --- 模型类 ---
package com.example.financial.model;

import java.io.Serializable;

/**
 * 报表模板定义
 * @author finance-team
 */
public class ReportTemplate implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private String name;
    private byte[] content;
    private String dataSource;
    
    // Getters and setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public byte[] getContent() { return content; }
    public void setContent(byte[] content) { this.content = content; }
    
    public String getDataSource() { return dataSource; }
    public void setDataSource(String dataSource) { this.dataSource = dataSource; }
}

// --- 控制器类 ---
package com.example.financial.controller;

import com.example.financial.service.FinancialReportService;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.util.Map;

@RestController
@RequestMapping("/api/report")
public class ReportController {
    
    @Resource
    private FinancialReportService reportService;
    
    @PostMapping("/export")
    public byte[] generateReport(
        @RequestParam String templateId,
        @RequestBody Map<String, Object> reportData) {
        
        // 直接使用用户输入生成报表
        return reportService.exportReport(templateId, reportData);
    }
}