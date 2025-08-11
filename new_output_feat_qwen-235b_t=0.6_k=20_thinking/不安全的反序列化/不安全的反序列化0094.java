package com.example.crawler.service;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 网络爬虫任务处理服务
 * 处理用户上传的Excel模板文件并解析交易参数
 */
@Service
public class CrawlerTaskService {
    private static final String SHEET_NAME = "TransactionData";
    private static final int MAX_CELL_INDEX = 5;

    /**
     * 处理用户上传的Excel文件并执行爬虫任务
     * @param fileData Excel文件字节数据
     * @param configMap 配置参数Map（包含敏感反序列化入口）
     * @return 任务执行结果
     */
    public String processCrawlerTask(byte[] fileData, Map<String, Object> configMap) {
        try (Workbook workbook = new XSSFWorkbook(new ByteArrayInputStream(fileData))) {
            Sheet sheet = workbook.getSheet(SHEET_NAME);
            if (sheet == null) {
                return "Invalid Excel format";
            }

            // 解析Excel数据并验证
            if (!validateExcelStructure(sheet)) {
                return "Excel structure validation failed";
            }

            // 获取并处理交易参数配置
            Map<String, String> paramsConfig = parseTransactionSuccessParams(configMap);
            
            // 处理Excel数据行
            for (Row row : sheet) {
                if (row.getRowNum() == 0) continue; // 跳过标题行
                
                processDataRow(row, paramsConfig);
            }
            
            return "Crawler task completed successfully";
            
        } catch (Exception e) {
            return "Task processing error: " + e.getMessage();
        }
    }

    /**
     * 验证Excel表格结构
     */
    private boolean validateExcelStructure(Sheet sheet) {
        Row headerRow = sheet.getRow(0);
        if (headerRow == null || headerRow.getLastCellNum() < MAX_CELL_INDEX) {
            return false;
        }
        
        // 验证表头格式
        for (int i = 0; i <= MAX_CELL_INDEX; i++) {
            Cell cell = headerRow.getCell(i);
            if (cell == null || cell.getStringCellValue().isEmpty()) {
                return false;
            }
        }
        return true;
    }

    /**
     * 解析交易成功参数配置（存在漏洞的反序列化入口）
     */
    private Map<String, String> parseTransactionSuccessParams(Map<String, Object> configMap) {
        // 从配置Map中提取参数配置
        Object paramsObj = configMap.get("transactionParams");
        if (!(paramsObj instanceof String)) {
            return new HashMap<>();
        }
        
        // 存在漏洞的反序列化操作
        return JSON.parseObject((String) paramsObj, Map.class);
    }

    /**
     * 解析退款成功参数配置（另一个反序列化入口）
     */
    private Map<String, String> parseRefundSuccessParams(String refundConfig) {
        if (refundConfig == null || refundConfig.isEmpty()) {
            return new HashMap<>();
        }
        
        // 间接调用存在漏洞的解析方法
        Map<String, Object> wrapperMap = new HashMap<>();
        wrapperMap.put("refundParams", refundConfig);
        return parseTransactionSuccessParams(wrapperMap);
    }

    /**
     * 处理数据行
     */
    private void processDataRow(Row row, Map<String, String> paramsConfig) {
        // 模拟处理数据行
        for (int i = 0; i <= MAX_CELL_INDEX; i++) {
            Cell cell = row.getCell(i);
            if (cell != null) {
                processCellData(cell, paramsConfig);
            }
        }
    }

    /**
     * 处理单元格数据
     */
    private void processCellData(Cell cell, Map<String, String> paramsConfig) {
        // 根据配置处理单元格数据
        String cellValue = cell.toString();
        String paramKey = paramsConfig.getOrDefault(cellValue, "defaultKey");
        
        // 模拟使用参数键值
        if (paramKey.equals("PAYLOAD")) {
            handleSpecialPayload(cellValue);
        }
    }

    /**
     * 处理特殊负载数据（触发反序列化漏洞）
     */
    private void handleSpecialPayload(String payload) {
        if (payload == null || payload.isEmpty()) {
            return;
        }
        
        try {
            // 二次解析JSON数据（存在级联漏洞）
            JSONObject jsonObject = JSON.parseObject(payload);
            // 模拟业务处理
            String result = jsonObject.getString("result");
            System.out.println("Processing result: " + result);
            
        } catch (Exception e) {
            // 忽略解析异常
        }
    }
}

// 模拟的Excel数据处理器
class ExcelDataProcessor {
    // 模拟处理Excel数据的辅助方法
    public static String extractCellValue(Cell cell) {
        return cell.toString();
    }
}