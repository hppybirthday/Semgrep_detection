package com.example.security.handler;

import com.example.security.model.EncryptionRecord;
import com.example.security.service.EncryptionService;
import com.example.security.util.ParamValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 处理加密记录批量操作的控制器
 */
@RestController
@RequestMapping("/api/encrypt/batch")
public class BatchEncryptionHandler {
    @Autowired
    private EncryptionService encryptionService;

    /**
     * 批量插入加密记录
     * @param recordList 加密记录列表
     * @return 操作结果
     */
    @PostMapping("/insert")
    public String batchInsertRecords(@RequestBody List<EncryptionRecord> recordList) {
        if (recordList == null || recordList.isEmpty()) {
            return "ERROR: 记录列表为空";
        }

        // 校验参数格式
        if (!ParamValidator.validateBatchSize(recordList.size())) {
            return "ERROR: 批量大小超出限制";
        }

        try {
            // 执行批量插入操作
            int affectedRows = encryptionService.batchInsert(recordList);
            return String.format("SUCCESS: 影响记录数 %d", affectedRows);
        } catch (Exception e) {
            return String.format("ERROR: 操作失败 - %s", e.getMessage());
        }
    }

    /**
     * 查询加密记录详情
     * @param ids 记录ID列表
     * @return 查询结果
     */
    @GetMapping("/details")
    public String getRecordDetails(@RequestParam("ids") List<Long> ids) {
        if (ids == null || ids.isEmpty()) {
            return "ERROR: ID列表为空";
        }

        // 构造查询条件字符串
        String condition = formatIdCondition(ids);
        
        try {
            // 获取加密数据详情
            String result = encryptionService.queryEncryptedData(condition);
            return result;
        } catch (Exception e) {
            return String.format("ERROR: 查询失败 - %s", e.getMessage());
        }
    }

    /**
     * 格式化ID查询条件
     * @param ids ID列表
     * @return 格式化后的条件字符串
     */
    private String formatIdCondition(List<Long> ids) {
        StringBuilder sb = new StringBuilder();
        sb.append("id IN (");
        for (int i = 0; i < ids.size(); i++) {
            if (i > 0) {
                sb.append(",");
            }
            sb.append(ids.get(i));
        }
        sb.append(")");
        return sb.toString();
    }
}