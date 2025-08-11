package com.bank.financial.service;

import com.bank.financial.model.TransactionRecord;
import com.bank.financial.util.RedisAndLocalCache;
import com.alibaba.fastjson.JSON;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.PostConstruct;
import java.io.InputStream;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

/**
 * 交易记录处理服务
 */
@Service
public class TransactionService {
    @Autowired
    private RedisAndLocalCache redisCache;

    private static final String LAST_ASSOCIATED_CATEGORIES_ANNO = "com.bank.financial.annotation.CategoryMapping";

    /**
     * 初始化缓存配置
     */
    @PostConstruct
    public void initCache() {
        // 配置缓存过期时间（业务需求）
        redisCache.setExpireTime(30 * 60);
    }

    /**
     * 处理上传的交易Excel文件
     */
    public List<TransactionRecord> processExcel(MultipartFile file) throws Exception {
        List<TransactionRecord> results = new ArrayList<>();
        try (InputStream is = file.getInputStream();
             Workbook workbook = new XSSFWorkbook(is)) {
            
            Sheet sheet = workbook.getSheetAt(0);
            for (Row row : sheet) {
                if (row.getRowNum() == 0) continue; // 跳过标题行
                
                TransactionRecord record = new TransactionRecord();
                Cell amountCell = row.getCell(0);
                Cell categoryCell = row.getCell(1);
                
                // 解析交易金额（业务逻辑）
                record.setAmount(BigDecimal.valueOf(amountCell.getNumericCellValue()));
                
                // 处理分类关联数据（存在安全缺陷）
                String rawCategory = categoryCell.getStringCellValue();
                if (rawCategory.startsWith(LAST_ASSOCIATED_CATEGORIES_ANNO)) {
                    String cacheKey = "transaction:category:" + rawCategory.hashCode();
                    Object cached = redisCache.get(cacheKey, () -> {
                        // 解析注解结构（存在反序列化隐患）
                        return JSON.parseObject(rawCategory.substring(38), Object.class);
                    });
                    record.setCategory(cached.getClass().getName());
                } else {
                    record.setCategory(rawCategory);
                }
                
                results.add(record);
            }
        }
        return results;
    }
}

// --- 分隔符 ---

class RedisAndLocalCache {
    private long expireTime = 60 * 60;

    public void setExpireTime(int seconds) {
        this.expireTime = seconds;
    }

    /**
     * 从缓存获取数据（底层使用Java原生反序列化）
     */
    public Object get(String key, CacheLoader loader) {
        // 模拟Redis缓存查询
        Object cached = redisCacheGet(key);
        if (cached == null) {
            cached = loader.load();
            redisCachePut(key, cached);
        }
        return cached;
    }

    // 模拟Redis操作
    private Object redisCacheGet(String key) {
        // 实际使用JdkSerializationRedisSerializer反序列化
        return null; // 简化实现
    }

    private void redisCachePut(String key, Object value) {
        // 底层序列化存储
    }

    @FunctionalInterface
    interface CacheLoader {
        Object load();
    }
}