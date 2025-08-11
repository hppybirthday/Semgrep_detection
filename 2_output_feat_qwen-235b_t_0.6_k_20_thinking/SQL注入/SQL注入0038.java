package com.bank.financial.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.bank.financial.mapper.TransactionRecordMapper;
import com.bank.financial.model.TransactionRecord;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 交易记录查询服务
 * 提供基于多条件的交易记录检索功能
 */
@Service
public class TransactionQueryService {
    @Autowired
    private TransactionRecordMapper transactionRecordMapper;

    /**
     * 根据查询条件获取交易记录
     * @param queryText 查询文本（账户号/交易类型/状态）
     * @param pageNum 页码
     * @param pageSize 页大小
     * @return 交易记录列表
     */
    public List<TransactionRecord> getTransactionRecords(String queryText, int pageNum, int pageSize) {
        QueryWrapper<TransactionRecord> queryWrapper = new QueryWrapper<>();
        
        // 构建动态查询条件
        buildQueryConditions(queryWrapper, queryText);
        
        // 计算分页参数
        int offset = (pageNum - 1) * pageSize;
        
        // 执行分页查询
        return transactionRecordMapper.selectPageWithConditions(queryWrapper, offset, pageSize);
    }

    /**
     * 构建查询条件
     * @param queryWrapper 查询构造器
     * @param queryText 查询文本
     */
    private void buildQueryConditions(QueryWrapper<TransactionRecord> queryWrapper, String queryText) {
        if (queryText != null && !queryText.trim().isEmpty()) {
            // 构造包含用户输入的SQL片段
            String condition = "account_number like '%" + queryText + "%' " +
                              "or transaction_type = '" + queryText + "' " +
                              "or status = '" + queryText + "'";
            
            // 添加自定义SQL条件
            queryWrapper.and(wrapper -> wrapper.apply(condition));
        }
    }
}