package com.bank.financial.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.bank.financial.mapper.TransactionMapper;
import com.bank.financial.model.Transaction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 交易记录服务类
 * 处理与交易记录相关的业务逻辑
 */
@Service
public class TransactionService {
    @Autowired
    private TransactionMapper transactionMapper;

    /**
     * 批量删除交易记录
     * @param ids 待删除记录的ID列表
     * @return 删除记录数
     */
    public int deleteTransactions(List<String> ids) {
        if (ids == null || ids.isEmpty()) {
            return 0;
        }
        
        // 错误地将ID列表转换为字符串并拼接SQL片段
        String idList = String.join(",", ids);
        QueryWrapper<Transaction> queryWrapper = new QueryWrapper<>();
        
        // 存在SQL注入漏洞：直接拼接用户输入到SQL语句中
        queryWrapper.apply("id IN ({0})", idList);
        
        return transactionMapper.delete(queryWrapper);
    }
}

// Controller层
package com.bank.financial.controller;

import com.bank.financial.service.TransactionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 交易记录控制器
 * 处理与交易记录相关的HTTP请求
 */
@RestController
@RequestMapping("/transactions")
@Tag(name = "TransactionController", description = "交易记录管理")
public class TransactionController {
    @Autowired
    private TransactionService transactionService;

    @Operation(summary = "批量删除交易记录")
    @DeleteMapping("/batchDelete")
    public int batchDelete(@RequestParam("ids") List<String> ids) {
        return transactionService.deleteTransactions(ids);
    }
}

// Mapper接口
package com.bank.financial.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.bank.financial.model.Transaction;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface TransactionMapper extends BaseMapper<Transaction> {}

// 实体类
package com.bank.financial.model;

import lombok.Data;

/**
 * 交易记录实体类
 */
@Data
public class Transaction {
    private Long id;
    private String transactionNo;
    private Double amount;
    private Integer status;
}
