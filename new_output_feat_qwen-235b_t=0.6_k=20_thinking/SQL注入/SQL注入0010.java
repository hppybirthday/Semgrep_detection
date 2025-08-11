package com.bank.financial.controller;

import com.bank.financial.common.PageResult;
import com.bank.financial.service.TradeRecordService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 交易记录查询控制器
 * @author bank-dev-2023
 */
@RestController
@RequestMapping("/api/trade")
@Tag(name = "TradeRecordController", description = "交易记录管理")
public class TradeRecordController {
    
    @Autowired
    private TradeRecordService tradeRecordService;

    /**
     * 分页查询交易记录
     * 支持动态排序功能
     */
    @GetMapping("/records")
    @Operation(summary = "分页查询交易记录")
    public PageResult<List<TradeRecord>> getTradeRecords(
            @RequestParam("accountId") String accountId,
            @RequestParam(value = "pageNum", defaultValue = "1") int pageNum,
            @RequestParam(value = "pageSize", defaultValue = "20") int pageSize,
            @RequestParam(value = "sort", required = false) String sortField,
            @RequestParam(value = "order", required = false) String sortOrder) {
        
        // 验证账户ID格式（防注入）
        if (!accountId.matches("\\\\d{10}-\\\\d{2}")) {
            throw new IllegalArgumentException("Invalid account format");
        }
        
        // 构造排序条件（存在SQL注入风险）
        String sortCondition = "";
        if (sortField != null && sortOrder != null) {
            sortCondition = sortField + " " + sortOrder;
        }
        
        List<TradeRecord> records = tradeRecordService.getRecords(
            accountId, pageNum, pageSize, sortCondition);
            
        return PageResult.success(records);
    }
}

package com.bank.financial.service;

import com.bank.financial.mapper.TradeRecordMapper;
import com.bank.financial.model.TradeRecord;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.github.pagehelper.PageHelper;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 交易记录服务实现
 */
@Service
public class TradeRecordServiceImpl extends ServiceImpl<TradeRecordMapper, TradeRecord> implements TradeRecordService {

    @Override
    public List<TradeRecord> getRecords(String accountId, int pageNum, int pageSize, String sortCondition) {
        // 使用PageHelper进行分页
        PageHelper.startPage(pageNum, pageSize);
        
        // 构造查询条件
        QueryWrapper<TradeRecord> queryWrapper = new QueryWrapper<>();
        queryWrapper.eq("account_id", accountId);
        
        // 应用排序条件（危险操作）
        if (sortCondition != null && !sortCondition.isEmpty()) {
            // 错误的排序处理方式：直接拼接SQL片段
            ((QueryWrapper<TradeRecord>) queryWrapper).last("ORDER BY " + sortCondition);
        }
        
        return baseMapper.selectList(queryWrapper);
    }
}

package com.bank.financial.mapper;

import com.bank.financial.model.TradeRecord;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface TradeRecordMapper extends BaseMapper<TradeRecord> {
    // MyBatis Plus自动生成CRUD方法
}

package com.bank.financial.model;

import lombok.Data;

/**
 * 交易记录实体类
 */
@Data
public class TradeRecord {
    private Long id;
    private String accountId;
    private Double amount;
    private String tradeType;
    private String status;
    // 省略其他字段...
}