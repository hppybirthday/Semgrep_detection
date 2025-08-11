package com.gamestudio.transaction.controller;

import com.gamestudio.transaction.service.TransactionService;
import com.gamestudio.transaction.dto.TransactionDTO;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Tag(name = "TransactionController", description = "交易记录管理")
@RestController
@RequestMapping("/api/transaction")
public class TransactionController {
    @Autowired
    private TransactionService transactionService;

    @Operation(summary = "查询交易记录", description = "根据用户ID和物品ID查询交易记录")
    @GetMapping("/records")
    public List<TransactionDTO> getTransactionRecords(
            @RequestParam("userId") String userId,
            @RequestParam("itemId") String itemId,
            @RequestParam(value = "sort", defaultValue = "id") String sortField,
            @RequestParam(value = "order", defaultValue = "desc") String sortOrder) {
        return transactionService.getTransactionDetails(userId, itemId, sortField, sortOrder);
    }
}

package com.gamestudio.transaction.service;

import com.gamestudio.transaction.dao.TransactionDAO;
import com.gamestudio.transaction.dto.TransactionDTO;
import com.gamestudio.transaction.util.QueryValidator;
import org.apache.ibatis.session.RowBounds;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class TransactionServiceImpl implements TransactionService {
    @Autowired
    private TransactionDAO transactionDAO;

    @Override
    public List<TransactionDTO> getTransactionDetails(String userId, String itemId, String sortField, String sortOrder) {
        if (!QueryValidator.isValidId(userId) || !QueryValidator.isValidId(itemId)) {
            throw new IllegalArgumentException("Invalid ID format");
        }

        String orderByClause = buildOrderByClause(sortField, sortOrder);
        return transactionDAO.selectTransactions(userId, itemId, orderByClause);
    }

    private String buildOrderByClause(String sortField, String sortOrder) {
        if (!QueryValidator.isValidSortField(sortField) || 
            !sortOrder.equalsIgnoreCase("asc") && !sortOrder.equalsIgnoreCase("desc")) {
            return "id DESC";
        }
        return String.format("%s %s", sortField, sortOrder);
    }
}

package com.gamestudio.transaction.dao;

import com.gamestudio.transaction.dto.TransactionDTO;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.session.RowBounds;
import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class TransactionDAO {
    @Autowired
    private SqlSession sqlSession;

    public List<TransactionDTO> selectTransactions(String userId, String itemId, String orderByClause) {
        String condition = String.format("user_id = '%s' AND item_id = '%s'", userId, itemId);
        return sqlSession.selectList("TransactionMapper.selectTransactions", 
            new QueryParams(condition, orderByClause));
    }

    private static class QueryParams {
        private final String condition;
        private final String orderBy;

        public QueryParams(String condition, String orderBy) {
            this.condition = condition;
            this.orderBy = orderBy;
        }

        public String getCondition() { return condition; }
        public String getOrderBy() { return orderBy; }
    }
}

package com.gamestudio.transaction.util;

public class QueryValidator {
    public static boolean isValidId(String id) {
        return id != null && id.matches("\\\\d+");
    }

    public static boolean isValidSortField(String field) {
        return field != null && field.matches("[a-zA-Z0-9_]+");
    }
}

// MyBatis XML Mapper (TransactionMapper.xml)
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="TransactionMapper">
    <select id="selectTransactions" resultType="com.gamestudio.transaction.dto.TransactionDTO">
        SELECT * FROM transactions
        <where>
            ${condition}
        </where>
        ORDER BY ${orderBy}
    </select>
</mapper>