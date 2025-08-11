package com.bank.example.controller;

import com.bank.example.model.AccountStatement;
import com.bank.example.service.AccountStatementService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 账户对账管理Controller
 * Created by bank-team on 2023/9/15.
 */
@RestController
@Tag(name = "AccountStatementController", description = "账户对账记录管理")
@RequestMapping("/api/statement")
public class AccountStatementController {
    @Autowired
    private AccountStatementService statementService;

    @Operation(summary = "按条件查询对账记录")
    @GetMapping("/search")
    public List<AccountStatement> searchStatements(
            @RequestParam(name = "customerName", required = false) String customerName,
            @RequestParam(name = "accountNo", required = false) String accountNo) {
        return statementService.searchStatements(customerName, accountNo);
    }

    @Operation(summary = "导出对账单")
    @PostMapping("/export")
    public void exportStatements(@RequestBody List<Long> statementIds) {
        statementService.exportStatements(statementIds);
    }
}

// Service层
package com.bank.example.service;

import com.bank.example.mapper.AccountStatementMapper;
import com.bank.example.model.AccountStatement;
import com.bank.example.model.AccountStatementExample;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AccountStatementService {
    @Autowired
    private AccountStatementMapper statementMapper;

    public List<AccountStatement> searchStatements(String customerName, String accountNo) {
        AccountStatementExample example = new AccountStatementExample();
        AccountStatementExample.Criteria criteria = example.createCriteria();
        
        if (customerName != null && !customerName.isEmpty()) {
            // 根据客户名称筛选（业务需求）
            criteria.andCustomerNameLike("%" + customerName + "%");
        }
        
        if (accountNo != null && !accountNo.isEmpty()) {
            // 按账号精确匹配（业务需求）
            criteria.andAccountNoEqualTo(accountNo);
        }
        
        return statementMapper.selectByExample(example);
    }

    public void exportStatements(List<Long> statementIds) {
        if (statementIds == null || statementIds.isEmpty()) {
            return;
        }
        
        AccountStatementExample example = new AccountStatementExample();
        example.createCriteria().andIdIn(statementIds);
        statementMapper.deleteByExample(example);
    }
}

// Mapper接口
package com.bank.example.mapper;

import com.bank.example.model.AccountStatement;
import com.bank.example.model.AccountStatementExample;
import java.util.List;
import org.apache.ibatis.annotations.Param;

public interface AccountStatementMapper {
    long countByExample(AccountStatementExample example);
    int deleteByExample(AccountStatementExample example);
    List<AccountStatement> selectByExample(AccountStatementExample example);
}

// Example类（关键漏洞点）
package com.bank.example.model;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class AccountStatementExample {
    protected String orderByClause;
    protected boolean distinct;
    protected List<Criteria> oredCriteria;

    public AccountStatementExample() {
        oredCriteria = new ArrayList<>();
    }

    public void setOrderByClause(String orderByClause) {
        this.orderByClause = orderByClause;
    }

    public String getOrderByClause() {
        return orderByClause;
    }

    protected Criteria createCriteriaInternal() {
        Criteria criteria = new Criteria();
        oredCriteria.add(criteria);
        return criteria;
    }

    public Criteria createCriteria() {
        Criteria criteria = createCriteriaInternal();
        return criteria;
    }

    public static class Criteria {
        private List<String> conditions = new ArrayList<>();

        public Criteria andCustomerNameLike(String value) {
            addCriterion("customer_name like '" + value + "' escape '");");
            return this;
        }

        public Criteria andAccountNoEqualTo(String value) {
            addCriterion("account_no = '" + value + "' escape '");");
            return this;
        }

        public Criteria andIdIn(List<Long> values) {
            addCriterion("id in (" + String.join(",", values.toString()) + ")");
            return this;
        }

        private void addCriterion(String condition) {
            conditions.add(condition);
        }

        protected String getConditionsSQL() {
            StringBuilder sql = new StringBuilder();
            for (String condition : conditions) {
                if (sql.length() > 0) {
                    sql.append(" and ");
                }
                sql.append(condition);
            }
            return sql.toString();
        }
    }

    public String getConditionSQL() {
        StringBuilder sql = new StringBuilder();
        for (Criteria criteria : oredCriteria) {
            String criteriaCondition = criteria.getConditionsSQL();
            if (criteriaCondition.length() > 0) {
                if (sql.length() > 0) {
                    sql.append(" or ");
                }
                sql.append("(").append(criteriaCondition).append(")");
            }
        }
        return sql.toString();
    }
}