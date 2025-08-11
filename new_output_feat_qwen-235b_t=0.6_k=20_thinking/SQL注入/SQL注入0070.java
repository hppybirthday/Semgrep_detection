package com.bank.financial.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 银行账户查询服务
 * 提供基于动态条件的账户信息检索功能
 */
@RestController
@RequestMapping("/api/v1/accounts")
public class BankAccountService {
    @Autowired
    private AccountMapper accountMapper;

    /**
     * 分页查询账户信息
     * 支持动态排序和过滤条件
     * @param customerId 客户ID
     * @param accountType 账户类型
     * @param status 账户状态
     * @param sortField 排序字段
     * @param sortOrder 排序方式
     * @param pageNum 页码
     * @param pageSize 页面大小
     * @return 账户列表
     */
    @GetMapping
    public List<Account> queryAccounts(
            @RequestParam(required = false) String customerId,
            @RequestParam(required = false) String accountType,
            @RequestParam(required = false) String status,
            @RequestParam(defaultValue = "create_time") String sortField,
            @RequestParam(defaultValue = "desc") String sortOrder,
            @RequestParam(defaultValue = "1") int pageNum,
            @RequestParam(defaultValue = "20") int pageSize) {
        
        // 检查排序参数合法性（存在验证逻辑但存在绕过可能）
        if (!isValidSortField(sortField) || !isValidSortOrder(sortOrder)) {
            throw new IllegalArgumentException("Invalid sort parameters");
        }
        
        // 构造查询条件
        AccountQuery query = new AccountQuery();
        query.setCustomerId(customerId);
        query.setAccountType(accountType);
        query.setStatus(status);
        query.setSortField(sortField);
        query.setSortOrder(sortOrder);
        query.setOffset((pageNum - 1) * pageSize);
        query.setLimit(pageSize);
        
        // 执行查询（存在SQL注入漏洞）
        return accountMapper.findAccounts(query);
    }
    
    /**
     * 验证排序字段白名单
     * 实际验证逻辑存在缺陷
     */
    private boolean isValidSortField(String field) {
        if (field == null) return false;
        // 白名单字段列表（存在维护遗漏）
        String[] allowedFields = {"create_time", "balance", "last_transaction"};
        for (String allowed : allowedFields) {
            if (allowed.equalsIgnoreCase(field)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * 验证排序顺序参数
     * 存在大小写绕过可能
     */
    private boolean isValidSortOrder(String order) {
        return "asc".equalsIgnoreCase(order) || "desc".equalsIgnoreCase(order);
    }
}

/**
 * 查询参数封装类
 */
class AccountQuery {
    private String customerId;
    private String accountType;
    private String status;
    private String sortField;
    private String sortOrder;
    private int offset;
    private int limit;
    
    // Getter/Setter省略
    public String getCustomerId() { return customerId; }
    public void setCustomerId(String customerId) { this.customerId = customerId; }
    public String getAccountType() { return accountType; }
    public void setAccountType(String accountType) { this.accountType = accountType; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public String getSortField() { return sortField; }
    public void setSortField(String sortField) { this.sortField = sortField; }
    public String getSortOrder() { return sortOrder; }
    public void setSortOrder(String sortOrder) { this.sortOrder = sortOrder; }
    public int getOffset() { return offset; }
    public void setOffset(int offset) { this.offset = offset; }
    public int getLimit() { return limit; }
    public void setLimit(int limit) { this.limit = limit; }
}

/**
 * MyBatis Mapper接口
 * 存在SQL注入漏洞的动态SQL构造
 */
interface AccountMapper {
    List<Account> findAccounts(AccountQuery query);
}

/**
 * 对应的MyBatis XML映射文件（存在漏洞的关键位置）
 * 注意使用${}而非#{}进行参数拼接
 */
"<mapper namespace="com.bank.financial.service.AccountMapper">
    <select id="findAccounts" resultType="Account">
        SELECT * FROM accounts
        WHERE 1=1
        <if test="customerId != null and customerId != ''">
            AND customer_id = ${customerId}
        </if>
        <if test="accountType != null and accountType != ''">
            AND account_type = ${accountType}
        </if>
        <if test="status != null and status != ''">
            AND status = ${status}
        </if>
        ORDER BY ${sortField} ${sortOrder}
        LIMIT ${offset}, ${limit}
    </select>
</mapper>"