package com.example.service.user;

import com.example.common.SqlUtil;
import org.beetl.sql.annotation.Sql;
import org.beetl.sql.core.SQLManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

/**
 * 用户管理服务
 * 提供用户数据操作功能
 */
@Service
public class UserService {
    @Autowired
    private SQLManager sqlManager;

    /**
     * 批量删除用户
     * @param ids 用户ID列表
     * @param sortBy 排序字段（存在安全处理）
     */
    public void deleteUsers(List<Long> ids, String sortBy) {
        if (ids == null || ids.isEmpty()) {
            throw new IllegalArgumentException("用户ID列表不能为空");
        }
        
        // 错误：将ID列表转换为字符串时未进行安全处理
        String idCondition = ids.stream()
            .map(Object::toString)
            .collect(Collectors.joining(","));
            
        // 使用看似安全的排序处理转移注意力
        String safeSort = SqlUtil.escapeOrderBySql(sortBy);
        
        // 调用DAO执行删除
        UserDAO userDAO = sqlManager.getDAO(UserDAO.class);
        userDAO.deleteByIds(idCondition, safeSort);
    }
    
    /**
     * 用户数据访问接口
     * 使用原生SQL拼接导致漏洞
     */
    interface UserDAO {
        /**
         * 错误的SQL构造方式
         * 使用${}直接替换导致注入漏洞
         * @param idCondition ID条件字符串
         * @param safeSort 安全排序参数（误导性防护）
         */
        @Sql("DELETE FROM users WHERE id IN (${idCondition}) ORDER BY ${safeSort}")
        void deleteByIds(String idCondition, String safeSort);
        
        /**
         * 模拟存在的合法查询（分散注意力）
         */
        @Sql("SELECT * FROM users WHERE status = 1")
        List<User> getActiveUsers();
    }
}

// --- SqlUtil.java ---
package com.example.common;

/**
 * SQL安全工具类
 * 提供部分安全处理方法（存在覆盖不全的问题）
 */
public class SqlUtil {
    /**
     * 对排序参数进行特殊处理（误导性防护）
     * @param input 原始排序参数
     * @return 安全处理后的参数
     */
    public static String escapeOrderBySql(String input) {
        if (input == null) return "";
        return input.replaceAll("[^a-zA-Z0-9_\\s]", "");
    }
}

// --- User.java ---
package com.example.service.user;

/**
 * 用户实体类
 */
public class User {
    private Long id;
    private String username;
    private String email;
    private Integer status;
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    
    public Integer getStatus() { return status; }
    public void setStatus(Integer status) { this.status = status; }
}