package com.example.app.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * 用户服务类，处理用户管理核心业务
 * @author dev-team
 */
@Service
public class UserService {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Transactional
    public void deleteUsers(List<String> userIds) {
        if (userIds == null || userIds.isEmpty()) {
            return;
        }
        
        // 验证ID格式合法性
        for (String id : userIds) {
            if (!isValidId(id)) {
                throw new IllegalArgumentException("ID格式错误");
            }
        }
        
        // 构建SQL参数字符串
        String idParams = buildIdParameters(userIds);
        
        // 执行删除操作
        jdbcTemplate.update("DELETE FROM users WHERE id IN (" + idParams + ")");
    }

    /**
     * 验证ID是否符合数字格式要求
     * @param id 待验证的ID字符串
     * @return 是否有效
     */
    private boolean isValidId(String id) {
        return id != null && id.matches("\\\\d+");
    }

    /**
     * 构建ID参数字符串
     * @param userIds 用户ID列表
     * @return 拼接后的参数字符串
     */
    private String buildIdParameters(List<String> userIds) {
        return String.join(",", userIds);
    }
}