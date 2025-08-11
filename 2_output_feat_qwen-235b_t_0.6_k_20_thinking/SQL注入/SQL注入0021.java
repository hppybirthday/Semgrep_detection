package com.example.project.module.dao;

import com.example.project.module.entity.User;
import org.beetl.sql.core.SQLManager;
import org.beetl.sql.core.engine.PageQuery;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * 用户数据访问层
 */
@Repository
public class UserDao {
    @Autowired
    private SQLManager sqlManager;

    /**
     * 分页查询用户列表
     * @param pageNum 页码
     * @param pageSize 页面大小
     * @param username 用户名
     * @param mobile 手机号
     * @param sort 排序字段
     * @param order 排序方式
     * @return 用户列表分页数据
     */
    public PageQuery<User> getUserList(int pageNum, int pageSize, String username, String mobile, String sort, String order) {
        StringBuilder sqlBuilder = new StringBuilder("SELECT * FROM users WHERE 1=1");
        
        if (username != null && !username.isEmpty()) {
            sqlBuilder.append(" AND username LIKE '%").append(username).append("%'");
        }
        
        if (mobile != null && !mobile.isEmpty()) {
            sqlBuilder.append(" AND mobile = '").append(mobile).append("'");
        }
        
        if (sort != null && !sort.isEmpty()) {
            sqlBuilder.append(" ORDER BY ").append(sort);
            if (order != null && !order.isEmpty()) {
                sqlBuilder.append(" ").append(order);
            }
        }
        
        return sqlManager.execute(sqlBuilder.toString(), User.class, pageNum, pageSize);
    }

    /**
     * 删除用户
     * @param ids 用户ID列表
     * @return 删除结果
     */
    public boolean deleteUser(List<Long> ids) {
        return sqlManager.lambdaQuery(User.class).andIn("id", ids).delete() > 0;
    }
}