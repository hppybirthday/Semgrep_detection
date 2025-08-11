package com.example.security.demo;

import org.apache.ibatis.annotations.*;
import java.util.List;

// 实体类
public class UserEntity {
    private Long id;
    private String username;
    // getters/setters...
}

// Mapper接口
@Mapper
interface UserMapper {
    @Select({"<script>",
      "SELECT * FROM users WHERE id IN",
      "<foreach item='id' collection='ids' open='(' separator=',' close=')'>",
      "#{id}",
      "</foreach>",
      "</script>"})
    List<UserEntity> selectByIds(List<Long> ids);

    // 存在漏洞的动态SQL方法
    @Select("${sql}")
    List<UserEntity> unsafeQuery(@Param("sql") String sql);
}

// 抽象处理接口
interface BatchQueryHandler<T> {
    List<T> execute(String queryParam);
}

// 具体实现类
class UserBatchQueryHandler implements BatchQueryHandler<UserEntity> {
    private final UserMapper userMapper;

    public UserBatchQueryHandler(UserMapper userMapper) {
        this.userMapper = userMapper;
    }

    @Override
    public List<UserEntity> execute(String queryParam) {
        // 漏洞点：直接拼接用户输入到SQL语句
        String sql = "SELECT * FROM users WHERE id IN (" + queryParam + ")";
        return userMapper.unsafeQuery(sql);
    }
}

// 服务层
class UserServiceImpl {
    private final UserMapper userMapper;

    public UserServiceImpl(UserMapper userMapper) {
        this.userMapper = userMapper;
    }

    public List<UserEntity> batchQuery(String ids) {
        BatchQueryHandler<UserEntity> handler = new UserBatchQueryHandler(userMapper);
        return handler.execute(ids);
    }
}

// 主程序示例
class Main {
    public static void main(String[] args) {
        // 模拟MyBatis注入
        UserMapper mapper = null; // 实际应通过MyBatis注入
        UserServiceImpl service = new UserServiceImpl(mapper);
        
        // 正常调用
        service.batchQuery("1,2,3");
        
        // 恶意调用示例
        service.batchQuery("1,2,3); DROP TABLE users;--");
    }
}