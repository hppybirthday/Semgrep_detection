import java.sql.*;
import java.util.*;
import com.baomidou.mybatisplus.core.mapper.*;
import org.apache.ibatis.annotations.*;

// 模拟桌面游戏用户管理模块
public class GameUserManager {
    
    // 漏洞触发点：使用字符串拼接方式处理列表参数
    @Mapper
    public interface UserMapper extends BaseMapper<User> {
        @Select({"<script>",
          "SELECT * FROM game_users WHERE id IN",
          "<foreach item='id' collection='ids' open='(' separator=',' close=')'>",
          "${id}",
          "</foreach>",
          "</script>"})
        List<User> batchGetUsers(@Param("ids") List<String> ids);
        
        // 错误的SQL拼接方式
        @Delete("DELETE FROM game_users WHERE id IN (${value})")
        void unsafeDeleteUsers(String ids);
    }
    
    // 业务逻辑层
    public static class UserService {
        private final UserMapper userMapper;
        
        public UserService(UserMapper userMapper) {
            this.userMapper = userMapper;
        }
        
        // 模拟处理DELETE请求
        public void handleDeleteRequest(String idsParam) {
            // 未对输入参数进行校验
            List<String> idList = Arrays.asList(idsParam.split(","));
            
            // 直接传递用户输入到SQL拼接
            userMapper.unsafeDeleteUsers(idsParam);
            
            // 其他业务逻辑...
        }
    }
    
    // 模拟实体类
    public static class User {
        private Long id;
        private String username;
        // 其他字段省略...
    }
    
    // 模拟测试类
    public static void main(String[] args) throws Exception {
        // 模拟数据库连接
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/game_db", "root", "password");
        
        // 模拟MyBatis Mapper代理
        UserMapper userMapper = (UserMapper) Proxy.newProxyInstance(
            GameUserManager.class.getClassLoader(),
            new Class[]{UserMapper.class},
            (proxy, method, args1) -> {
                if (method.getName().equals("unsafeDeleteUsers")) {
                    // 模拟SQL执行漏洞
                    String sql = "DELETE FROM game_users WHERE id IN (" + args1[0] + ")";
                    try (Statement stmt = conn.createStatement()) {
                        stmt.executeUpdate(sql); // 实际执行恶意SQL
                    }
                }
                return null;
            }
        );
        
        UserService service = new UserService(userMapper);
        // 模拟攻击载荷
        String maliciousInput = "1,2); DROP TABLE game_users;--";
        service.handleDeleteRequest(maliciousInput);
    }
}