import java.util.List;
import java.util.ArrayList;
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.io.Resources;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;

// 用户实体类
class User {
    private int id;
    private String username;
    private int score;
    // 省略getter/setter
}

// 数据访问接口
interface UserMapper {
    List<User> findUsersByIds(String ids);
}

// 服务层
class UserService {
    private SqlSessionFactory sqlSessionFactory;

    public UserService() {
        try {
            sqlSessionFactory = new SqlSessionFactoryBuilder().build(
                Resources.getResourceAsStream("mybatis-config.xml"));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public List<User> batchGetUsers(String ids) {
        try (SqlSession session = sqlSessionFactory.openSession()) {
            UserMapper mapper = session.getMapper(UserMapper.class);
            // 漏洞点：直接传递未校验的字符串参数
            return mapper.findUsersByIds(ids);
        }
    }
}

// 控制器层
class UserController {
    private UserService userService = new UserService();

    public void handleRequest(String userInput) {
        // 模拟接收用户输入（如："1,2,3" 或 "1' OR '1'='1"")
        List<User> users = userService.batchGetUsers(userInput);
        users.forEach(u -> System.out.println(u.getUsername()));
    }
}

// MyBatis映射文件（resources/mapper/UserMapper.xml）
/*
<mapper namespace="UserMapper">
    <select id="findUsersByIds" resultType="User">
        SELECT * FROM users WHERE id IN (${ids})
        <!-- 漏洞点：使用${}导致SQL注入 -->
    </select>
</mapper>
*/

// MyBatis配置文件（resources/mybatis-config.xml）
/*
<configuration>
    <environments default="development">
        <environment id="development">
            <transactionManager type="JDBC"/>
            <dataSource type="POOLED">
                <property name="driver" value="com.mysql.cj.jdbc.Driver"/>
                <property name="url" value="jdbc:mysql://localhost:3306/game_db"/>
                <property name="username" value="root"/>
                <property name="password" value="password"/>
            </dataSource>
        </environment>
    </environments>
    <mappers>
        <mapper resource="mapper/UserMapper.xml"/>
    </mappers>
</configuration>
*/