package com.example.mathsim;

import java.lang.reflect.Field;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

/**
 * 数学模型参数服务类
 */
public class ModelParameterService {
    private Connection connection;

    public ModelParameterService() {
        try {
            connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mathsim_db", "user", "password");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    /**
     * 通过反射动态查询模型参数
     * @param paramName 参数名称
     * @param paramValue 参数值
     * @return 参数对象列表
     * @throws Exception
     */
    public List<ModelParameter> queryParameters(String paramName, String paramValue) throws Exception {
        List<ModelParameter> result = new ArrayList<>();
        
        // 漏洞点：直接拼接SQL语句
        String query = "SELECT * FROM model_parameters WHERE " + paramName + " = '" + paramValue + "'";
        
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            while (rs.next()) {
                ModelParameter param = new ModelParameter();
                Field[] fields = param.getClass().getDeclaredFields();
                
                for (Field field : fields) {
                    field.setAccessible(true);
                    // 元编程方式设置字段值
                    field.set(param, rs.getObject(field.getName()));
                }
                
                result.add(param);
            }
        }
        return result;
    }

    /**
     * 动态更新模型参数
     * @param paramName 参数名称
     * @param oldValue 旧值
     * @param newValue 新值
     * @throws Exception
     */
    public void updateParameter(String paramName, String oldValue, String newValue) throws Exception {
        // 漏洞点：拼接更新语句
        String update = "UPDATE model_parameters SET " + paramName + " = '" + newValue + "' " +
                      "WHERE " + paramName + " = '" + oldValue + "'";
        
        try (Statement stmt = connection.createStatement()) {
            stmt.executeUpdate(update);
        }
    }

    public static void main(String[] args) {
        ModelParameterService service = new ModelParameterService();
        try {
            // 示例调用
            System.out.println("查询参数:");
            service.queryParameters("threshold", "0.75").forEach(System.out::println);
            
            // 模拟SQL注入攻击
            System.out.println("\
执行SQL注入攻击测试:");
            service.queryParameters("id", "1' OR '1'='1");
            
            // 更新参数示例
            System.out.println("\
更新参数测试:");
            service.updateParameter("convergence_rate", "0.01", "0.05");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

/**
 * 数学模型参数实体类
 */
class ModelParameter {
    private String name;
    private String value;
    private String description;
    private String category;
    private Timestamp lastUpdated;

    // Getters and setters omitted for brevity

    @Override
    public String toString() {
        return "ModelParameter{" +
                "name='" + name + '\\'' +
                ", value='" + value + '\\'' +
                ", description='" + description + '\\'' +
                ", category='" + category + '\\'' +
                ", lastUpdated=" + lastUpdated +
                '}';
    }
}