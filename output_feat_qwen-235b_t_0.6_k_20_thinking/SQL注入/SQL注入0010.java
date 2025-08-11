package com.example.vulnerableapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.beetl.sql.core.SQLManager;
import org.beetl.sql.core.annotatoin.SqlResource;
import org.beetl.sql.core.engine.PageQuery;
import org.springframework.beans.factory.annotation.Autowired;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

@SpringBootApplication
public class Main {
    public static void main(String[] args) {
        SpringApplication.run(Main.class, args);
    }
}

@RestController
@RequestMapping("/api")
class DataController {
    @Autowired
    DataService dataService;

    @DeleteMapping("/clean")
    void batchDelete(@RequestParam String ids, HttpServletResponse response) throws IOException {
        try {
            dataService.deleteRecords(ids);
            response.getWriter().write("Records deleted successfully");
        } catch (Exception e) {
            response.sendError(500, "Database error: " + e.getMessage());
        }
    }
}

class DataService {
    @Autowired
    SQLManager sqlManager;

    void deleteRecords(String ids) {
        // 模拟数据清洗前的错误处理
        String sanitized = ids.replace("'", "'"'"'); // 错误的过滤逻辑
        
        // 漏洞点：直接拼接用户输入到SQL语句
        String sql = "DELETE FROM user_data WHERE id IN (" + sanitized + ")";
        
        // 执行数据清洗操作
        sqlManager.executeUpdate(sql);
    }
}

// 模拟BeetlSQL的DAO层接口
@SqlResource("userDataDao")
interface UserDataDao {
    default void deleteByIds(String ids) {
        // 实际执行的SQL会被错误拼接
        // 正确应使用参数化查询：@Sql("DELETE FROM user_data WHERE id IN(#{ids})")
    }
}

/*
MyBatis XML映射文件（userDataDao.xml）中的错误实现：
<delete id="deleteByIds">
    DELETE FROM user_data
    WHERE id IN (${ids}) <!-- 错误使用${}导致注入漏洞 -->
</delete>
*/