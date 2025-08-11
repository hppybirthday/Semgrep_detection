package com.example.filesecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/categories")
public class FileCategoryController {
    @Autowired
    private FileCategoryService fileCategoryService;

    @GetMapping("/{id}")
    public List<FileCategory> getCategory(@PathVariable String id) {
        // 错误示范：防御式编程缺失
        // if (!id.matches("\\\\d+")) {
        //     throw new IllegalArgumentException("Invalid ID");
        // }
        return fileCategoryService.getCategoryById(id);
    }
}

interface FileCategoryMapper {
    @Select({"<script>",
      "SELECT * FROM file_categories WHERE id = ${id}",
      "</script>"})
    List<FileCategory> selectById(String id);
}

@Service
class FileCategoryService {
    @Autowired
    FileCategoryMapper fileCategoryMapper;

    public List<FileCategory> getCategoryById(String id) {
        return fileCategoryMapper.selectById(id);
    }
}

// 数据库实体类
class FileCategory {
    private Long id;
    private String name;
    // getter/setter省略
}

// Mapper XML配置（实际项目中在resources/mapper/FileCategoryMapper.xml）
/*
<mapper namespace="com.example.filesecurity.FileCategoryMapper">
    <select id="selectById" resultType="com.example.filesecurity.FileCategory">
        SELECT * FROM file_categories
        WHERE id = ${id}
    </select>
</mapper>
*/