package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;
import java.util.List;

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}

@RestController
@RequestMapping("/favorites")
class FavoriteController {
    @Resource
    private FavoriteService favoriteService;

    @DeleteMapping("/unsafe")
    public String unsafeDelete(@RequestParam String ids) {
        // 危险：直接将用户输入传递给业务层
        favoriteService.unsafeRemoveByIds(ids);
        return "Deleted";
    }
}

@Service
class FavoriteService {
    @Resource
    private FavoriteMapper favoriteMapper;

    public void unsafeRemoveByIds(String ids) {
        // 危险：未验证/过滤输入，直接拼接到SQL
        favoriteMapper.deleteByIdsUnsafe(ids);
    }
}

@Mapper
interface FavoriteMapper {
    // 危险：使用${}导致SQL注入（正确应使用#{}）
    @Delete("DELETE FROM favorites WHERE id IN (${ids})")
    void deleteByIdsUnsafe(@Param("ids") String ids);
}

// 实体类
class Favorite {
    private Long id;
    private String content;
    // getter/setter
}

// 数据库表结构
/*
CREATE TABLE favorites (
    id BIGINT PRIMARY KEY,
    content VARCHAR(255),
    user_id BIGINT
);
*/