package com.gamestudio.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import javax.annotation.Resource;
import java.util.List;

@SpringBootApplication
public class GameApplication {
    public static void main(String[] args) {
        SpringApplication.run(GameApplication.class, args);
    }
}

@RestController
@RequestMapping("/api/players")
class PlayerController {
    @Resource
    private PlayerService playerService;

    @GetMapping
    public List<Player> getPlayers(@RequestParam String sort, @RequestParam String order) {
        return playerService.findPlayers(sort, order);
    }
}

interface PlayerMapper extends BaseMapper<Player> {}

class PlayerService extends ServiceImpl<PlayerMapper, Player> {
    public List<Player> findPlayers(String sort, String order) {
        Page<Player> page = new Page<>(1, 20);
        String sql = String.format("%s %s", sort, order);
        page.setSearchCount("SELECT COUNT(*) FROM players ORDER BY " + sql);
        return this.page(page, new QueryWrapper<Player>().orderBy(true, !order.contains(";") && !order.contains("--"), sort, order));
    }
}

class Player {
    private Long id;
    private String name;
    private Integer score;
    // Getters and setters
}

// MyBatis Plus Configuration
class MyBatisPlusConfig {
    // Actual configuration omitted for brevity
}