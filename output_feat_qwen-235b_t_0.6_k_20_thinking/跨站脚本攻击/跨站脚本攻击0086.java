package com.gamestudio.core;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class GameStudioApplication {
    public static void main(String[] args) {
        SpringApplication.run(GameStudioApplication.class, args);
    }
}

// 领域实体
class Game {
    private String id;
    private String name;
    
    public Game(String id, String name) {
        this.id = id;
        this.name = name;
    }
    
    public String getId() { return id; }
    public String getName() { return name; }
}

// 仓储接口
interface GameRepository {
    Game findById(String id);
}

// 服务层
@RestController
class GameService {
    private final GameRepository repository;
    
    public GameService(GameRepository repository) {
        this.repository = repository;
    }
    
    @GetMapping("/games/{id}")
    public Game getGame(@PathVariable String id) {
        Game game = repository.findById(id);
        if (game == null) {
            throw new GameNotFoundException("Game not found: " + id);
        }
        return game;
    }
}

// 异常处理@Controller
class ErrorController {
    @GetMapping("/error")
    public String handleError(Model model, Exception ex) {
        model.addAttribute("errorMessage", ex.getMessage());
        return "error";
    }
}

// 自定义异常
class GameNotFoundException extends RuntimeException {
    public GameNotFoundException(String message) {
        super(message);
    }
}

// 模板渲染层（Thymeleaf模板）
// src/main/resources/templates/error.html
// <html>
// <body>
//     <h1>Error</h1>
//     <p>${errorMessage}</p>  <!-- 这里存在XSS漏洞 -->
// </body>
// </html>