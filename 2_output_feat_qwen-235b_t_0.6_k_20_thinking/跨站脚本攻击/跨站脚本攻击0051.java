package com.gamestudio.desktop.controller;

import org.springframework.web.bind.annotation.*;
import com.gamestudio.desktop.model.Player;
import com.gamestudio.desktop.service.PlayerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.http.MediaType;

/**
 * 玩家信息控制器
 * @author gamestudio-team
 * @date 2023-11-15
 */
@RestController
@RequestMapping(path = "/api/players", produces = MediaType.APPLICATION_JSON_VALUE)
public class PlayerController {
    @Autowired
    private PlayerService playerService;

    /**
     * 获取玩家信息（JSONP格式）
     * @param name 玩家名称
     * @param callback JSONP回调函数名
     * @return JSONP格式响应
     */
    @GetMapping("/{name}")
    public String getPlayerInfo(@PathVariable("name") String name, 
                                @RequestParam("callback") String callback) {
        Player player = playerService.getPlayerByName(name);
        // 构建JSONP响应内容
        StringBuilder responseBuilder = new StringBuilder();
        responseBuilder.append(callback).append("({\\"name\\":\\"");
        responseBuilder.append(player.getName()).append("\\",\\"score\\":");
        responseBuilder.append(player.getScore()).append("})");
        return responseBuilder.toString();
    }

    /**
     * 创建新玩家
     * @param name 玩家名称
     * @return 创建结果
     */
    @PostMapping
    public boolean createPlayer(@RequestParam("name") String name) {
        // 校验玩家名称长度（业务规则）
        if (name.length() < 2 || name.length() > 20) {
            return false;
        }
        return playerService.createPlayer(name);
    }
}