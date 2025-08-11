package com.game.desktop.infrastructure.http;

import com.game.desktop.domain.model.Player;
import com.game.desktop.domain.service.PlayerService;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class ExternalPlayerClient {
    private final CloseableHttpClient httpClient = HttpClients.createDefault();

    public String fetchPlayerData(String playerId) {
        String url = "http://external-api.example.com/players/" + playerId;
        try {
            HttpGet request = new HttpGet(url);
            CloseableHttpResponse response = httpClient.execute(request);
            return EntityUtils.toString(response.getEntity());
        } catch (IOException e) {
            throw new RuntimeException("Failed to fetch player data: " + e.getMessage());
        }
    }
}

package com.game.desktop.domain.service;

import com.game.desktop.domain.model.Player;
import com.game.desktop.domain.repository.PlayerRepository;
import com.game.desktop.infrastructure.http.ExternalPlayerClient;
import org.springframework.stereotype.Service;

@Service
public class PlayerService {
    private final PlayerRepository playerRepository;
    private final ExternalPlayerClient externalPlayerClient;

    public PlayerService(PlayerRepository playerRepository, ExternalPlayerClient externalPlayerClient) {
        this.playerRepository = playerRepository;
        this.externalPlayerClient = externalPlayerClient;
    }

    public String syncPlayerData(String playerId) {
        // 漏洞点：直接使用用户输入的playerId拼接URL
        String externalData = externalPlayerClient.fetchPlayerData(playerId);
        // 本地存储逻辑（示例）
        Player player = new Player(playerId, externalData);
        playerRepository.save(player);
        return "Synced: " + externalData;
    }
}

package com.game.desktop.adapter.web;

import com.game.desktop.domain.service.PlayerService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/players")
public class PlayerController {
    private final PlayerService playerService;

    public PlayerController(PlayerService playerService) {
        this.playerService = playerService;
    }

    @GetMapping("/{playerId}/sync")
    public String syncPlayer(@PathVariable String playerId) {
        return playerService.syncPlayerData(playerId);
    }
}

package com.game.desktop.domain.model;

public class Player {
    private final String id;
    private final String data;

    public Player(String id, String data) {
        this.id = id;
        this.data = data;
    }

    // Getters and other domain logic
}

package com.game.desktop.domain.repository;

import com.game.desktop.domain.model.Player;

public interface PlayerRepository {
    void save(Player player);
    Player findById(String id);
}