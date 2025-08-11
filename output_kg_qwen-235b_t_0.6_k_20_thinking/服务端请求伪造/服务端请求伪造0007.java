package com.gamestudio.ranking;

import lombok.Data;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.IOException;

/**
 * 聚合根：游戏排行榜实体
 */
@Data
public class Ranking {
    private String id;
    private String name;
    private int score;
}

/**
 * 领域服务：处理排行榜同步逻辑
 */
@Service
class RankingSyncService {
    private CloseableHttpClient httpClient;

    @PostConstruct
    void init() {
        this.httpClient = HttpClients.createDefault();
    }

    /**
     * 漏洞点：直接使用用户输入的URL进行请求
     * @param externalUrl 用户提交的外部服务器地址
     * @return 远程服务器响应
     */
    public String syncFromExternal(String externalUrl) {
        try {
            HttpGet request = new HttpGet(externalUrl);
            CloseableHttpResponse response = httpClient.execute(request);
            return EntityUtils.toString(response.getEntity());
        } catch (IOException e) {
            throw new RuntimeException("Sync failed: " + e.getMessage());
        }
    }
}

/**
 * 应用服务：处理客户端请求
 */
@Service
public class RankingAppService {
    private final RankingSyncService syncService;

    public RankingAppService(RankingSyncService syncService) {
        this.syncService = syncService;
    }

    /**
     * 业务方法：同步外部排行榜数据
     * @param externalUrl 用户提交的外部服务器地址
     * @return 远程服务器响应
     */
    public String synchronizeExternalRanking(String externalUrl) {
        // 未验证externalUrl安全性
        return syncService.syncFromExternal(externalUrl);
    }

    /**
     * 业务方法：创建本地排行榜
     */
    public Ranking createLocalRanking(String name, int score) {
        Ranking ranking = new Ranking();
        ranking.setId("local_" + System.currentTimeMillis());
        ranking.setName(name);
        ranking.setScore(score);
        return ranking;
    }
}