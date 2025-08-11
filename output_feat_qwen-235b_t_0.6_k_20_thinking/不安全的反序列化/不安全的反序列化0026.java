import java.io.*;
import java.util.*;
import com.alibaba.fastjson.JSON;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class AccountService {
    private final RedisTemplate<String, Object> redisTemplate;

    public AccountService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void insertAccount(String accountData) {
        Account account = JSON.parseObject(accountData, Account.class);
        // 模拟数据清洗
        account.setEmail(account.getEmail().toLowerCase());
        redisTemplate.opsForValue().set("account:" + account.getId(), account);
    }

    public void updateAccount(String accountId, String updateData) {
        Account account = (Account) redisTemplate.opsForValue().get("account:" + accountId);
        if (account != null) {
            Map<String, Object> updateMap = JSON.parseObject(updateData, Map.class);
            // 不安全的反序列化操作
            if (updateMap.containsKey("config")) {
                ObjectInputStream ois = null;
                try {
                    ByteArrayInputStream bais = new ByteArrayInputStream(
                        Base64.getDecoder().decode((String) updateMap.get("config")));
                    ois = new ObjectInputStream(bais);
                    account.setConfig((Map<String, Object>) ois.readObject());
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    try {
                        if (ois != null) ois.close();
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }
                }
            }
            redisTemplate.opsForValue().set("account:" + accountId, account);
        }
    }

    public void batchSetStatus(String accountIds, boolean enabled) {
        // 模拟批量操作
    }

    public void updateAuthProviderEnabled(String configMap) {
        // 存在漏洞的JSON解析
        Map<String, Object> config = JSON.parseObject(configMap, Map.class);
        // 恶意构造的configMap可触发反序列化攻击
        redisTemplate.opsForValue().set("auth:config", config);
    }

    static class Account implements Serializable {
        private String id;
        private String email;
        private Map<String, Object> config;
        
        // Getters and setters
        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
        public Map<String, Object> getConfig() { return config; }
        public void setConfig(Map<String, Object> config) { this.config = config; }
    }
}