import javax.persistence.*;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Service;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.util.List;

@Entity
class CrawledData {
    @Id
    private Long id;
    private String url;
    private String content;
    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }
    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }
}

interface CrawledDataRepository extends JpaRepository<CrawledData, Long> {}

@Service
class CrawledDataService {
    @PersistenceContext
    private EntityManager entityManager;

    // 漏洞点：直接拼接用户输入到SQL语句
    public List<CrawledData> searchByKeyword(String keyword) {
        String sql = "SELECT * FROM crawled_data WHERE url LIKE '%" + keyword + "%'";
        return entityManager.createNativeQuery(sql, CrawledData.class).getResultList();
    }
}

@SpringBootApplication
public class VulnerableCrawlerApplication implements CommandLineRunner {
    @Autowired
    private CrawledDataService crawledDataService;

    public static void main(String[] args) {
        SpringApplication.run(VulnerableCrawlerApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        // 模拟正常用户输入
        System.out.println("Normal search results:");
        crawledDataService.searchByKeyword("example.com").forEach(data -> 
            System.out.println("Found: " + data.getUrl()));

        // 模拟攻击者输入
        System.out.println("\
Malicious input attack:");
        String payload = "%' UNION SELECT null, 'hacked', 'sensitive_data' -- ";
        crawledDataService.searchByKeyword(payload).forEach(data -> 
            System.out.println("Stolen data: " + data.getContent()));
    }

    // 模拟数据库配置
    @Bean
    public DataSource dataSource() {
        return new EmbeddedDatabaseBuilder().setType(EmbeddedDatabaseType.H2)
            .addScript("schema.sql").build();
    }
}