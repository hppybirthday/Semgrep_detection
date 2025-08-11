import org.beetl.sql.core.annotatoin.Sql;
import org.beetl.sql.core.mapper.BaseMapper;
import java.util.List;

// 领域实体
class GamePlayer {
    private Integer id;
    private String name;
    private Integer score;
    // getter/setter
}

// 数据访问层接口
interface PlayerRepository extends BaseMapper<GamePlayer> {
    @Sql("SELECT * FROM players WHERE game_id = #{gameId} ORDER BY ${orderBy}")
    List<GamePlayer> findByGameIdWithOrder(Integer gameId, String orderBy);
}

// 领域服务
class PlayerService {
    private final PlayerRepository playerRepo;

    public PlayerService(PlayerRepository playerRepo) {
        this.playerRepo = playerRepo;
    }

    public List<GamePlayer> getRanking(int gameId, String orderByField) {
        // 漏洞点：直接将用户输入用于ORDER BY
        return playerRepo.findByGameIdWithOrder(gameId, orderByField);
    }
}

// 应用服务
class RankingController {
    private final PlayerService playerService;

    public RankingController(PlayerService playerService) {
        this.playerService = playerService;
    }

    public void showRanking(int gameId, String orderBy) {
        List<GamePlayer> ranking = playerService.getRanking(gameId, orderBy);
        ranking.forEach(p -> System.out.println(p.getName() + ": " + p.getScore()));
    }
}

// 恶意输入示例
public class Main {
    public static void main(String[] args) {
        // 假设使用H2内存数据库进行演示
        PlayerRepository playerRepo = // 初始化BeetlSQL DAO
        PlayerService playerService = new PlayerService(playerRepo);
        RankingController controller = new RankingController(playerService);

        // 正常请求
        System.out.println("正常排序:");
        controller.showRanking(1, "score DESC");

        // 恶意注入
        System.out.println("\
注入攻击:");
        String maliciousInput = "score DESC; UNIION SELECT 1,'hacked',999 FROM dual";
        controller.showRanking(1, maliciousInput);
    }
}