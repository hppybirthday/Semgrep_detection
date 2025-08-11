import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

// 领域模型
class Player {
    private String id;
    private String name;

    public Player(String id, String name) {
        this.id = id;
        this.name = name;
    }

    public String getName() {
        return name;
    }
}

// 仓储接口
interface PlayerRepository {
    Player findPlayerById(String id);
}

// 命令执行服务
class CommandExecutor {
    public String executeCommand(String command) throws IOException {
        Process process = Runtime.getRuntime().exec(command);
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        return output.toString();
    }
}

// 游戏业务服务
class GameService {
    private PlayerRepository playerRepo;
    private CommandExecutor executor;

    public GameService(PlayerRepository repo, CommandExecutor executor) {
        this.playerRepo = repo;
        this.executor = executor;
    }

    public String handleCustomCommand(String playerId, String userInput) throws Exception {
        Player player = playerRepo.findPlayerById(playerId);
        if (player == null) {
            throw new IllegalArgumentException("Player not found");
        }
        
        // 漏洞点：直接拼接用户输入执行系统命令
        String fullCommand = "echo 'Welcome " + player.getName() + "' && " + userInput;
        return executor.executeCommand(fullCommand);
    }
}

// 模拟仓储实现
class InMemoryPlayerRepository implements PlayerRepository {
    @Override
    public Player findPlayerById(String id) {
        // 模拟数据库查询
        return new Player(id, "Player_" + id);
    }
}

// 主程序
class GameApplication {
    public static void main(String[] args) {
        try {
            PlayerRepository repo = new InMemoryPlayerRepository();
            CommandExecutor executor = new CommandExecutor();
            GameService gameService = new GameService(repo, executor);
            
            // 模拟用户输入
            String playerId = "123";
            String userInput = args.length > 0 ? args[0] : "echo default";
            
            String result = gameService.handleCustomCommand(playerId, userInput);
            System.out.println("Command Output:\
" + result);
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}