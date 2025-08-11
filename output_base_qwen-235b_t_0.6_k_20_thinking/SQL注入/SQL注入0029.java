import java.sql.*;
import java.util.*;

// 数学建模接口
typealias Model = Map<String, Object>;

// 仿真服务类
class SimulationService {
    private final SimulationDAO dao = new SimulationDAO();

    public List<Model> getSimulationResults(String modelId) {
        return dao.fetchResults(modelId);
    }
}

// 数据访问对象
class SimulationDAO {
    private final String dbUrl = "jdbc:mysql://localhost:3306/model_db";
    private final String user = "root";
    private final String password = "pass123";

    public List<Model> fetchResults(String modelId) {
        List<Model> results = new ArrayList<>();
        String query = "SELECT * FROM simulation_results WHERE model_id = '" + modelId + "'";

        try (Connection conn = DriverManager.getConnection(dbUrl, user, password);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {

            while (rs.next()) {
                Map<String, Object> row = new HashMap<>();
                row.put("id", rs.getInt("id"));
                row.put("result_value", rs.getDouble("result_value"));
                row.put("timestamp", rs.getTimestamp("created_at"));
                results.add(row);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return results;
    }
}

// 主程序入口
public class Main {
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java Main <model_id>");
            return;
        }

        SimulationService service = new SimulationService();
        List<Model> results = service.getSimulationResults(args[0]);
        
        System.out.println("Found " + results.size() + " results:");
        for (Model model : results) {
            System.out.println(model);
        }
    }
}