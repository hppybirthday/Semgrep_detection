import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class GameResourceLoader extends JFrame {
    private JTextField urlField;
    private JTextArea resultArea;
    private JButton loadButton;

    public GameResourceLoader() {
        setTitle("Game Resource Loader");
        setSize(600, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        initUI();
    }

    private void initUI() {
        JPanel panel = new JPanel();
        panel.setLayout(new BorderLayout(5, 5));

        JPanel inputPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel label = new JLabel("Resource URL:");
        urlField = new JTextField(30);
        loadButton = new JButton("Load");

        inputPanel.add(label);
        inputPanel.add(urlField);
        inputPanel.add(loadButton);

        resultArea = new JTextArea();
        resultArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(resultArea);

        panel.add(inputPanel, BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);

        add(panel);

        loadButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String urlString = urlField.getText();
                if (urlString.isEmpty()) {
                    resultArea.setText("Please enter a URL");
                    return;
                }

                new Thread(() -> {
                    try {
                        URL url = new URL(urlString);
                        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                        conn.setRequestMethod("GET");

                        StringBuilder response = new StringBuilder();
                        try (BufferedReader reader = new BufferedReader(
                                new InputStreamReader(conn.getInputStream()))) {
                            String line;
                            while ((line = reader.readLine()) != null) {
                                response.append(line).append("\
");
                            }
                        }

                        SwingUtilities.invokeLater(() -> {
                            resultArea.setText(response.toString());
                        });
                    } catch (Exception ex) {
                        SwingUtilities.invokeLater(() -> {
                            resultArea.setText("Error loading resource: " + ex.getMessage());
                        });
                    }
                }).start();
            }
        });
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new GameResourceLoader().setVisible(true);
        });
    }
}