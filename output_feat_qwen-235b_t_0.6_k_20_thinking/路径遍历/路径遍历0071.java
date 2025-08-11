import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.nio.file.*;

public class GameSaveManager extends JFrame {
    private JTextField prefixField;
    private JTextField suffixField;
    private JTextArea contentArea;
    private JLabel statusLabel;

    public GameSaveManager() {
        setTitle("Game Save Manager");
        setSize(500, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        initializeUI();
    }

    private void initializeUI() {
        JPanel panel = new JPanel(new GridLayout(5, 2));
        
        panel.add(new JLabel("Prefix (e.g., player1):"));
        prefixField = new JTextField();
        panel.add(prefixField);
        
        panel.add(new JLabel("Suffix (e.g., level3):"));
        suffixField = new JTextField();
        panel.add(suffixField);
        
        panel.add(new JLabel("Content to save:"));
        contentArea = new JTextArea(5, 20);
        panel.add(new JScrollPane(contentArea));
        
        JButton saveButton = new JButton("Save Game");
        saveButton.addActionListener(this::saveGame);
        panel.add(saveButton);
        
        statusLabel = new JLabel("Status: Ready");
        panel.add(statusLabel);
        
        add(panel);
    }

    private void saveGame(ActionEvent e) {
        String prefix = prefixField.getText();
        String suffix = suffixField.getText();
        
        try {
            // Vulnerable path construction
            String basePath = "user_saves/";
            File dir = new File(basePath + prefix);
            if (!dir.exists()) {
                dir.mkdirs();
            }
            
            // Vulnerable file path
            File file = new File(basePath + prefix + "/" + suffix + ".dat");
            
            // Check if file exists (vulnerable to TOCTOU)
            if (file.exists()) {
                statusLabel.setText("Status: File exists. Overwriting...");
            }
            
            // Vulnerable write operation
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
                writer.write(contentArea.getText());
            }
            
            statusLabel.setText("Status: Saved to " + file.getAbsolutePath());
            
        } catch (Exception ex) {
            statusLabel.setText("Status: Error - " + ex.getMessage());
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new GameSaveManager().setVisible(true);
        });
    }
}