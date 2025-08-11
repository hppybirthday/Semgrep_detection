package com.game.load;

import java.io.*;
import java.util.Scanner;

public class GameLoader {
    private final GameService gameService = new GameService();

    public static void main(String[] args) {
        GameLoader loader = new GameLoader();
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter savegame name: ");
        String filename = scanner.nextLine();
        loader.loadSaveGame(filename);
    }

    public void loadSaveGame(String filename) {
        try {
            String content = gameService.loadSaveFile(filename);
            System.out.println("Loaded game data:");
            System.out.println(content);
        } catch (Exception e) {
            System.err.println("Failed to load game: " + e.getMessage());
        }
    }
}

class GameService {
    private static final String BASE_DIR = "./saves/";
    private final FileManager fileManager = new FileManager();

    public String loadSaveFile(String filename) throws IOException {
        // Vulnerable path concatenation
        String safePath = BASE_DIR + filename;
        return fileManager.readFile(safePath);
    }
}

class FileManager {
    public String readFile(String path) throws IOException {
        File file = new File(path);
        if (!file.exists()) {
            throw new FileNotFoundException("File not found: " + path);
        }

        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
        }
        return content.toString();
    }
}