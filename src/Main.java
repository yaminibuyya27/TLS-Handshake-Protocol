import protocol.*;
import utils.Colors;
import java.util.Scanner;
import java.io.*;

public class Main {

    private static final String CLIENT_TO_SERVER = "client_to_server.msg";
    private static final String SERVER_TO_CLIENT = "server_to_client.msg";

    public static void main(String[] args) {
        if (args[0].equalsIgnoreCase("server")) {
            runServer();
        } else if (args[0].equalsIgnoreCase("client")) {
            runClient();
        } else {
            System.out.println("Usage: java Main [server|client]");
            System.out.println("Or just: java Main (to launch both terminals)");
        }
    }

    // --------- SERVER MODE -------------
    private static void runServer() {
        Scanner scanner = new Scanner(System.in);
        printHeader("SERVER", Colors.BOLD_MAGENTA);

        try {
            TLSServer server = new TLSServer();

            // Phase 1: Initialize
            pressEnterToContinue(scanner, "Press ENTER to initialize server", Colors.MAGENTA);
            server.initialize();
            System.out.println(Colors.success("Server initialized!"));

            // Signal client that server is ready
            new File("server_ready.flag").createNewFile();

            // Phase 2: Receive Client Hello
            System.out.println("\n" + Colors.server("Waiting for CLIENT_HELLO..."));
            TLSMessage clientHello = waitForMessage(CLIENT_TO_SERVER);
            System.out.println(Colors.success("Received CLIENT_HELLO from client!"));

            // Phase 3: Send Server Hello + Certificate
            pressEnterToContinue(scanner, "Press ENTER to send SERVER_HELLO and CERTIFICATE", Colors.MAGENTA);
            TLSMessage[] serverMessages = server.handleClientHello(clientHello);
            saveMessage(SERVER_TO_CLIENT, serverMessages[0]); // Server Hello

            // Wait for client to read the first message
            while (new File(SERVER_TO_CLIENT).exists()) {
                Thread.sleep(50);
            }
            saveMessage(SERVER_TO_CLIENT, serverMessages[1]); // Certificate
            System.out.println(Colors.success("Sent SERVER_HELLO and CERTIFICATE to client!"));

            // Phase 4: Receive Client Key Exchange
            System.out.println("\n" + Colors.server("Waiting for CLIENT_KEY_EXCHANGE..."));
            TLSMessage clientKeyExchange = waitForMessage(CLIENT_TO_SERVER);
            System.out.println(Colors.success("Received CLIENT_KEY_EXCHANGE from client!"));

            // Phase 5: Send Server Finished
            pressEnterToContinue(scanner, "Press ENTER to compute shared secret and send FINISHED", Colors.MAGENTA);
            TLSMessage serverFinished = server.handleClientKeyExchange(clientKeyExchange);
            saveMessage(SERVER_TO_CLIENT, serverFinished);
            System.out.println(Colors.success("Sent SERVER_FINISHED to client!"));

            // Phase 6: Receive Client Finished
            System.out.println("\n" + Colors.server("Waiting for CLIENT_FINISHED..."));
            TLSMessage clientFinished = waitForMessage(CLIENT_TO_SERVER);
            boolean success = server.handleClientFinished(clientFinished);

            if (!success) {
                System.out.println(Colors.error("Handshake failed!"));
                return;
            }

            System.out.println(Colors.BOLD_GREEN + "-------SECURE CONNECTION ESTABLISHED!---------" + Colors.RESET);

            // Chat mode
            chatMode(scanner, server, "SERVER", Colors.BOLD_MAGENTA);

        } catch (Exception e) {
            System.out.println(Colors.error("Error: " + e.getMessage()));
            e.printStackTrace();
        } finally {
            cleanup();
            scanner.close();
        }
    }

    // --------- CLIENT MODE -------------
    private static void runClient() {
        Scanner scanner = new Scanner(System.in);
        printHeader("CLIENT", Colors.BOLD_CYAN);

        try {
            TLSClient client = new TLSClient();

            // Wait for server to be ready
            System.out.println(Colors.client("Waiting for server to initialize..."));
            waitForFile("server_ready.flag");
            deleteFile("server_ready.flag");
            System.out.println(Colors.success("Server is ready!"));

            // Phase 1: Client Hello
            pressEnterToContinue(scanner, "Press ENTER to send CLIENT_HELLO to server", Colors.CYAN);
            TLSMessage clientHello = client.sendClientHello();
            saveMessage(CLIENT_TO_SERVER, clientHello);
            System.out.println(Colors.success("CLIENT_HELLO sent to server!"));

            // Phase 2: Receive Server Hello + Certificate
            System.out.println("\n" + Colors.client("Waiting for server response..."));
            TLSMessage[] serverMessages = waitForServerMessages();
            System.out.println(Colors.success("Received SERVER_HELLO and CERTIFICATE from server!"));

            // Phase 3: Process certificate and send key exchange
            pressEnterToContinue(scanner, "Press ENTER to process certificate and send key exchange", Colors.CYAN);
            client.handleServerMessages(serverMessages[0], serverMessages[1]);
            TLSMessage clientKeyExchange = client.sendClientKeyExchange();
            saveMessage(CLIENT_TO_SERVER, clientKeyExchange);
            System.out.println(Colors.success("CLIENT_KEY_EXCHANGE sent to server!"));

            // Phase 4: Receive Server Finished
            System.out.println("\n" + Colors.client("Waiting for server to finish handshake..."));
            TLSMessage serverFinished = waitForMessage(SERVER_TO_CLIENT);
            System.out.println(Colors.success("Received SERVER_FINISHED from server!"));

            // Phase 5: Send Client Finished
            pressEnterToContinue(scanner, "Press ENTER to send CLIENT_FINISHED", Colors.CYAN);
            TLSMessage clientFinished = client.handleServerFinished(serverFinished);
            saveMessage(CLIENT_TO_SERVER, clientFinished);
            System.out.println(Colors.success("CLIENT_FINISHED sent to server!"));

            System.out.println(Colors.BOLD_GREEN + "-------SECURE CONNECTION ESTABLISHED!---------" + Colors.RESET);


            // Chat mode
            chatMode(scanner, client, "CLIENT", Colors.BOLD_CYAN);

        } catch (Exception e) {
            System.out.println(Colors.error("Error: " + e.getMessage()));
            e.printStackTrace();
        } finally {
            cleanup();
            scanner.close();
        }
    }

    // --------- CHAT MODE -------------
    private static void chatMode(Scanner scanner, Object party, String role, String color) {
        boolean isServer = role.equals("SERVER");
        String myFile = isServer ? SERVER_TO_CLIENT : CLIENT_TO_SERVER;
        String theirFile = isServer ? CLIENT_TO_SERVER : SERVER_TO_CLIENT;
        String otherRole = isServer ? "CLIENT" : "SERVER";
        String otherColor = isServer ? Colors.BOLD_CYAN : Colors.BOLD_MAGENTA;

        System.out.println(color + "------------- SECURE CHAT MODE ACTIVATED ------------------" + Colors.RESET);
        System.out.println(Colors.info("Type your messages and press ENTER to send"));
        System.out.println(Colors.info("Messages are encrypted before transmission!"));
        System.out.println(Colors.info("Type 'quit' to exit\n"));

        // Start receiver thread
        Thread receiverThread = new Thread(() -> {
            try {
                while (true) {
                    if (new File(theirFile).exists()) {
                        TLSMessage encrypted = loadMessage(theirFile);
                        deleteFile(theirFile);

                        if (encrypted == null) { // Quit signal
                            System.out.println("\n" + Colors.info(otherRole + " disconnected."));
                            System.exit(0);
                        }

                        String decrypted;
                        if (isServer) {
                            decrypted = ((TLSServer) party).receiveData(encrypted);
                        } else {
                            decrypted = ((TLSClient) party).receiveData(encrypted);
                        }

                        System.out.println("\n" + otherColor + otherRole + Colors.RESET + ": " + decrypted);
                        System.out.print(color + role + Colors.RESET + ": ");
                        System.out.flush();
                    }
                    Thread.sleep(100);
                }
            } catch (Exception e) {
                // Thread stopped
            }
        });
        receiverThread.setDaemon(true);
        receiverThread.start();

        // Send messages
        while (true) {
            System.out.print(color + role + Colors.RESET + ": ");
            String message = scanner.nextLine();

            if (message.equalsIgnoreCase("quit")) {
                try {
                    saveMessage(myFile, null); // Signal quit
                } catch (IOException e) {
                    e.printStackTrace();
                }
                System.out.println(Colors.info("Closing connection..."));
                System.out.println(Colors.success("Connection closed. Goodbye!"));
                break;
            }

            if (message.trim().isEmpty()) continue;

            try {
                TLSMessage encrypted;
                if (isServer) {
                    encrypted = ((TLSServer) party).sendData(message);
                } else {
                    encrypted = ((TLSClient) party).sendData(message);
                }
                saveMessage(myFile, encrypted);
                System.out.println(Colors.success("Encrypted and sent!"));
            } catch (Exception e) {
                System.out.println(Colors.error("Failed to send: " + e.getMessage()));
            }
        }
    }

    // ------------ UTILITY METHODS -------------

    private static void printHeader(String role, String color) {
        System.out.println(color + "---------------TLS HANDSHAKE PROTOCOL--------------" + Colors.RESET);
        System.out.println(color + "----------" + role + " TERMINAL" + "----------" + Colors.RESET);
    }

    private static void pressEnterToContinue(Scanner scanner, String message, String color) {
        System.out.print("\n" + color + "→ " + Colors.RESET + message + ": ");
        scanner.nextLine();
    }

    private static void saveMessage(String filename, TLSMessage message) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filename))) {
            oos.writeObject(message);
        }
    }

    private static TLSMessage loadMessage(String filename) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename))) {
            return (TLSMessage) ois.readObject();
        }
    }

    private static TLSMessage[] waitForServerMessages() throws Exception {
        // Wait for server hello
        waitForFile(SERVER_TO_CLIENT);
        TLSMessage serverHello = loadMessage(SERVER_TO_CLIENT);
        deleteFile(SERVER_TO_CLIENT);

        // Wait for certificate
        waitForFile(SERVER_TO_CLIENT);
        TLSMessage serverCert = loadMessage(SERVER_TO_CLIENT);
        deleteFile(SERVER_TO_CLIENT);

        return new TLSMessage[] { serverHello, serverCert };
    }

    private static TLSMessage waitForMessage(String filename) throws Exception {
        waitForFile(filename);
        TLSMessage message = loadMessage(filename);
        deleteFile(filename);
        return message;
    }

    private static void waitForFile(String filename) throws InterruptedException {
        File file = new File(filename);
        while (!file.exists()) {
            Thread.sleep(100);
        }
        Thread.sleep(50); // Ensure write is complete
    }

    private static void deleteFile(String filename) {
        new File(filename).delete();
    }

    private static void cleanup() {
        deleteFile(CLIENT_TO_SERVER);
        deleteFile(SERVER_TO_CLIENT);
        deleteFile("server_ready.flag");
    }
}