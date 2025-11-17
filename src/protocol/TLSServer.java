package protocol;

import crypto.RSA;
import crypto.DiffieHellman;
import crypto.KDF;
import utils.ByteUtils;
import utils.Colors;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.util.UUID;


// TLS Server Implementation which handles server-side TLS handshake and encrypted communication
public class TLSServer {

    private final HandshakeState state;
    private DiffieHellman dhServer;
    private final SecureRandom random;

    public TLSServer() {
        this.state = new HandshakeState();
        this.random = new SecureRandom();
    }


    // Initialize server with RSA keys
    public void initialize() {
        System.out.println("\n" + Colors.server("Initializing server..."));

        // Generate RSA key pair for authentication
        RSA.KeyPair rsaKeys = RSA.generateKeyPair(2048);
        state.setServerKeyPair(rsaKeys);

        System.out.println(Colors.success("Server initialized with RSA keys"));
    }


    // Step 2: Process Client Hello and send Server Hello
    public TLSMessage[] handleClientHello(TLSMessage clientHello) {
        System.out.println("\n" + Colors.server("Received CLIENT_HELLO"));

        if (clientHello.getType() != TLSMessage.MessageType.CLIENT_HELLO) {
            System.out.println(Colors.error("Expected CLIENT_HELLO"));
            state.transitionTo(HandshakeState.State.ERROR);
            return null;
        }

        // Extract client random
        state.setClientRandom(clientHello.getPayload());
        System.out.println(Colors.info("Client random: " +
                ByteUtils.toHex(state.getClientRandom()).substring(0, 16) + "..."));

        state.transitionTo(HandshakeState.State.SERVER_HELLO_RECEIVED);

        // Generate server random
        byte[] serverRandom = new byte[32];
        random.nextBytes(serverRandom);
        state.setServerRandom(serverRandom);

        // Generate session ID
        String sessionId = UUID.randomUUID().toString().substring(0, 8);
        state.setSessionId(sessionId);

        // Generate DH parameters
        DiffieHellman.DHParameters dhParams = DiffieHellman.generateParameters(2048);
        state.setDhParameters(dhParams);

        // Initialize DH for server
        dhServer = new DiffieHellman(dhParams.p, dhParams.g);
        dhServer.generatePrivateKey();
        BigInteger serverDHPublic = dhServer.computePublicKey();
        state.setServerDHPublic(serverDHPublic);

        System.out.println(Colors.server("Sending SERVER_HELLO + SERVER_CERTIFICATE"));

        // Create SERVER_HELLO message
        TLSMessage serverHello = new TLSMessage(
                TLSMessage.MessageType.SERVER_HELLO,
                serverRandom,
                "SessionID: " + sessionId
        );

        // Create SERVER_CERTIFICATE message
        // Contains: RSA Public Key + DH Parameters + Server DH Public Key
        byte[] certData = createCertificateData();
        TLSMessage serverCert = new TLSMessage(
                TLSMessage.MessageType.SERVER_CERTIFICATE,
                certData
        );

        return new TLSMessage[] { serverHello, serverCert };
    }


    // Step 4: Process Client Key Exchange and send Finished
    public TLSMessage handleClientKeyExchange(TLSMessage clientKeyExchange) {
        System.out.println("\n" + Colors.server("Received CLIENT_KEY_EXCHANGE"));

        if (clientKeyExchange.getType() != TLSMessage.MessageType.CLIENT_KEY_EXCHANGE) {
            System.out.println(Colors.error("Expected CLIENT_KEY_EXCHANGE"));
            state.transitionTo(HandshakeState.State.ERROR);
            return null;
        }

        // Parse client's DH public key (first part of payload)
        byte[] payload = clientKeyExchange.getPayload();
        BigInteger clientDHPublic = new BigInteger(payload);
        state.setClientDHPublic(clientDHPublic);

        System.out.println(Colors.info("Client DH public key received"));

        // Compute shared secret
        BigInteger sharedSecret = dhServer.computeSharedSecret(clientDHPublic);
        state.setSharedSecret(sharedSecret);

        System.out.println(Colors.success("Shared secret computed: " +
                sharedSecret.toString(16).substring(0, 32) + "..."));

        // Derive session keys
        byte[][] sessionKeys = KDF.deriveSessionKeys(sharedSecret);
        state.setSessionKeys(sessionKeys[0], sessionKeys[1]);

        System.out.println(Colors.success("Session keys derived"));
        System.out.println(Colors.info("Encryption key: " +
                ByteUtils.toHex(sessionKeys[0]).substring(0, 16) + "..."));

        state.transitionTo(HandshakeState.State.FINISHED_SENT);

        // Send FINISHED message
        System.out.println(Colors.server("Sending FINISHED"));

        String finishedMsg = "SERVER_FINISHED:" + state.getSessionId();
        byte[] encryptedFinished = simpleEncrypt(
                finishedMsg.getBytes(StandardCharsets.UTF_8),
                state.getSessionEncryptionKey()
        );

        return new TLSMessage(
                TLSMessage.MessageType.FINISHED,
                encryptedFinished
        );
    }


    // Step 6: Process Client Finished message
    public boolean handleClientFinished(TLSMessage clientFinished) {
        System.out.println("\n" + Colors.server("Received FINISHED from client"));

        if (clientFinished.getType() != TLSMessage.MessageType.FINISHED) {
            System.out.println(Colors.error("Expected FINISHED"));
            return false;
        }

        // Decrypt finished message
        byte[] decrypted = simpleDecrypt(
                clientFinished.getPayload(),
                state.getSessionEncryptionKey()
        );

        String message = new String(decrypted, StandardCharsets.UTF_8);
        System.out.println(Colors.info("Decrypted: " + message));

        // Verify session ID
        if (message.contains(state.getSessionId())) {
            state.transitionTo(HandshakeState.State.HANDSHAKE_COMPLETE);
            System.out.println(Colors.success("Handshake complete"));
            return true;
        }

        System.out.println(Colors.error("Session ID mismatch"));
        return false;
    }


    // Receive and decrypt application data
    public String receiveData(TLSMessage message) {
        if (!state.isHandshakeComplete()) {
            throw new IllegalStateException("Handshake not complete");
        }

        if (message.getType() != TLSMessage.MessageType.APPLICATION_DATA) {
            throw new IllegalArgumentException("Expected APPLICATION_DATA");
        }

        byte[] decrypted = simpleDecrypt(
                message.getPayload(),
                state.getSessionEncryptionKey()
        );

        return new String(decrypted, StandardCharsets.UTF_8);
    }


    // Encrypt and send application data
    public TLSMessage sendData(String plaintext) {
        if (!state.isHandshakeComplete()) {
            throw new IllegalStateException("Handshake not complete");
        }

        byte[] encrypted = simpleEncrypt(
                plaintext.getBytes(StandardCharsets.UTF_8),
                state.getSessionEncryptionKey()
        );

        return new TLSMessage(
                TLSMessage.MessageType.APPLICATION_DATA,
                encrypted
        );
    }


    // Create certificate data containing server credentials
    private byte[] createCertificateData() {
        RSA.KeyPair keys = state.getServerKeyPair();
        DiffieHellman.DHParameters dhParams = state.getDhParameters();

        // Format: [RSA_e][RSA_n][DH_p][DH_g][Server_DH_public]
        byte[] rsaE = keys.publicKey.e.toByteArray();
        byte[] rsaN = keys.publicKey.n.toByteArray();
        byte[] dhP = dhParams.p.toByteArray();
        byte[] dhG = dhParams.g.toByteArray();
        byte[] serverDH = state.getServerDHPublic().toByteArray();

        // Create length-prefixed format
        return ByteUtils.concat(
                intToBytes(rsaE.length), rsaE,
                intToBytes(rsaN.length), rsaN,
                intToBytes(dhP.length), dhP,
                intToBytes(dhG.length), dhG,
                intToBytes(serverDH.length), serverDH
        );
    }


    // XOR-based encryption
    private byte[] simpleEncrypt(byte[] plaintext, byte[] key) {
        byte[] result = new byte[plaintext.length];
        for (int i = 0; i < plaintext.length; i++) {
            result[i] = (byte) (plaintext[i] ^ key[i % key.length]);
        }
        return result;
    }


    // XOR-based decryption
    private byte[] simpleDecrypt(byte[] ciphertext, byte[] key) {
        return simpleEncrypt(ciphertext, key); // XOR is symmetric
    }


    // Convert int to 4-byte array
    private byte[] intToBytes(int value) {
        return new byte[] {
                (byte) (value >> 24),
                (byte) (value >> 16),
                (byte) (value >> 8),
                (byte) value
        };
    }
}