package protocol;

import crypto.RSA;
import crypto.DiffieHellman;
import crypto.KDF;
import utils.ByteUtils;
import utils.Colors;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;


 // TLS Client Implementation which handles client-side TLS handshake and encrypted communication
public class TLSClient {

    private final HandshakeState state;
    private DiffieHellman dhClient;
    private final SecureRandom random;

    public TLSClient() {
        this.state = new HandshakeState();
        this.random = new SecureRandom();
    }

     // Step 1: Send Client Hello to initiate handshake
    public TLSMessage sendClientHello() {
        System.out.println("\n" + Colors.client("Initiating TLS handshake..."));

        // Generate client random nonce (32 bytes)
        byte[] clientRandom = new byte[32];
        random.nextBytes(clientRandom);
        state.setClientRandom(clientRandom);

        System.out.println(Colors.client("Sending CLIENT_HELLO"));
        System.out.println(Colors.info("Client random: " +
                ByteUtils.toHex(clientRandom).substring(0, 16) + "..."));

        state.transitionTo(HandshakeState.State.CLIENT_HELLO_SENT);

        return new TLSMessage(
                TLSMessage.MessageType.CLIENT_HELLO,
                clientRandom
        );
    }


     // Step 3: Process Server Hello and Certificate
    public void handleServerMessages(TLSMessage serverHello, TLSMessage serverCert) {
        System.out.println("\n" + Colors.client("Received SERVER_HELLO + SERVER_CERTIFICATE"));

        // Process Server Hello
        if (serverHello.getType() != TLSMessage.MessageType.SERVER_HELLO) {
            System.out.println(Colors.error("Expected SERVER_HELLO"));
            state.transitionTo(HandshakeState.State.ERROR);
            return;
        }

        state.setServerRandom(serverHello.getPayload());
        String sessionInfo = serverHello.getTextData();
        String sessionId = sessionInfo.split(": ")[1];
        state.setSessionId(sessionId);

        System.out.println(Colors.info("Session ID: " + sessionId));
        System.out.println(Colors.info("Server random: " +
                ByteUtils.toHex(state.getServerRandom()).substring(0, 16) + "..."));

        state.transitionTo(HandshakeState.State.SERVER_HELLO_RECEIVED);

        // Process Server Certificate
        if (serverCert.getType() != TLSMessage.MessageType.SERVER_CERTIFICATE) {
            System.out.println(Colors.error("Expected SERVER_CERTIFICATE"));
            state.transitionTo(HandshakeState.State.ERROR);
            return;
        }

        parseCertificate(serverCert.getPayload());
        state.transitionTo(HandshakeState.State.SERVER_CERT_RECEIVED);

        System.out.println(Colors.success("Server authenticated"));
    }


     // Step 4: Send Client Key Exchange
    public TLSMessage sendClientKeyExchange() {
        System.out.println("\n" + Colors.client("Sending CLIENT_KEY_EXCHANGE"));

        if (state.getDhParameters() == null) {
            throw new IllegalStateException("DH parameters not received");
        }

        // Initialize DH with server's parameters
        DiffieHellman.DHParameters dhParams = state.getDhParameters();
        dhClient = new DiffieHellman(dhParams.p, dhParams.g);

        // Generate client's DH key pair
        dhClient.generatePrivateKey();
        BigInteger clientDHPublic = dhClient.computePublicKey();
        state.setClientDHPublic(clientDHPublic);

        System.out.println(Colors.info("Client DH public key generated"));

        // Compute shared secret
        BigInteger sharedSecret = dhClient.computeSharedSecret(state.getServerDHPublic());
        state.setSharedSecret(sharedSecret);

        System.out.println(Colors.success("Shared secret computed: " +
                sharedSecret.toString(16).substring(0, 32) + "..."));

        // Derive session keys
        byte[][] sessionKeys = KDF.deriveSessionKeys(sharedSecret);
        state.setSessionKeys(sessionKeys[0], sessionKeys[1]);

        System.out.println(Colors.success("Session keys derived"));
        System.out.println(Colors.info("Encryption key: " +
                ByteUtils.toHex(sessionKeys[0]).substring(0, 16) + "..."));

        state.transitionTo(HandshakeState.State.CLIENT_KEY_EXCHANGE_SENT);

        // Send client's DH public key
        return new TLSMessage(
                TLSMessage.MessageType.CLIENT_KEY_EXCHANGE,
                clientDHPublic.toByteArray()
        );
    }


     // Step 5: Process Server Finished and send Client Finished
    public TLSMessage handleServerFinished(TLSMessage serverFinished) {
        System.out.println("\n" + Colors.client("Received FINISHED from server"));

        if (serverFinished.getType() != TLSMessage.MessageType.FINISHED) {
            System.out.println(Colors.error("Expected FINISHED"));
            state.transitionTo(HandshakeState.State.ERROR);
            return null;
        }

        // Decrypt server's finished message
        byte[] decrypted = simpleDecrypt(
                serverFinished.getPayload(),
                state.getSessionEncryptionKey()
        );

        String message = new String(decrypted, StandardCharsets.UTF_8);
        System.out.println(Colors.info("Decrypted: " + message));

        // Verify session ID
        if (!message.contains(state.getSessionId())) {
            System.out.println(Colors.error("Session ID mismatch"));
            state.transitionTo(HandshakeState.State.ERROR);
            return null;
        }

        state.transitionTo(HandshakeState.State.FINISHED_RECEIVED);

        // Send client finished message
        System.out.println(Colors.client("Sending FINISHED"));

        String finishedMsg = "CLIENT_FINISHED:" + state.getSessionId();
        byte[] encryptedFinished = simpleEncrypt(
                finishedMsg.getBytes(StandardCharsets.UTF_8),
                state.getSessionEncryptionKey()
        );

        state.transitionTo(HandshakeState.State.HANDSHAKE_COMPLETE);
        System.out.println(Colors.success("Handshake complete"));

        return new TLSMessage(
                TLSMessage.MessageType.FINISHED,
                encryptedFinished
        );
    }


     // Send encrypted application data
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


    // Parse server certificate to extract credentials
    private void parseCertificate(byte[] certData) {
        int offset = 0;

        // Parse RSA public key (e)
        int eLen = bytesToInt(certData, offset);
        offset += 4;
        byte[] eBytes = new byte[eLen];
        System.arraycopy(certData, offset, eBytes, 0, eLen);
        offset += eLen;
        BigInteger e = new BigInteger(eBytes);

        // Parse RSA public key (n)
        int nLen = bytesToInt(certData, offset);
        offset += 4;
        byte[] nBytes = new byte[nLen];
        System.arraycopy(certData, offset, nBytes, 0, nLen);
        offset += nLen;
        BigInteger n = new BigInteger(nBytes);

        RSA.PublicKey serverPublicKey = new RSA.PublicKey(e, n);
        state.setServerPublicKey(serverPublicKey);

        System.out.println(Colors.info("Server RSA public key received"));

        // Parse DH parameters (p)
        int pLen = bytesToInt(certData, offset);
        offset += 4;
        byte[] pBytes = new byte[pLen];
        System.arraycopy(certData, offset, pBytes, 0, pLen);
        offset += pLen;
        BigInteger p = new BigInteger(pBytes);

        // Parse DH parameters (g)
        int gLen = bytesToInt(certData, offset);
        offset += 4;
        byte[] gBytes = new byte[gLen];
        System.arraycopy(certData, offset, gBytes, 0, gLen);
        offset += gLen;
        BigInteger g = new BigInteger(gBytes);

        DiffieHellman.DHParameters dhParams = new DiffieHellman.DHParameters(p, g);
        state.setDhParameters(dhParams);

        System.out.println(Colors.info("DH parameters received"));

        // Parse server's DH public key
        int serverDHLen = bytesToInt(certData, offset);
        offset += 4;
        byte[] serverDHBytes = new byte[serverDHLen];
        System.arraycopy(certData, offset, serverDHBytes, 0, serverDHLen);
        BigInteger serverDHPublic = new BigInteger(serverDHBytes);

        state.setServerDHPublic(serverDHPublic);
        System.out.println(Colors.info("Server DH public key received"));
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


    // Convert byte array to int
    private int bytesToInt(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xFF) << 24) |
                ((bytes[offset + 1] & 0xFF) << 16) |
                ((bytes[offset + 2] & 0xFF) << 8) |
                (bytes[offset + 3] & 0xFF);
    }
}