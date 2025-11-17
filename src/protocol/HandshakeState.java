package protocol;

import java.math.BigInteger;
import crypto.RSA;
import crypto.DiffieHellman;

 // Handshake State Machine
 // Tracks the state of TLS handshake for both client and server
public class HandshakeState {

    public enum State {
        IDLE,
        CLIENT_HELLO_SENT,
        SERVER_HELLO_RECEIVED,
        SERVER_CERT_RECEIVED,
        CLIENT_KEY_EXCHANGE_SENT,
        FINISHED_SENT,
        FINISHED_RECEIVED,
        HANDSHAKE_COMPLETE,
        ERROR
    }

    private State currentState;

    // Cryptographic materials
    private RSA.KeyPair serverKeyPair;   // Server's RSA keys
    private RSA.PublicKey serverPublicKey;  // For client

    private DiffieHellman.DHParameters dhParameters; // DH parameters
    private BigInteger clientDHPublic;              // Client's DH public key
    private BigInteger serverDHPublic;              // Server's DH public key
    private BigInteger sharedSecret;                // Computed shared secret

    private byte[] sessionEncryptionKey;            // Derived encryption key
    private byte[] sessionMacKey;                   // Derived MAC key

    // Random nonces for replay protection
    private byte[] clientRandom;
    private byte[] serverRandom;

    // Session identifier
    private String sessionId;

    public HandshakeState() {
        this.currentState = State.IDLE;
    }

    // State transitions
    public void transitionTo(State newState) {
        System.out.println("  State: " + currentState + " → " + newState);
        this.currentState = newState;
    }

    public void setServerKeyPair(RSA.KeyPair keyPair) {
        this.serverKeyPair = keyPair;
    }

    public RSA.KeyPair getServerKeyPair() {
        return serverKeyPair;
    }

    public void setServerPublicKey(RSA.PublicKey publicKey) {
        this.serverPublicKey = publicKey;
    }

    public void setDhParameters(DiffieHellman.DHParameters params) {
        this.dhParameters = params;
    }

    public DiffieHellman.DHParameters getDhParameters() {
        return dhParameters;
    }

    public void setClientDHPublic(BigInteger clientPublic) {
        this.clientDHPublic = clientPublic;
    }

    public void setServerDHPublic(BigInteger serverPublic) {
        this.serverDHPublic = serverPublic;
    }

    public BigInteger getServerDHPublic() {
        return serverDHPublic;
    }

    public void setSharedSecret(BigInteger secret) {
        this.sharedSecret = secret;
    }

    public void setSessionKeys(byte[] encKey, byte[] macKey) {
        this.sessionEncryptionKey = encKey;
        this.sessionMacKey = macKey;
    }

    public byte[] getSessionEncryptionKey() {
        return sessionEncryptionKey;
    }

    public void setClientRandom(byte[] random) {
        this.clientRandom = random;
    }

    public byte[] getClientRandom() {
        return clientRandom;
    }

    public void setServerRandom(byte[] random) {
        this.serverRandom = random;
    }

    public byte[] getServerRandom() {
        return serverRandom;
    }

    public void setSessionId(String id) {
        this.sessionId = id;
    }

    public String getSessionId() {
        return sessionId;
    }

    public boolean isHandshakeComplete() {
        return currentState == State.HANDSHAKE_COMPLETE;
    }

    @Override
    public String toString() {
        return "HandshakeState{" +
                "state=" + currentState +
                ", sessionId='" + sessionId + '\'' +
                ", hasSharedSecret=" + (sharedSecret != null) +
                ", hasSessionKeys=" + (sessionEncryptionKey != null) +
                '}';
    }
}