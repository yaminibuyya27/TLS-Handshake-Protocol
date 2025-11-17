package protocol;

import utils.ByteUtils;
import java.io.Serializable;


// TLS Message Format it represents different message types in the TLS handshake
public class TLSMessage implements Serializable {

     private static final long serialVersionUID = 1L;

    // Message types
    public enum MessageType {
        CLIENT_HELLO,
        SERVER_HELLO,
        SERVER_CERTIFICATE,
        CLIENT_KEY_EXCHANGE,
        FINISHED,
        APPLICATION_DATA,
        ERROR
    }

    private final MessageType type;
    private final byte[] payload;
    private final String textData;

    public TLSMessage(MessageType type, byte[] payload) {
        this.type = type;
        this.payload = payload;
        this.textData = null;
    }

    public TLSMessage(MessageType type, String textData) {
        this.type = type;
        this.textData = textData;
        this.payload = null;
    }

    public TLSMessage(MessageType type, byte[] payload, String textData) {
        this.type = type;
        this.payload = payload;
        this.textData = textData;
    }

    // Getters
    public MessageType getType() {
        return type;
    }

    public byte[] getPayload() {
        return payload;
    }

    public String getTextData() {
        return textData;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("TLSMessage{type=").append(type);

        if (payload != null) {
            sb.append(", payload=").append(ByteUtils.toHex(payload).substring(0,
                    Math.min(32, payload.length * 2))).append("...");
        }

        if (textData != null) {
            sb.append(", text='").append(textData).append("'");
        }

        sb.append("}");
        return sb.toString();
    }
}