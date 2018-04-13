package be.msec.client;

import java.io.Serializable;
import java.security.PublicKey;

public class MessageToAuthCard implements Serializable {
	private byte[] encryptedMessage;
	
	public MessageToAuthCard(byte[] message) {
		super();
		this.encryptedMessage = message;
	}

	public byte[] getMessage() {
		return encryptedMessage;
	}
	
	
	

}
