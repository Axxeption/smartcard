package be.msec.client;

import java.io.Serializable;
import java.security.PublicKey;

public class CardChallenge implements Serializable {
	private byte[] encryptedMessage;
	
	public CardChallenge(byte[] message) {
		super();
		this.encryptedMessage = message;
	}

	public byte[] getMessage() {
		return encryptedMessage;
	}
	
	
	

}
