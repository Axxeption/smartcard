package be.msec.client;

import java.io.Serializable;

public class AuthenticateToSPResponse implements Serializable {
	private byte[] encryptedMessage;
	
	public AuthenticateToSPResponse (byte[] message) {
		super();
		this.encryptedMessage = message;
	}

	public byte[] getMessage() {
		return encryptedMessage;
	}
	
	
	

}
