package be.msec.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.PublicKey;
import java.util.Date;

public class TimeInfoStruct extends InfoStruct {
	private byte [] signedData;
	private byte[] date;
	
	public TimeInfoStruct(byte [] signedData, byte[] dataToSend) {
		super();
		this.signedData = signedData;
		this.date = dataToSend;
	}


	public byte[] getSignedData() {
		return signedData;
	}

	public void setSignedData(byte[] signedData) {
		this.signedData = signedData;
	}

	public byte[] getDate() {
		return date;
	}

	public void setDate(byte[] date) {
		this.date = date;
	}

}
