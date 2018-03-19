package be.msec.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.PublicKey;

public class OwnCertificate implements Serializable{
	
	private PublicKey publicKey = null;
	private String issuer;
	private int validTime;
	public OwnCertificate() {
	}
	
	public OwnCertificate(PublicKey publicKey , String issuer, int validTime) {
		this.publicKey = publicKey;
		this.issuer = issuer;
		this.validTime = validTime;
	}
	
	public byte [] getBytes() {
		try{
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(baos);
			oos.writeObject(this);
			return baos.toByteArray();
		}catch (IOException ioe){
			System.err.println(ioe.getLocalizedMessage());
			return null;
		}
	}

	@Override
	public String toString() {
		return "OwnCertificate [publicKey=" + publicKey + ", issuer=" + issuer + ", validTime=" + validTime + "]";
	}
	
	

}
