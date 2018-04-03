package be.msec.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ServiceProviderInfoStruct implements InfoStruct, Serializable {
	private PublicKey publicKey;
	private String issuer;
	private int validTime;
	
	public ServiceProviderInfoStruct(PublicKey publicKey, String issuer, int validTime) {
		super();
		this.publicKey = publicKey;
		this.issuer = issuer;
		this.validTime = validTime;
	}
	
	public byte [] getBytes() {
		try{
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(baos);
			oos.writeObject(this);
			System.out.println("bytes from ServiceProviderInfoStruct");
			return baos.toByteArray();
		}catch (IOException ioe){
			System.err.println(ioe.getLocalizedMessage());
			return null;
		}
	}
}
