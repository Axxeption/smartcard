package be.msec.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ServiceProviderInfoStruct implements InfoStruct, Serializable {
	private PublicKey publicKey;
	private String name;
	private int validTime;
	private ServiceProviderType type;
	
	public ServiceProviderInfoStruct(PublicKey publicKey, String name) {
		super();
		this.publicKey = publicKey;
		this.name = name;
		this.validTime = 24*60*60; // default 24h
		this.type = ServiceProviderType.DEFAULT; // default type is default
	}
	

	public ServiceProviderType getType() {
		return type;
	}

	public void setType(ServiceProviderType type) {
		this.type = type;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}


	public int getValidTime() {
		return validTime;
	}

	public void setValidTime(int validTime) {
		this.validTime = validTime;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
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
