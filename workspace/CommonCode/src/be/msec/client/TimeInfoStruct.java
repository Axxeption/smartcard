package be.msec.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.PublicKey;
import java.util.Date;

public class TimeInfoStruct implements InfoStruct, Serializable {
	private byte [] signedData;
	private Date date;
	
	public TimeInfoStruct(byte [] signedData, Date date) {
		super();
		this.signedData = signedData;
		this.date = date;
	}
	
	
	public byte[] getSignedData() {
		return signedData;
	}



	public void setSignedData(byte[] signedData) {
		this.signedData = signedData;
	}



	public Date getDate() {
		return date;
	}



	public void setDate(Date date) {
		this.date = date;
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
