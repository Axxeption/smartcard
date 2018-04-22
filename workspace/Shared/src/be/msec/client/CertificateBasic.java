package be.msec.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class CertificateBasic implements Serializable {
	
	private byte[] bytes;
	
	
	
	/**
	 * Parse object into byte[]
	 * @return
	 */
	
	public byte [] getBytes() {
//		try{
//			ByteArrayOutputStream baos = new ByteArrayOutputStream();
//			ObjectOutputStream oos = new ObjectOutputStream(baos);
//			System.out.println(this);
//			oos.writeObject(this);
//			return baos.toByteArray();
//		}catch (IOException ioe){
//			System.err.println(ioe.getLocalizedMessage());
//			return null;
//		}
		
		return this.bytes;
	}
	
	public void setBytes(byte[] bytes) {
		this.bytes = new byte[bytes.length];
		System.arraycopy(bytes, 0, this.bytes, 0, bytes.length);
	}

}
