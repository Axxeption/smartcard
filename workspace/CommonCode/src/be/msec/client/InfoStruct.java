package be.msec.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class InfoStruct implements Serializable {
	
	/**
	 * Parse object into byte[]
	 * @return
	 */
	public byte [] getBytes() {
		try{
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(baos);
			System.out.println(this);
			oos.writeObject(this);
			return baos.toByteArray();
		}catch (IOException ioe){
			System.err.println(ioe.getLocalizedMessage());
			return null;
		}
	}

}
