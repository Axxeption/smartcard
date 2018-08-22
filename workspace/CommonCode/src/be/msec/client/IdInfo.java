package be.msec.client;

import java.io.Serializable;

public class IdInfo implements Serializable{
	//evt nog signature apart toevoegen

	private static final long serialVersionUID = 1L;
	private String info;
	
	private byte[] IDFile;
	public IdInfo(byte[] IDFile) {
		this.IDFile = IDFile;
	}
	

	public byte[] getInfo() {
		return this.IDFile;
	}
}
