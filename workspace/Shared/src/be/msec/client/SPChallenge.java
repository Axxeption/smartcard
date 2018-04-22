package be.msec.client;

import java.io.Serializable;
import java.util.Arrays;

public class SPChallenge implements Serializable{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private byte[] challengeBytes;
	private byte[] rndBytes;
	private byte[] nameBytes;
	

	public SPChallenge( byte[] rndBytes,byte[] challengeBytes, byte[] nameBytes) {
		super();
		this.challengeBytes = challengeBytes;	//32bytes
		this.rndBytes = rndBytes;				//64bytes
		this.nameBytes = nameBytes;
	}

	public byte[] getRndBytes() {
		return rndBytes;
	}

	public void setRndBytes(byte[] rndBytes) {
		this.rndBytes = rndBytes;
	}

	public byte[] getNameBytes() {
		return nameBytes;
	}

	public void setNameBytes(byte[] nameBytes) {
		this.nameBytes = nameBytes;
	}

	public byte[] getChallengeBytes() {
		return challengeBytes;
	}

	public void setChallengeBytes(byte[] challengeBytes) {
		this.challengeBytes = challengeBytes;
	}

	@Override
	public String toString() {
		return "Challenge [challengeBytes=" + bytesToDec(challengeBytes) + ", rndBytes="
				+ bytesToDec(rndBytes) + ", nameBytes=" + bytesToDec(nameBytes) + "]";
	}
	
	public String bytesToDec(byte[] barray) {
		String str = "";
		for (byte b : barray)
			str += (int) b + ", ";
		return str;
	}
	

}
