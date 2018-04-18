package be.msec.client;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Calendar;

public class CertificateServiceProvider extends CertificateBasic implements Serializable {
	private PublicKey publicKey;
	private String name;
	private long validTime;
	private ServiceProviderType type;
	private byte[] publicKeyExpBytes;
	private byte[] publicKeyModBytes;
	private byte[] maxRight;
	
	public CertificateServiceProvider(PublicKey publicKey, String name, short max) {
		super();
		this.publicKey = publicKey;
		this.maxRight = toBytes(max);
		RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
		this.publicKeyExpBytes = rsaPublicKey.getPublicExponent().toByteArray();
		this.publicKeyModBytes = rsaPublicKey.getModulus().toByteArray();
		
		this.name = name;
		Calendar cal = Calendar.getInstance();
		Long time = cal.getTimeInMillis();
		this.validTime = time + 31556952000L; // default: +1 year more than current time...
		this.type = ServiceProviderType.DEFAULT; // default type is default
		
		byte[] nameBytes = this.name.getBytes();
		byte[] validTimeBytes = longToBytes(this.validTime);
		byte[] certificateBytes = new byte[publicKeyExpBytes.length + publicKeyModBytes.length + nameBytes.length + validTimeBytes.length +2];
		
		System.arraycopy(this.publicKeyExpBytes, 0, certificateBytes, 0, this.publicKeyExpBytes.length);
		System.arraycopy(this.publicKeyModBytes, 0, certificateBytes, this.publicKeyExpBytes.length, this.publicKeyModBytes.length);
		System.arraycopy(validTimeBytes, 0, certificateBytes, this.publicKeyExpBytes.length + this.publicKeyModBytes.length  , validTimeBytes.length);
		System.arraycopy(maxRight, 0, certificateBytes, this.publicKeyExpBytes.length + this.publicKeyModBytes.length + validTimeBytes.length , maxRight.length);
		System.arraycopy(nameBytes, 0, certificateBytes, this.publicKeyExpBytes.length + this.publicKeyModBytes.length + validTimeBytes.length + 2, nameBytes.length);
		
		super.setBytes(certificateBytes);
//		System.out.println(this.name);
//		System.out.println("exp length " + publicKeyExpBytes.length + "  "+ bytesToDec(publicKeyExpBytes));
//		System.out.println("mod length " + publicKeyModBytes.length + "   " + bytesToDec(publicKeyModBytes));
//		System.out.println("validbyteslength  "+validTimeBytes.length);
//		System.out.println("name length "+nameBytes.length + "  "+ nameBytes.toString());
//		System.out.println(certificateBytes.length+ "cert bytes beforesend: "+bytesToDec(certificateBytes));
		
		
		//System.out.println("the maxrigh byte array: " + maxRight + " has a length of: " + maxRight.length);
	}
	
	public byte[] toBytes(short s) {
	    return new byte[]{(byte)(s & 0x00FF),(byte)((s & 0xFF00)>>8)};
	}
	
	
	public byte[] getBytesForSC() {
		byte[] nameBytes = this.name.getBytes();
		byte[] validTimeBytes = longToBytes(this.validTime);
		byte[] certificateBytes = new byte[publicKeyExpBytes.length + publicKeyModBytes.length + nameBytes.length + validTimeBytes.length ];

		System.arraycopy(this.publicKeyExpBytes, 0, certificateBytes, 0, this.publicKeyExpBytes.length);
		System.arraycopy(this.publicKeyModBytes, 0, certificateBytes, this.publicKeyExpBytes.length, this.publicKeyModBytes.length);
		System.arraycopy(validTimeBytes, 0, certificateBytes, this.publicKeyExpBytes.length + this.publicKeyModBytes.length  , validTimeBytes.length);
		System.arraycopy(maxRight, 0, certificateBytes, this.publicKeyExpBytes.length + this.publicKeyModBytes.length + validTimeBytes.length , maxRight.length);
		System.arraycopy(nameBytes, 0, certificateBytes, this.publicKeyExpBytes.length + this.publicKeyModBytes.length + validTimeBytes.length + 2, nameBytes.length);
		return certificateBytes;
	}
	
	public byte[] getValidTimeBytes() {
		return longToBytes(validTime);
	}

	public ServiceProviderType getType() {
		return type;
	}
	
	public byte[] longToBytes(long x) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(x);
		return buffer.array();
	}

	public void setType(ServiceProviderType type) {
		this.type = type;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}
	
	public byte[] getPublicKeyByte() {
		return publicKey.getEncoded();
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}


	public long getValidTime() {
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
	
	//utility
	public String bytesToDec(byte[] barray) {
		String str = "";
		for (byte b : barray)
			str += (int) b + ", ";
		return str;
	}
	
}
