package be.msec.client;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.util.Calendar;

public class CertificateServiceProvider extends CertificateBasic implements Serializable {
	private PublicKey publicKey;
	private String name;
	private long validTime;
	private ServiceProviderType type;
	
	public CertificateServiceProvider(PublicKey publicKey, String name) {
		super();
		this.publicKey = publicKey;
		this.name = name;
		Calendar cal = Calendar.getInstance();
		Long time = cal.getTimeInMillis();
		this.validTime = time + 31556952000L; // default: +1 year more than current time...
		this.type = ServiceProviderType.DEFAULT; // default type is default
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
}
