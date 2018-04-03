package be.msec.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class OwnCertificate implements Serializable{
	
	private InfoStruct infoStruct;
	private byte[] signatureBytes;
	public OwnCertificate() {
	}
	
	public OwnCertificate(InfoStruct infoStruct) {
		this.infoStruct = infoStruct;
	}
	
	
	public void signCertificate(PrivateKey privateKey) {
		try {
			byte [] data = infoStruct.getBytes();
			Signature sig = Signature.getInstance("SHA1WithRSA");
			sig.initSign(privateKey);
			sig.update(data);
			signatureBytes = sig.sign();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public boolean verifySignature(PublicKey publicKey) {
		Signature sig;
		try {
			sig = Signature.getInstance("SHA1WithRSA");
			byte [] data = infoStruct.getBytes();
			
			sig.initVerify(publicKey);
	        sig.update(data);
	        return sig.verify(signatureBytes);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
		
	}	

}
