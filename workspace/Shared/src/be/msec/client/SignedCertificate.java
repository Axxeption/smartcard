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

public class SignedCertificate implements Serializable{
	
	private CertificateBasic infoStruct;
	private byte[] signatureBytes;
	
	public byte[] getSignatureBytes() {
		return signatureBytes;
	}
	
	public CertificateBasic getCertificateBasic() {
		return infoStruct;
	}

	public SignedCertificate() {
	}
	
	public SignedCertificate(CertificateBasic infoStruct) {
		this.infoStruct = infoStruct;
	}
	
	public byte[] getBytes() {
		return infoStruct.getBytes();
	}
	
	public void signCertificate(PrivateKey privateKey) {
		try {
			byte [] data = infoStruct.getBytes();
			//System.out.println("bytes to sign:  "+ bytesToDec(data));
			Signature sig = Signature.getInstance("SHA1WithRSA");
			sig.initSign(privateKey);
			sig.update(data);
			signatureBytes = sig.sign();
			//System.out.println("signed bytes: "+bytesToDec(signatureBytes));
		} catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
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
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		return false;
		
	}	
	
	//utility
	public String bytesToDec(byte[] barray) {
		String str = "";
		for (byte b : barray)
			str += (int) b + ", ";
		return str;
	}

}
