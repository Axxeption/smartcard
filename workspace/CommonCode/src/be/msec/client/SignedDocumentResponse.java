package be.msec.client;

import java.io.Serializable;

public class SignedDocumentResponse implements Serializable{

	private byte[] response;
	private byte[] unsignedDocument;
	private byte[] documentHash;
	
	public byte[] getResponse() {
		return response;
	}

	public void setResponse(byte[] response) {
		this.response = response;
	}

	public byte[] getUnsignedDocument() {
		return unsignedDocument;
	}

	public void setUnsignedDocument(byte[] unsignedDocument) {
		this.unsignedDocument = unsignedDocument;
	}

	public byte[] getDocumentHash() {
		return documentHash;
	}

	public void setDocumentHash(byte[] documentHash) {
		this.documentHash = documentHash;
	}

	
	
	public SignedDocumentResponse(byte[] response, byte[] unsignedDocument, byte[] documentHash) {
		super();
		this.response = response;
		this.unsignedDocument = unsignedDocument;
		this.documentHash = documentHash;
	}
	
	
}
