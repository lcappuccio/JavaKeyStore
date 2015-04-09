/**
 * $Id$
 *
 * @author lcappuccio
 * @date 08/04/2015 12:20
 *
 * Copyright (C) 2015 Scytl Secure Electronic Voting SA
 *
 * All rights reserved.
 *
 */
package com.scytl.javakeystore.pojo;

import com.scytl.javakeystore.exception.SignatureUtilException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;

public class SignatureUtil {

	private KeyStore keyStore;
	private final Signature signature;
	private final ArrayList<Certificate> certificates;
	private final ArrayList<PublicKey> publicKeys;
	private PrivateKey privateKey;
	private final ArrayList<String> certificateAliases;
	private byte[] byteSignature;
	private final static String algorithm = "SHA256withRSA";
	private final static int signatureSize = 256;

	/**
	 *
	 * @param keyStorePath
	 * @param keyStorePasswd
	 * @throws com.scytl.javakeystore.exception.SignatureUtilException
	 */
	public SignatureUtil(String keyStorePath, byte[] keyStorePasswd) throws com.scytl.javakeystore.exception.SignatureUtilException {
		this.certificates = new ArrayList();
		this.certificateAliases = new ArrayList();
		this.publicKeys = new ArrayList();
		// Initialize keyStore
		openKeyStore(keyStorePath, new String(keyStorePasswd));
		// Load certificates
		try {
			Enumeration enumeration = keyStore.aliases();
			while (enumeration.hasMoreElements()) {
				String alias = (String) enumeration.nextElement();
				certificateAliases.add(alias);
				certificates.add(keyStore.getCertificate(alias));
			}
			// Initialize signature and load certificates/public keys
			signature = Signature.getInstance(algorithm);
			for (Certificate certificate : certificates) {
				publicKeys.add(certificate.getPublicKey());
			}
		} catch (KeyStoreException | NoSuchAlgorithmException ex) {
			throw new com.scytl.javakeystore.exception.SignatureUtilException(ex.getMessage());
		}
	}

	/**
	 *
	 * @param keyStorePath
	 * @param keyStorePasswd
	 */
	private void openKeyStore(String keyStorePath, String keyStorePasswd) throws com.scytl.javakeystore.exception.SignatureUtilException {
		try {
			keyStore = KeyStore.getInstance("jks");
			FileInputStream inputStream = new FileInputStream(new File(keyStorePath));
			keyStore.load(inputStream, keyStorePasswd.toCharArray());
		} catch (NoSuchAlgorithmException | CertificateException | KeyStoreException | IOException ex) {
			throw new com.scytl.javakeystore.exception.SignatureUtilException(ex.getMessage());
		}
	}

	/**
	 *
	 * @param keyAlias
	 * @param keyPasswd
	 * @throws com.scytl.javakeystore.exception.SignatureUtilException
	 */
	public void useKey(String keyAlias, char[] keyPasswd) throws com.scytl.javakeystore.exception.SignatureUtilException {
		try {
			privateKey = (PrivateKey) keyStore.getKey(keyAlias, keyPasswd);
			if (privateKey == null) {
				throw new SignatureUtilException("No such key in keystore");
			}
		} catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
			throw new com.scytl.javakeystore.exception.SignatureUtilException(ex.getMessage());
		}
	}

	/**
	 *
	 * @param document
	 * @throws com.scytl.javakeystore.exception.SignatureUtilException
	 */
	public void signDocument(String document) throws com.scytl.javakeystore.exception.SignatureUtilException {
		if (document == null) {
			throw new com.scytl.javakeystore.exception.SignatureUtilException("Trying to sign a null document");
		}
		try {
			signature.initSign(privateKey);
			signature.update(document.getBytes());
			byteSignature = signature.sign();
		} catch (InvalidKeyException | SignatureException ex) {
			throw new com.scytl.javakeystore.exception.SignatureUtilException(ex.getMessage());
		}
	}

	/**
	 *
	 * @param document
	 * @param documentSignature
	 * @return
	 * @throws com.scytl.javakeystore.exception.SignatureUtilException
	 */
	// TODO Try to validate against every key of a keystore
	// TODO Implement validation against certificate
	public Boolean verifySign(String document, byte[] documentSignature) throws com.scytl.javakeystore.exception.SignatureUtilException {
		if (documentSignature.length != signatureSize) {
			throw new com.scytl.javakeystore.exception.SignatureUtilException("Invalid signature size: " + documentSignature.length);
		}
		try {
			signature.initVerify(publicKeys.get(0));
			signature.update(document.getBytes());
			return signature.verify(documentSignature);
		} catch (InvalidKeyException | SignatureException ex) {
			throw new com.scytl.javakeystore.exception.SignatureUtilException(ex.getMessage());
		}
	}

	/**
	 *
	 * @return
	 */
	public byte[] getDocumentSignature() {
		return byteSignature;
	}
}
