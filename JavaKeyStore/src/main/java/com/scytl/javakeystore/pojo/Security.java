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

public class Security {

	private KeyStore keyStore;
	private final Signature signature;
	private final ArrayList<Certificate> certificates;
	private final ArrayList<PublicKey> publicKeys;
	private PrivateKey privateKey;
	private final ArrayList<String> certificateAliases;
	private byte[] byteSignature;

	/**
	 *
	 * @param keyStorePath
	 * @param keyStorePasswd
	 */
	public Security(String keyStorePath, byte[] keyStorePasswd) {
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
			signature = Signature.getInstance("SHA512withRSA");
			for (Certificate certificate : certificates) {
				publicKeys.add(certificate.getPublicKey());
			}
		} catch (KeyStoreException | NoSuchAlgorithmException ex) {
			throw new SecurityException(ex.getMessage());
		}
	}

	/**
	 *
	 * @param keyStorePath
	 * @param keyStorePasswd
	 */
	private void openKeyStore(String keyStorePath, String keyStorePasswd) {
		try {
			keyStore = KeyStore.getInstance("jks");
			FileInputStream inputStream = new FileInputStream(new File(keyStorePath));
			keyStore.load(inputStream, keyStorePasswd.toCharArray());
		} catch (NoSuchAlgorithmException | CertificateException | KeyStoreException | IOException ex) {
			throw new SecurityException(ex.getMessage());
		}
	}

	/**
	 *
	 * @param keyAlias
	 * @param keyPasswd
	 */
	public void useKey(String keyAlias, char[] keyPasswd) {
		try {
			privateKey = (PrivateKey) keyStore.getKey(keyAlias, keyPasswd);
		} catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
			throw new SecurityException(ex.getMessage());
		}
	}

	/**
	 *
	 * @param document
	 */
	public void signDocument(String document) {
		try {
			signature.initSign(privateKey);
			signature.update(document.getBytes());
			byteSignature = signature.sign();
		} catch (InvalidKeyException | SignatureException ex) {
			throw new SecurityException(ex.getMessage());
		}
	}

	/**
	 *
	 * @param document
	 * @param documentSignature
	 * @return
	 */
	// TODO Add check for document and signedDocument size
	// TODO Try to validate against every key of a keystore
	// TODO Implement validation against certificate
	public Boolean verifySign(String document, byte[] documentSignature) {
		try {
			signature.initVerify(publicKeys.get(0));
			signature.update(document.getBytes());
			return signature.verify(documentSignature);
		} catch (InvalidKeyException | SignatureException ex) {
			throw new SecurityException(ex.getMessage());
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
