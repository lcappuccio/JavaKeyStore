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
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Enumeration;

public class KeyStoreUtils {

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
	 * @throws Exception
	 */
	public KeyStoreUtils(String keyStorePath, byte[] keyStorePasswd)
			throws Exception {
		this.certificates = new ArrayList();
		this.certificateAliases = new ArrayList();
		this.publicKeys = new ArrayList();
		// Initialize keyStore
		openKeyStore(keyStorePath, new String(keyStorePasswd));
		// Load certificates
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
	}

	/**
	 *
	 * @param keyStorePath
	 * @param keyStorePasswd
	 * @throws Exception
	 */
	// TODO Pass keyStorePasswd as CharArray directly
	private void openKeyStore(String keyStorePath, String keyStorePasswd)
			throws Exception {
		keyStore = KeyStore.getInstance("jks");
		FileInputStream inputStream = new FileInputStream(new File(keyStorePath));
		keyStore.load(inputStream, keyStorePasswd.toCharArray());
	}

	/**
	 *
	 * @param keyAlias
	 * @param keyPasswd
	 * @throws Exception
	 */
	public void useKey(String keyAlias, String keyPasswd) throws Exception {
		privateKey = (PrivateKey) keyStore.getKey(keyAlias, keyPasswd.toCharArray());
	}

	/**
	 *
	 * @param document
	 * @throws Exception
	 */
	public void signDocument(String document) throws Exception {
		signature.initSign(privateKey);
		signature.update(document.getBytes());
		byteSignature = signature.sign();
	}

	/**
	 *
	 * @param document
	 * @param documentSignature
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	// TODO Add check for document and signedDocument size
	// TODO Try to validate against every key of a keystore
	// TODO Implement validation against certificate
	public Boolean verifySign(String document, byte[] documentSignature) throws Exception {
		signature.initVerify(publicKeys.get(0));
		signature.update(document.getBytes());
		return signature.verify(documentSignature);
	}

	/**
	 *
	 * @return
	 */
	public byte[] getDocumentSignature() {
		return byteSignature;
	}

}
