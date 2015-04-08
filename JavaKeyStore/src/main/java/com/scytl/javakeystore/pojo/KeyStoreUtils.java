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
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import sun.misc.BASE64Encoder;

public class KeyStoreUtils {

	private KeyStore keyStore;
	private Signature signature;
	private final ArrayList<Certificate> certificates;
	private final ArrayList<PublicKey> publicKeys;
	private final ArrayList<PrivateKey> privateKeys;
	private final ArrayList<String> certificateAliases;

	/**
	 *
	 * @param keyStorePath
	 * @param keyStorePasswd
	 * @throws Exception
	 */
	public KeyStoreUtils(String keyStorePath, String keyStorePasswd)
			throws Exception {
		this.certificates = new ArrayList();
		this.certificateAliases = new ArrayList();
		this.publicKeys = new ArrayList();
		this.privateKeys = new ArrayList();
		// Initialize keyStore
		openKeyStore(keyStorePath, keyStorePasswd);
		// Load certificates
		Enumeration enumeration = keyStore.aliases();
		while (enumeration.hasMoreElements()) {
			String alias = (String) enumeration.nextElement();
			certificateAliases.add(alias);
			certificates.add(keyStore.getCertificate(alias));
		}
		// Initialize signature and load public keys
		signature = Signature.getInstance("SHA512withRSA");
		for (Certificate certificate : certificates) {
			publicKeys.add(certificate.getPublicKey());
		}
	}

	/**
	 *
	 * @param keyStorePath
	 * @param keyStorePasswd
	 * @return
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
	 * @return
	 * @throws Exception
	 */
	public PrivateKey getPrivateKey(String keyAlias, String keyPasswd) throws Exception {
		PrivateKey key = (PrivateKey) keyStore.getKey(keyAlias, keyPasswd.toCharArray());
		return key;
	}

	/**
	 *
	 * @param key
	 * @return
	 */
	// TODO Don't save key as BASE64 encode
	public String getDecodedPrivateKey(PrivateKey key) {
		return new BASE64Encoder().encode(key.getEncoded());
	}

	/**
	 *
	 * @param document
	 * @param privateKey
	 * @return
	 * @throws Exception
	 */
	public byte[] getSignature(String document, PrivateKey privateKey) throws Exception {
		signature.initSign(privateKey);
		signature.update(document.getBytes());
		return signature.sign();
	}

	/**
	 *
	 * @param document
	 * @param documentSignature
	 * @param publicKey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	// TODO Add check for document and signedDocument size
	// TODO Try to validate against every key of a keystore
	// TODO Implement validation against certificate
	public Boolean verifySign(String document, byte[] documentSignature, PublicKey publicKey) throws Exception {
		signature.initVerify(publicKey);
		signature.update(document.getBytes());
		return signature.verify(documentSignature);
	}

	public List<PublicKey> getPublicKeys() {
		return publicKeys;
	}

	public ArrayList<String> getCertificateAliases() {
		return certificateAliases;
	}

	public Certificate getCertificateForAlias(String alias) throws KeyStoreException {
		return keyStore.getCertificate(alias);
	}

}
