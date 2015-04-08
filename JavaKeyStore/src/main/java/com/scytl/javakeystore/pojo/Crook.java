/**
 * $Id$
 *
 * @author lcappuccio
 * @date 08/04/2015 09:31
 *
 * Copyright (C) 2015 Scytl Secure Electronic Voting SA
 *
 * All rights reserved.
 *
 */
package com.scytl.javakeystore.pojo;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Crook {

	private static final Logger logger = Logger.getLogger(Crook.class.getCanonicalName());

	private File documentFile;
	private KeyStore keystore;
	private RCPKeyStore rcpKeyStore;
	private Certificate cert;
	private String clearText, signedText, documentPath;
	private Signature signature;

	public Crook(String documentPath, String keystorePath) throws InvalidKeyException, SignatureException, UnsupportedEncodingException {
		this.documentPath = documentPath;
		readFile();
		try {
			rcpKeyStore = new RCPKeyStore(keystorePath, "rcpxrcpx", "rcpx");
		} catch (KeyStoreException ex) {
			logger.log(Level.SEVERE, ex.getMessage());
		}
		keystore = rcpKeyStore.openKeyStore();
		signedText = signDocument();
	}

	public String signDocument() throws InvalidKeyException, SignatureException, UnsupportedEncodingException {
		try {
			// TODO Magical string for certificate alias
			cert = keystore.getCertificate("client");
		} catch (KeyStoreException ex) {
			logger.log(Level.SEVERE, ex.getMessage());
		}
		try {
			signature = Signature.getInstance("SHA256withRSA");
			signature.initSign((PrivateKey) rcpKeyStore.getKey());
			signature.update(clearText.getBytes());
		} catch (NoSuchAlgorithmException ex) {
			logger.log(Level.SEVERE, ex.getMessage());
		}
		return new String(signature.sign(), "UTF8");
	}

	private void readFile() {
		BufferedReader br = null;
		try {
			br = new BufferedReader(new FileReader(documentPath));
			try {
				StringBuilder sb = new StringBuilder();
				String line = br.readLine();

				while (line != null) {
					sb.append(line);
					sb.append(System.lineSeparator());
					line = br.readLine();
				}
				clearText = sb.toString();
			} catch (IOException ex) {
				Logger.getLogger(Crook.class.getName()).log(Level.SEVERE, null, ex);
			} finally {
				try {
					br.close();
				} catch (IOException ex) {
					Logger.getLogger(Crook.class.getName()).log(Level.SEVERE, null, ex);
				}
			}
		} catch (FileNotFoundException ex) {
			Logger.getLogger(Crook.class.getName()).log(Level.SEVERE, null, ex);
		} finally {
			try {
				br.close();
			} catch (IOException ex) {
				Logger.getLogger(Crook.class.getName()).log(Level.SEVERE, null, ex);
			}
		}
	}

	public void verifySign() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		signature = Signature.getInstance("SHA256withRSA");
		PublicKey publickey = cert.getPublicKey();
		System.out.println("Algorithm for key: " + publickey.getAlgorithm());
		signature.initVerify(publickey);
		signature.update(clearText.getBytes());
		signature.verify(clearText.getBytes());
	}

	public String getClearText() {
		return clearText;
	}

	public String getSignedText() {
		return signedText;
	}
}
