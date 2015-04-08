/**
 * $Id$
 *
 * @author lcappuccio
 * @date 07/04/2015 17:25
 *
 * Copyright (C) 2015 Scytl Secure Electronic Voting SA
 *
 * All rights reserved.
 *
 */
package com.scytl.javakeystore.main;

import com.scytl.javakeystore.pojo.KeyStoreUtils;
import com.scytl.javakeystore.pojo.ZipUtils;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.util.List;
import org.apache.commons.io.FileUtils;

public class Main {

	private static KeyStoreUtils keystore;
	private static ZipUtils zipUtil;

	public static void main(String[] args) throws Exception {
		String keyStorePath = "src/main/resources/client.jks";
		byte[] keyStorePasswd = "rcpxrcpx".getBytes();
		// TODO just pass alias, the key password and that's all

		// Create keystore
		keystore = new KeyStoreUtils(keyStorePath, keyStorePasswd);

		// Get public keys
		List<PublicKey> publicKeys = keystore.getPublicKeys();
		for (PublicKey publicKey : publicKeys) {
			System.out.println("Public key algorithms in keystore: " + publicKey.getAlgorithm());
		}

		// Select private key
		String keyAlias = "client";
		String keyPasswd = "rcpx";
		keystore.useKey(keyAlias, keyPasswd);

		// Read a document
		String loremIpsum = readTextFile("src/main/resources/lorem_ipsum.txt");
		System.out.println("\n*** CLEAR TEXT DOCUMENT ***");
		System.out.println(loremIpsum);

		// Sign the document with the preselected key
		keystore.signDocument(loremIpsum);

//		// Verify signature
//		System.out.println("\n*** VERIFY SIGNATURE ***");
//		System.out.println("Document signature is valid: " + keystore.verifySign(loremIpsum, documentSignature, publicKeys.get(0)));
//		assert (keystore.verifySign(loremIpsum, documentSignature, publicKeys.get(0)));
//		// Negative case
//		System.out.println("Falsified document signature is valid: " + keystore.verifySign("Falsified document", documentSignature, publicKeys.get(0)));
//		assert (keystore.verifySign("Falsified document", documentSignature, publicKeys.get(0)) == false);
//
//		// Save document and signature to ZIP
//		zipUtil = new ZipUtils("output");
//		zipUtil.addFileToZip(new File("src/main/resources/lorem_ipsum.txt"));
//		File signatureFile = new File("target/lorem_ipsum.txt.sig");
//		writeTextToFile(Arrays.toString(documentSignature), signatureFile);
//		zipUtil.addFileToZip(signatureFile);
//		zipUtil.closeZip();
		System.exit(0);
	}

	private static String readTextFile(String fileName) throws UnsupportedEncodingException, IOException {
		byte[] encoded = Files.readAllBytes(Paths.get(fileName));
		return new String(encoded, "UTF8");
	}

	private static void writeTextToFile(String text, File fileName) throws FileNotFoundException, IOException {
		FileUtils.writeStringToFile(fileName, text);
	}
}
