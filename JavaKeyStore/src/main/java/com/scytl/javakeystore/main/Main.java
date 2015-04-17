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

import com.scytl.javakeystore.exception.SignatureUtilException;
import com.scytl.javakeystore.impl.SignatureUtilImpl;
import com.scytl.javakeystore.pojo.ZipUtils;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.apache.commons.io.FileUtils;

public class Main {

	public static final String INPUT_PATH = "input/", OUTPUT_PATH = System.getProperty("user.dir") + "/";
	private static SignatureUtilImpl keystore;
	private static ZipUtils zipUtil;

	public static void main(String[] args) throws IOException, SignatureUtilException {

		String keyStorePath = INPUT_PATH + "client.jks";
		byte[] keyStorePasswd = "rcpxrcpx".getBytes();

		// Create keystore
		keystore = new SignatureUtilImpl(keyStorePath, keyStorePasswd);

		// Select private key
		String keyAlias = "client";
		char[] keyPasswd = "rcpx".toCharArray();
		keystore.useKey(keyAlias, keyPasswd);

		// Read a document
		String loremIpsum = readTextFile(INPUT_PATH + "lorem_ipsum.txt");
		System.out.println("\n*** CLEAR TEXT DOCUMENT ***");
		System.out.println(loremIpsum);

		// Sign the document with the preselected key
		keystore.signDocument(loremIpsum);

		// Verify signature
		System.out.println("\n*** VERIFY SIGNATURE ***");
		System.out.println("Document signature is valid: " + keystore.verifySign(loremIpsum, keystore.getDocumentSignature()));
		assert (keystore.verifySign(loremIpsum, keystore.getDocumentSignature()));
		// Negative case
		System.out.println("Falsified document signature is valid: " + keystore.verifySign("Falsified document", keystore.getDocumentSignature()));
		assert (keystore.verifySign("Falsified document", keystore.getDocumentSignature()) == false);

		// Save document and signature to ZIP
		zipUtil = new ZipUtils("output");
		zipUtil.addFileToZip(new File(INPUT_PATH + "lorem_ipsum.txt"));
		File signatureFile = new File(OUTPUT_PATH + "lorem_ipsum.txt.sig");
		writeTextToFile(new String(keystore.getDocumentSignature()), signatureFile);
		zipUtil.addFileToZip(signatureFile);
		zipUtil.closeZip();
		System.exit(0);
	}

	/**
	 *
	 * @param fileName
	 * @return
	 * @throws UnsupportedEncodingException
	 * @throws IOException
	 */
	private static String readTextFile(String fileName) throws UnsupportedEncodingException, IOException {
		byte[] encoded = Files.readAllBytes(Paths.get(fileName));
		return new String(encoded, "UTF8");
	}

	/**
	 *
	 * @param text
	 * @param fileName
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	private static void writeTextToFile(String text, File fileName) throws FileNotFoundException, IOException {
		FileUtils.writeStringToFile(fileName, text);
	}
}
