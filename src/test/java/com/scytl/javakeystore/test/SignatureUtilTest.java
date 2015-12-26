/**
 * $Id$
 *
 * @author lcappuccio
 * @date 09/04/2015 12:12
 * <p>
 * Copyright (C) 2015 Scytl Secure Electronic Voting SA
 * <p>
 * All rights reserved.
 */
package com.scytl.javakeystore.test;

import com.scytl.javakeystore.exception.SignatureUtilException;
import com.scytl.javakeystore.impl.SignatureUtilImpl;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SignatureUtilTest {

	private SignatureUtilImpl sut;
	private final static String keyStore = "client.jks";
	private static String keyStorePath;

	@BeforeClass
	public static void setUp() throws URISyntaxException {
		URL keyStoreURL = ClassLoader.getSystemResource(keyStore);
		File keyStoreFile = new File(keyStoreURL.toURI());
		keyStorePath = keyStoreFile.getAbsolutePath();
	}

	@Test(expected = SignatureUtilException.class)
	public void throwExceptionNotExistingFile() throws SignatureUtilException {
		sut = new SignatureUtilImpl("abc", "somepassword".getBytes());
	}

	@Test(expected = SignatureUtilException.class)
	public void wrongKeyStorePasswordException() throws SignatureUtilException {
		sut = new SignatureUtilImpl(keyStorePath, "abc".getBytes());
	}

	@Test(expected = SignatureUtilException.class)
	public void nonExistingKeyAliasDisplaysError() throws SignatureUtilException {
		sut = new SignatureUtilImpl(keyStorePath, "rcpxrcpx".getBytes());
		// Select private key
		String keyAlias = "some_missing_key_alias";
		char[] keyPasswd = "some_nonexisting_pwd".toCharArray();
		sut.useKey(keyAlias, keyPasswd);
	}

	@Test(expected = SignatureUtilException.class)
	public void askToSignNullDocumentThrowsException() throws SignatureUtilException {
		buildEffectiveSut();
		// Sign the document with the preselected key
		sut.signDocument(null);
	}

	@Test(expected = SignatureUtilException.class)
	public void throwExceptionOnBadSignature() throws SignatureUtilException {
		buildEffectiveSut();
		// Sign the document with the preselected key
		String testDocument = "some text document";
		sut.signDocument(testDocument);
		// Tamper the signature
		byte[] testSignature = sut.getDocumentSignature();
		sut.verifySign(testDocument, Arrays.copyOf(testSignature, testSignature.length - 5));
	}

	@Test
	public void askToVerifyDocument() throws SignatureUtilException {
		buildEffectiveSut();
		// Sign the document with the preselected key
		String testDocument = "some text document";
		sut.signDocument(testDocument);
		assertTrue(sut.verifySign(testDocument, sut.getDocumentSignature()));
	}

	@Test
	public void askToVerifyDocumentWithBadSignature() throws SignatureUtilException {
		buildEffectiveSut();
		// Sign the document with the preselected key
		String testDocument = "some text document";
		sut.signDocument(testDocument);
		assertFalse(sut.verifySign(testDocument, new byte[256]));
	}

	@Test
	public void askToVerifyTamperedDocument() throws SignatureUtilException {
		buildEffectiveSut();
		// Sign the document with the preselected key
		String testDocument = "some text document";
		sut.signDocument(testDocument);
		assertFalse(sut.verifySign(testDocument.substring(0, testDocument.length() - 5), sut.getDocumentSignature()));
	}

	/**
	 * Build SignatureUtil for tests
	 *
	 * @throws SignatureUtilException
	 */
	private void buildEffectiveSut() throws SignatureUtilException {
		sut = new SignatureUtilImpl(keyStorePath, "rcpxrcpx".getBytes());
		// Select private key
		String keyAlias = "client";
		char[] keyPasswd = "rcpx".toCharArray();
		sut.useKey(keyAlias, keyPasswd);
	}

}
