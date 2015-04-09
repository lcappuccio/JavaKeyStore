/**
 * $Id$
 *
 * @author lcappuccio
 * @date 09/04/2015 12:12
 *
 * Copyright (C) 2015 Scytl Secure Electronic Voting SA
 *
 * All rights reserved.
 *
 */
package com.scytl.javakeystore.pojo;

import com.scytl.javakeystore.exception.SignatureUtilException;
import java.util.Arrays;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

public class SignatureUtilTest {

	SignatureUtil sut;

	@Test(expected = com.scytl.javakeystore.exception.SignatureUtilException.class)
	public void throwExceptionNotExistingFile() throws SignatureUtilException {
		sut = new SignatureUtil("abc", "somepassword".getBytes());
	}

	@Test(expected = com.scytl.javakeystore.exception.SignatureUtilException.class)
	public void wrongKeyStorePasswordException() throws SignatureUtilException {
		sut = new SignatureUtil("src/test/resources/client.jks", "abc".getBytes());
	}

	@Test(expected = com.scytl.javakeystore.exception.SignatureUtilException.class)
	public void nonExistingKeyAliasDisplaysError() throws SignatureUtilException {
		sut = new SignatureUtil("src/test/resources/client.jks", "rcpxrcpx".getBytes());
		// Select private key
		String keyAlias = "some_missing_key_alias";
		char[] keyPasswd = "some_nonexisting_pwd".toCharArray();
		sut.useKey(keyAlias, keyPasswd);
	}

	@Test(expected = com.scytl.javakeystore.exception.SignatureUtilException.class)
	public void askToSignNullDocumentThrowsException() throws SignatureUtilException {
		buildEffectiveSut();
		// Sign the document with the preselected key
		sut.signDocument(null);
	}

	@Test(expected = com.scytl.javakeystore.exception.SignatureUtilException.class)
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
	public void askToVerifyTamperedDocument() throws SignatureUtilException {
		buildEffectiveSut();
		// Sign the document with the preselected key
		String testDocument = "some text document";
		sut.signDocument(testDocument);
		assertFalse(sut.verifySign(testDocument.substring(0, testDocument.length() - 5), sut.getDocumentSignature()));
	}

	/**
	 * Build sut for tests
	 *
	 * @throws SignatureUtilException
	 */
	private void buildEffectiveSut() throws SignatureUtilException {
		sut = new SignatureUtil("src/test/resources/client.jks", "rcpxrcpx".getBytes());
		// Select private key
		String keyAlias = "client";
		char[] keyPasswd = "rcpx".toCharArray();
		sut.useKey(keyAlias, keyPasswd);
	}

}
