/**
 * @author leo
 * @date 10/04/2015 22:42
 */
package com.scytl.javakeystore.api;

import com.scytl.javakeystore.exception.SignatureUtilException;

public interface SignatureUtil {

	/**
	 *
	 * @param keyAlias the key alias
	 * @param keyPasswd the key password
	 * @throws SignatureUtilException
	 */
	void useKey(String keyAlias, char[] keyPasswd) throws SignatureUtilException;

	/**
	 *
	 * @param document the document to sign
	 * @throws SignatureUtilException
	 */
	void signDocument(String document) throws SignatureUtilException;

	/**
	 *
	 * @param document the document to verify
	 * @param documentSignature the signature to verify
	 * @return the signature verification status
	 * @throws SignatureUtilException
	 */
	Boolean verifySign(String document, byte[] documentSignature) throws SignatureUtilException;

}
