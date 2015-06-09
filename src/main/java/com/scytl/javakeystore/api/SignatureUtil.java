/**
 * @author leo
 * @date 10/04/2015 22:42
 */
package com.scytl.javakeystore.api;

import com.scytl.javakeystore.exception.SignatureUtilException;

public interface SignatureUtil {

	/**
	 *
	 * @param keyAlias
	 * @param keyPasswd
	 * @throws SignatureUtilException
	 */
	void useKey(String keyAlias, char[] keyPasswd) throws SignatureUtilException;

	/**
	 *
	 * @param document
	 * @throws SignatureUtilException
	 */
	void signDocument(String document) throws SignatureUtilException;

	/**
	 *
	 * @param document
	 * @param documentSignature
	 * @return
	 * @throws SignatureUtilException
	 */
	Boolean verifySign(String document, byte[] documentSignature) throws SignatureUtilException;

}
