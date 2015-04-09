/**
 * $Id$
 *
 * @author lcappuccio
 * @date 09/04/2015 11:00
 *
 * Copyright (C) 2015 Scytl Secure Electronic Voting SA
 *
 * All rights reserved.
 *
 */
package com.scytl.javakeystore.exception;

public class SecurityException extends Exception {
	
	private static final long serialVersionUID = 5495464303671968900L;

    /**
     * Creates a new instance of <code>SecurityException</code> without detail message.
     */
    public SecurityException() {
    }


    /**
     * Constructs an instance of <code>SecurityException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public SecurityException(String msg) {
        super(msg);
    }
}
