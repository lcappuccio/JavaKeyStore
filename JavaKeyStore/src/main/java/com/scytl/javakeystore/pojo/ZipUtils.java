/**
 * $Id$
 *
 * @author lcappuccio
 * @date 08/04/2015 16:11
 *
 * Copyright (C) 2015 Scytl Secure Electronic Voting SA
 *
 * All rights reserved.
 *
 */
package com.scytl.javakeystore.pojo;

import com.scytl.javakeystore.main.Main;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class ZipUtils {

	private final ZipOutputStream zipOutput;
	private final byte[] buffer;

	public ZipUtils() throws FileNotFoundException {
		this.buffer = new byte[1024];
		FileOutputStream fos = new FileOutputStream(Main.OUTPUT_PATH + "output" + ".zip");
		zipOutput = new ZipOutputStream(fos);
	}

	/**
	 *
	 * @param fileName
	 * @throws IOException
	 */
	public void addFileToZip(File fileName) throws IOException {
		ZipEntry zipEntry = new ZipEntry(fileName.getName());
		zipOutput.putNextEntry(zipEntry);
		try (FileInputStream in = new FileInputStream(fileName)) {
			int len;
			while ((len = in.read(buffer)) > 0) {
				zipOutput.write(buffer, 0, len);
			}
		}
		zipOutput.closeEntry();
	}

	/**
	 *
	 * @throws IOException
	 */
	public void closeZip() throws IOException {
		// close it
		zipOutput.close();
	}
}
