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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class ZipUtils {

	ZipOutputStream zipOutput;

	public ZipUtils(String zipFileName) throws FileNotFoundException {
		FileOutputStream fos = new FileOutputStream("target/" + zipFileName + ".zip");
		zipOutput = new ZipOutputStream(fos);
	}

	public void addFileToZip(String fileName) throws IOException {
		File file = new File(fileName);
		ZipEntry zipEntry = new ZipEntry(file.getName());
		zipOutput.putNextEntry(zipEntry);
		zipOutput.closeEntry();
		// close it
		zipOutput.close();
	}
}
