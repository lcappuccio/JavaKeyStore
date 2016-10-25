package org.systemexception.javakeystore.test;

import org.systemexception.javakeystore.main.Main;
import org.systemexception.javakeystore.pojo.ZipUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;

/**
 * @author leo
 * @date 26/12/15 13:11
 */
public class ZipUtilsTest {

	private final static String TEST_FILE = Main.OUTPUT_PATH + ZipUtils.OUTPUT_FILE;
	private ZipUtils sut;

	@Before
	public void setUp() throws IOException {
		File zipOutput = new File(TEST_FILE);
		zipOutput.delete();
		sut = new ZipUtils();
	}

	@After
	public void tearDown() throws IOException {
		File zipOutput = new File(TEST_FILE);
		zipOutput.delete();
		sut.closeZip();
	}

	@Test
	public void add_file_to_zip() throws IOException, URISyntaxException {
		sut = new ZipUtils();
		URL keyStoreURL = ClassLoader.getSystemResource(Main.INPUT_FILE);
		File keyStoreFile = new File(keyStoreURL.toURI());
		sut.addFileToZip(keyStoreFile);
		assert (new File(TEST_FILE).exists());
	}

}