/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2019, 2022  Dirk Stolle

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Net;

namespace updater_test.utility
{
    /// <summary>
    /// Unit tests for updater.utility.Verificator class.
    /// </summary>
    [TestClass]
    public class Verificator_Tests
    {
        /// <summary>
        /// holds the path of the downloaded file
        /// </summary>
        private static string downloadFileLocation = null;


        /// <summary>
        /// subject in signature for LibreOffice Help Pack installer
        /// </summary>
        private const string libreOfficePublisherX509 = "E=info@documentfoundation.org, CN=The Document Foundation, O=The Document Foundation, OU=LibreOffice Build Team, L=Berlin, S=Berlin, C=DE";


        /// <summary>
        /// Downloads a file from the given URL.
        /// </summary>
        /// <param name="url">URL of the file</param>
        /// <returns>Returns the local path of the downloaded file, if successful.
        /// Returns null, if an error occurred.</returns>
        private static string download(string url)
        {
            string localFile = Path.Combine(Path.GetTempPath(), "test_original.msi");
            using (var wc = new WebClient())
            {
                try
                {
                    wc.DownloadFile(url, localFile);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("An error occurred while downloading the file "
                        + url + ": " + ex.Message);
                    wc.Dispose();
                    return null;
                }
            } // using
            return localFile;
        }


        /// <summary>
        /// Downloads a signed MSI file that will be used during the tests.
        /// </summary>
        /// <param name="testContext"></param>
        [ClassInitialize()]
        public static void DownloadExampleFile(TestContext testContext)
        {
            downloadFileLocation = download("https://download.documentfoundation.org/libreoffice/stable/7.4.1/win/x86_64/LibreOffice_7.4.1_Win_x64_helppack_de.msi");
        }


        /// <summary>
        /// Deletes the signed MSI file that was used during the tests.
        /// </summary>
        [ClassCleanup()]
        public static void DeleteExampleFile()
        {
            if (!string.IsNullOrWhiteSpace(downloadFileLocation))
            {
                try
                {
                    File.Delete(downloadFileLocation);
                }
                catch (Exception)
                {
                    // nothing
                }
            }
        }


        /// <summary>
        /// negative test case for verifiySignature, i.e. verification fails
        /// </summary>
        [TestMethod]
        public void Test_verifySignature_negative()
        {
            Assert.IsNotNull(downloadFileLocation, "The test file was not downloaded!");

            bool verified = true;
            string copyLocation = downloadFileLocation + "_copy";
            try
            {
                // copy original file
                File.Copy(downloadFileLocation, copyLocation);
                // modify some bytes in the copied file
                using (Stream stream = File.Open(copyLocation, FileMode.Open))
                {
                    stream.Position = 345;
                    byte[] data = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
                    stream.Write(data, 0, data.Length);
                    stream.Close();
                }
                // check signature
                verified = updater.utility.Verificator.verifySignature(copyLocation, libreOfficePublisherX509);
            }
            finally
            {
                if (File.Exists(copyLocation))
                    File.Delete(copyLocation);
            }
            // Verification should have failed.
            Assert.IsFalse(verified);
        }


        /// <summary>
        /// positive test case for verifiySignature, i.e. verification succeeds
        /// </summary>
        [TestMethod]
        public void Test_verifySignature_positive()
        {
            Assert.IsNotNull(downloadFileLocation, "The test file was not downloaded!");

            bool s = updater.utility.Verificator.verifySignature(downloadFileLocation, libreOfficePublisherX509);
            // If this assertion fails and it is the 8th September 2023 or later,
            // then this is because the certificate has expired.
            Assert.IsTrue(s);
        }
    }
}
