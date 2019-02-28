/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2019  Dirk Stolle

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

using System.Security.Cryptography.X509Certificates;

namespace updater.utility
{
    /// <summary>
    /// Class to verify signed binary files.
    /// </summary>
    public class Verificator
    {
        /// <summary>
        /// NLog.Logger for Verificator class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Verificator).FullName);


        /// <summary>
        /// Verifies signature and publisher of a file.
        /// </summary>
        /// <param name="fileName">file name with full path</param>
        /// <param name="publisher">publisher name</param>
        /// <returns>Returns true, if the file has a valid signature and is from the given publisher.
        /// Returns false otherwise.</returns>
        public static bool verifySignature(string fileName, string publisher)
        {
            if (!trust.WinTrust.VerifyEmbeddedSignature(fileName))
                return false;

            return verifiyPublisher(fileName, publisher);
        }


        /// <summary>
        /// Verifies that a given file is from a certain publisher.
        /// </summary>
        /// <param name="fileName">file name with full path</param>
        /// <param name="publisher">publisher name</param>
        /// <returns>Returns true, if the file is from the given publisher.
        /// Returns false otherwise.</returns>
        public static bool verifiyPublisher(string fileName, string publisher)
        {
            X509Certificate2 cert = null;
            string sub = null;
            try
            {
                cert = new X509Certificate2(fileName);
                X509Chain certChain = new X509Chain();
                bool chainValid = certChain.Build(cert);
                if (!chainValid)
                {
                    foreach (var status in certChain.ChainStatus)
                    {
                        var level = (status.Status == X509ChainStatusFlags.NoError)
                            ? NLog.LogLevel.Info : NLog.LogLevel.Error;
                        logger.Log(level, "Certificate chain status: " + status.Status.ToString() + " - " + status.StatusInformation);
                        if (status.Status == X509ChainStatusFlags.NotTimeValid)
                        {
                            logger.Info("Certificate is not valid before " + cert.NotBefore.ToString("yyyy-MM-dd HH:mm:ss")
                                + " and not valid after " + cert.NotAfter.ToString("yyyy-MM-dd HH:mm:ss") + ".");
                        }
                    } // foreach
                }
                if (!cert.Verify())
                    return false;
                sub = cert.Subject;
            }
            catch
            {
                // Any exception is an error and makes verification impossible.
                return false;
            }
            return sub == publisher;
        }

    }
} // namespace
