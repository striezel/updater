/*
    This file is part of the updater command line interface.
    Copyright (C) 2017  Dirk Stolle

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
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using updater_cli.data;

namespace updater_cli.software
{
    /// <summary>
    /// Firefox Developer Edition (i.e. aurora channel)
    /// </summary>
    public class FirefoxAurora : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxAurora class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "53.0a2";

        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxAurora(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains<string>(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            //Do not set checksum explicitly, because nightly releases change too often.
            // Instead we try to get them on demand, when needed.
            checksum32Bit = null;
            checksum64Bit = null;
            triedToGetChecksums = false;
        }


        /// <summary>
        /// gets an enumerable collection of valid language codes
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            //Let's use the same language codes as in Firefox release channel.
            // That may not be completely accurate, but it should be close enough.
            return Firefox.validLanguageCodes();
        }


        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            if (!triedToGetChecksums && ((checksum32Bit == null) || (checksum64Bit == null)))
            {
                triedToGetChecksums = true;
                string[] sums = determineNewestChecksums(currentVersion);
                if (null != sums)
                {
                    checksum32Bit = sums[0];
                    checksum64Bit = sums[1];
                }
            } //if there are no checksums and we did not try to find them yet

            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition [0-9]{2}\\.[0-9][a-z][0-9] \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition [0-9]{2}\\.[0-9][a-z][0-9] \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                //32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/nightly/latest-mozilla-aurora-l10n/firefox-53.0a2." + languageCode + ".win32.installer.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    "-ms -ma",
                    "C:\\Program Files\\Firefox Developer Edition",
                    "C:\\Program Files (x86)\\Firefox Developer Edition"),
                //64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/nightly/latest-mozilla-aurora-l10n/firefox-53.0a2." + languageCode + ".win64.installer.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    "-ms -ma",
                    null,
                    "C:\\Program Files\\Firefox Developer Edition")
                    );
        }


        /// <summary>
        /// tries to find the newest version number of Firefox Developer Edition
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        private string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-aurora-latest-l10n-ssl&os=win&lang=" + languageCode;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]{2}\\.[0-9][a-z][0-9]");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// tries to get the checksums of the newer version
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit an 64 bit (in that order), if successfull.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/firefox/nightly/latest-mozilla-aurora-l10n/firefox-53.0a2.de.win64.checksums
             * Common lines look like
             * "faa1ddd5...1512 sha512 47502080 install/sea/firefox-53.0a2.de.win64.installer.exe"
             */

            var sums = new List<string>();
            foreach (var bits in new string[] { "32", "64" })
            {
                string url = "https://ftp.mozilla.org/pub/firefox/nightly/latest-mozilla-aurora-l10n/firefox-"
                    + newerVersion + "." + languageCode + ".win" + bits + ".checksums";
                string sha512SumsContent = null;
                using (var client = new WebClient())
                {
                    try
                    {
                        sha512SumsContent = client.DownloadString(url);
                    }
                    catch (Exception ex)
                    {
                        logger.Warn("Exception occurred while checking for newer"
                            + " version of Firefox Developer Edition (" + languageCode + "): " + ex.Message);
                        return null;
                    }
                    client.Dispose();
                } //using
                  //look for line with the correct data
                Regex reChecksum = new Regex("[0-9a-f]{128} sha512 [0-9]+ install/sea/firefox\\-"
                    + Regex.Escape(newerVersion) + "\\." + languageCode.Replace("-", "\\-") + "\\.win" + bits + "\\.installer\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value.Substring(0, 128));
            } //foreach
            //return list as array
            return sums.ToArray();
        }


        /// <summary>
        /// whether or not the method searchForNewer() is implemented
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return true;
        }


        /// <summary>
        /// looks for newer versions of the software than the currently known version
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Debug("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            //If versions match, we can return the current information.
            var currentInfo = knownInfo();
            if (newerVersion == currentInfo.newestVersion)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if ((null == newerChecksums) || (newerChecksums.Length != 2)
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                // fallback to known information
                return null;
            //replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksums[0];
            currentInfo.install64Bit.downloadUrl = currentInfo.install64Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install64Bit.checksum = newerChecksums[1];
            return currentInfo;
        }


        /// <summary>
        /// language code for the Firefox ESR version
        /// </summary>
        private string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private string checksum64Bit;


        /// <summary>
        /// whether or not this instance already tried to get the checksums
        /// </summary>
        private bool triedToGetChecksums;
    } //class
} //namespace
