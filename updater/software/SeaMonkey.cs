/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018  Dirk Stolle

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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// SeaMonkey localizations that are supported in version 2.48 and later.
    /// </summary>
    public class SeaMonkey : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for SeaMonkey class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(SeaMonkey).FullName);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the SeaMonkey software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public SeaMonkey(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d = knownChecksums();
            if (!d.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum = d[languageCode];
        }


        /// <summary>
        /// gets a dictionary with the known checksums for the installers (key: language, value: checksum)
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://archive.mozilla.org/pub/seamonkey/releases/2.49.4/SHA1SUMS
            var result = new Dictionary<string, string>();
            result.Add("cs", "cf74566a89f5c5f8103dfa1d625fa0534f7ab3f0");
            result.Add("de", "a7cce6c9f99464e3e992a8dc7e94d29110aece54");
            result.Add("en-GB", "5534ad032553cb522a6e4f30d5b8a4fe8f8d039a");
            result.Add("en-US", "ee095b6730c4ec9b6b02174fc0d3d3212335f332");
            result.Add("es-AR", "842732fc84b58a40068833783ac72c59a4df8e2b");
            result.Add("es-ES", "b5ee29c5c35176a28ea07a92312bd768d0da5ef5");
            result.Add("fr", "49c91d221aa2520a4d09f71f6bab4228870b126b");
            result.Add("hu", "828345b6b57a97de7f7d1158108a88fd6dc3a004");
            result.Add("it", "7d1a206f1699357e72b6dfe6bacb58a3f73c0b45");
            result.Add("ja", "1ca1364ea791149ed27ab6538995d22fb332578e");
            result.Add("lt", "39f2362b03c664a19ede779c7a5905d6af20cc09");
            result.Add("nb-NO", "5e5385efbad67840acc623b431c1ff7ddc6e7ac4");
            result.Add("nl", "46d7184cf0b67191c4e633df05e822276e1a0567");
            result.Add("pl", "914398fb0ff19be8d60b46e69f530d0c66d69be2");
            result.Add("pt-PT", "194f89622420add222043d36ad89fa5a0f5c7238");
            result.Add("ru", "dae3297003b36e39e36c9c8337e6c513a6dd7ff6");
            result.Add("sk", "e30d20565cef27e8c1288becf00dcf2bac0a9c8c");
            result.Add("sv-SE", "9bd058844a8e9186338a3557f259a5b5694767b0");
            result.Add("zh-CN", "4aa18d2e727362a1741e937094afd21c0b4f1375");
            result.Add("zh-TW", "98366fb32872ba97ad01a6ac71b97348e19ea076");

            return result;
        }


        /// <summary>
        /// gets an enumerable collection of valid language codes
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums();
            return d.Keys;
        }


        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            const string knownVersion = "2.49.4";
            return new AvailableSoftware("SeaMonkey (" + languageCode + ")",
                knownVersion,
                "^SeaMonkey [0-9]+\\.[0-9]+(\\.[0-9]+)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                null,
                new InstallInfoExe(
                    "https://archive.mozilla.org/pub/seamonkey/releases/" + knownVersion + "/win32/" + languageCode + "/SeaMonkey%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA1,
                    checksum,
                    null,
                    "-ms -ma"),
                //There is no 64 bit installer yet.
                null);
        }


        /// <summary>
        /// list of IDs to identify the software
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "seamonkey", "seamonkey-" + languageCode.ToLower() };
        }


        /// <summary>
        /// tries to find the newest version number of SeaMonkey
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://archive.mozilla.org/pub/seamonkey/releases/";
            string htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of SeaMonkey: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using
            
            Regex reVersion = new Regex("/[0-9]+\\.[0-9]+(\\.[0-9]+)?/");
            MatchCollection matches = reVersion.Matches(htmlCode);
            if (matches.Count <= 0)
                return null;

            List<Triple> releaseList = new List<Triple>();
            foreach (Match item in matches)
            {
                var trip = new Triple(item.Value.Replace("/", ""));
                releaseList.Add(trip);
            }
            releaseList.Sort();
            var newest = releaseList[releaseList.Count - 1];

            if (htmlCode.Contains("/" + newest.full() + "/"))
                return newest.full();
            else
                return newest.major.ToString() + "." + newest.minor.ToString();
        }


        /// <summary>
        /// tries to get the checksum of the newer version
        /// </summary>
        /// <returns>Returns a string containing the checksum, if successfull.
        /// Returns null, if an error occurred.</returns>
        private string determineNewestChecksum(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://archive.mozilla.org/pub/seamonkey/releases/2.46/SHA1SUMS
             * Common lines look like
             * "7219....f4b4d  win32/en-GB/SeaMonkey Setup 2.46.exe"
             */

            string url = "https://archive.mozilla.org/pub/seamonkey/releases/" + newerVersion + "/SHA1SUMS";
            string sha1SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha1SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of SeaMonkey: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using
            //look for line with the correct language code and version
            Regex reChecksum = new Regex("[0-9a-f]{40}  win32/" + languageCode.Replace("-", "\\-")
                + "/SeaMonkey Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum = reChecksum.Match(sha1SumsContent);
            if (!matchChecksum.Success)
                return null;
            // checksum is the first 40 characters of the match
            return matchChecksum.Value.Substring(0, 40);
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
            logger.Debug("Searching for newer version of SeaMonkey (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            var currentInfo = knownInfo();
            if (newerVersion == currentInfo.newestVersion)
                // fallback to known information
                return currentInfo;
            string newerChecksum = determineNewestChecksum(newerVersion);
            if (string.IsNullOrWhiteSpace(newerChecksum))
                return null;
            //replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksum;
            return currentInfo;
        }


        /// <summary>
        /// lists names of processes that might block an update, e.g. because
        /// the application cannot be update while it is running
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>();
        }


        /// <summary>
        /// whether or not a separate process must be run before the update
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate proess returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        public override bool needsPreUpdateProcess(DetectedSoftware detected)
        {
            return true;
        }


        /// <summary>
        /// returns a process that must be run before the update
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            if (string.IsNullOrWhiteSpace(detected.installPath))
                return null;
            var processes = new List<Process>();
            //uninstall previous version to avoid having two SeaMonkey entries in control panel
            var proc = new Process();
            proc.StartInfo.FileName = Path.Combine(detected.installPath , "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// whether the detected software is older than the newest known software
        /// </summary>
        /// <param name="detected">the corresponding detected software</param>
        /// <returns>Returns true, if the detected software version is older
        /// than the newest software version, thus needing an update.
        /// Returns false, if no update is necessary.</returns>
        public override bool needsUpdate(DetectedSoftware detected)
        {
            Triple verDetected = new Triple(detected.displayVersion);
            Triple verNewest = new Triple(info().newestVersion);
            return (verDetected < verNewest);
        }


        /// <summary>
        /// language code for the SeaMonkey version
        /// </summary>
        private string languageCode;


        /// <summary>
        /// checksum for the installer
        /// </summary>
        private string checksum;

    } //class
} //namespace
