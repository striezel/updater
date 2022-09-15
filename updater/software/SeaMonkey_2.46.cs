/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021  Dirk Stolle

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
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Class for SeaMonkey languages that were only available up to version 2.46,
    /// because those languages were dropped in version 2.48. Other localized
    /// versions of SeaMonkey are handled by the SeaMonkey class.
    /// </summary>
    /// <remarks>Language support for be, ca, fi, gl, nb-No, tr and uk has been
    /// dropped in 2.46, because the languages are no longer updated for
    /// SeaMonkey. However, support for nb-No has been reintroduced in 2.49.1.</remarks>
    public class SeaMonkey246 : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for SeaMonkey class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(SeaMonkey).FullName);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the SeaMonkey software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public SeaMonkey246(string langCode, bool autoGetNewer)
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
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum = d[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://archive.mozilla.org/pub/seamonkey/releases/2.46/SHA1SUMS
            var result = new Dictionary<string, string>(6)
            {
                { "be", "f7d41d99ff000ab38181fb1083173524049d76bf" },
                { "ca", "fcbd9a1b3ba22c8ab23e5239238ab13e58d72d35" },
                { "fi", "23c2866da87fffb825d2c4cc060aab09f8af6d3e" },
                { "gl", "452b0ad172d35561fc9053c84d2793d07a3ce78c" },
                // Support for nb-NO has been reintroduced in version 2.49.1.
                //result.Add("nb-NO", "2d70dec6be6b924733bebf90b36ab25a865b8f15");
                { "tr", "f227afd4ff6a1fa28c8a4fccde9c597575e2f7f0" },
                { "uk", "9fad7399f92b7e16c1cfd1d26374152f25d4ee82" }
            };

            return result;
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums();
            return d.Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("SeaMonkey 2.46 (" + languageCode + ")",
                "2.46",
                "^SeaMonkey [0-9]+\\.[0-9]+(\\.[0-9]+)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                null,
                new InstallInfoExe(
                    "https://archive.mozilla.org/pub/seamonkey/releases/2.46/win32/" + languageCode + "/SeaMonkey%20Setup%202.46.exe",
                    HashAlgorithm.SHA1,
                    checksum,
                    Signature.None,
                    "-ms -ma"),
                //There is no 64 bit installer yet.
                null);
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "seamonkey246", "seamonkey246-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Determines whether or not the method searchForNewer() is implemented.
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return true;
        }


        /// <summary>
        /// Logs a message about dropped language support for SeaMonkey.
        /// </summary>
        private void logLangSupportedDropped()
        {
            string message = "Language support for " + languageCode + " has been "
                + "dropped in SeaMonkey 2.48, because the language is no longer"
                + " updated for SeaMonkey. To receive further updates switch "
                + "to another, still supported language.";
            var langs = SeaMonkey.validLanguageCodes();
            var enumerator = langs.GetEnumerator();
            if (enumerator.MoveNext())
            {
                var firstLangCode = enumerator.Current;
                var sm = new SeaMonkey(firstLangCode, false);
                message += Environment.NewLine + "Supported languages of "
                    + "version " + sm.knownInfo().newestVersion + " of "
                    + "SeaMonkey are:";
                foreach (var lang in langs)
                {
                    message += Environment.NewLine + "    " + lang;
                } // foreach
            } // if enumerator move was successful
            logger.Warn(message);
        }


        /// <summary>
        /// Looks for newer versions of the software than the currently known version.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logLangSupportedDropped();
            logger.Warn("Falling back to version 2.46, although there is a "
                + "newer version!");
            return knownInfo();
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>(0);
        }


        /// <summary>
        /// Determines whether or not a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate process returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        public override bool needsPreUpdateProcess(DetectedSoftware detected)
        {
            return true;
        }


        /// <summary>
        /// Returns a list of processes that must be run before the update.
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
            // uninstall previous version to avoid having two SeaMonkey entries in control panel
            var proc = new Process();
            proc.StartInfo.FileName = Path.Combine(detected.installPath , "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// Checks whether the detected software is older than the newest known software.
        /// </summary>
        /// <param name="detected">the corresponding detected software</param>
        /// <returns>Returns true, if the detected software version is older
        /// than the newest software version, thus needing an update.
        /// Returns false, if no update is necessary.</returns>
        public override bool needsUpdate(DetectedSoftware detected)
        {
            var verDetected = new Triple(detected.displayVersion);
            var verNewest = new Triple(info().newestVersion);
            return verDetected < verNewest;
        }


        /// <summary>
        /// language code for the SeaMonkey version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the installer
        /// </summary>
        private readonly string checksum;

    } // class
} // namespace
