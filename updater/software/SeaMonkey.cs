/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023, 2024  Dirk Stolle

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
    /// SeaMonkey localizations that are supported in version 2.48 and later.
    /// </summary>
    public class SeaMonkey : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for SeaMonkey class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(SeaMonkey).FullName);

        /// <summary>
        /// publisher name for signed installers
        /// </summary>
        private const string publisherX509 = "CN=SeaMonkey e.V., O=SeaMonkey e.V., S=Bayern, C=DE";


        /// <summary>
        /// expiration date for the publisher certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2025, 1, 5, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// Constructor with language code.
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
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.TryGetValue(languageCode, out checksum32Bit) || !d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code for SeaMonkey!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://archive.seamonkey-project.org/releases/2.53.20/SHA512SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "9fd5790dd2179b71c117e276c28ca3b93cce949af29345e0de2fae093994136008ca66933d04908cf5d92270621dad8a62a61bd5f9c802523146e5fd09a1d08d" },
                { "de", "eddef546a7ac9f9511e1e4113c64a84d70378d2b69ec940041f110ded379a50ea3bb33e6eda35c0c25df1f83fb9b26c1af4f6240c7e8a64766550406e82c935e" },
                { "el", "6430c2c29ff5d8fecce40758ea734b57d1733c648cc90341a34e6fde3d0e0483ef1238442d31057bd59434f851c98b10283b06b79a6cf432ed24bf82ff4d0851" },
                { "en-GB", "4e73b2b33dd35e9f4e39785ccbb1543bced8b2088c619ca9ed01fbefa93d3c0b5bbb10c9751baa57a65f7ed1ed51b502a87cd697a711c5ac7cbbb4d12af6c967" },
                { "en-US", "5d3754cb51781e80572e6c601ba0311bccd9b7af20892e7881ebb8689df58c2557a64334150669feeb3fbff2f04515e14ec6f09a478e527460c36c6eead5fe32" },
                { "es-AR", "4331698c58a3772df48f689e74cd9bdf58f5e97d82601b6df035bbc0d1914902a1dbd1a34f880204377b4145ccc0f03219258ed32a3535b9089c001a858106de" },
                { "es-ES", "bb2021eb387b59409c956b44159422bcd30402497d9ad3dc3b8e832e3b332e60ab96f1499ecdc630ffce38ec0789bc14809ded2f5ddbca94a0a9e95a2458ae5e" },
                { "fi", "39ed23ded4aa63bacb3db63f1ed45ce2b8801504d56cb1f5bf9a8759b6fe9bb54b16d1c83452cb7afdeaba2b20343db420cd436dd33eb73e1d96afb8b51bed14" },
                { "fr", "8d7b6ada040473c0375166fad41e3d1a13531958a320cec93784a25de2d38d9809d02ac314c291f2851d6370bbe797ba0af2e229f806e6272e25e8668ee13a12" },
                { "hu", "04ecce3b412a3b1ed67717369510d2b24eb9008b8a3e520aa8ed45b11886b0326412ea7d5c453bbe2bff2ee22374056aaa21c1b673338dc36505d108f4e0b3e3" },
                { "it", "b152aad561df7a85f95de43757d100f24004014eaae7821a110755497c45bf0d4302381237988982c2437bf4fbf11df4564530db308c7becdf45e558539cfaf6" },
                { "ja", "c8f17b3e43aaf22e61375337d4cda83cc4fff0e43cbdf0640ff6b021f88d62aec9da6bab69fdf416bd32f668ee4d178a65e549e07e15069c08a7a44fcfbb7044" },
                { "ka", "d098419411ebef6f3d7a6b981f38664064ac5ca2307cbd44f9c5689c8014e2ba00404ec747b94b8c5e0c47536be760b0b877d736621807cf343631d8c82c5046" },
                { "nb-NO", "8331f420f2b257e7ce61f19f6cd54e962568cc32aeec8aeab32bc1ff195bf775f254a32cdac1788738a183ee03ad666a3f4a517224de38f9c0d384b8f98a4dcd" },
                { "nl", "d50459c2ba6309590c2c12b0f0dd6091f697518f0fd302cc0d67b2d173d640e301c5ee201f0a348d0e8f9cb34d7d8aad0758cde52a8e9335c9d08794402d686d" },
                { "pl", "34babb41edf05e9cc0d4b3c81cdbfb2d82008aa8abb490807c30817ebea697a20100ee5affdf3fc2dbbbb99be6871c4e13b5b77dfeae0a0e3b550101ef17d0f9" },
                { "pt-BR", "1fa630bf2bb4dd124e3562ec2bf85baff95f7ac6a2cfff330047da1e97825ae9be451f1e7557445ff767b7266ecacb29ca0e7b6b43a5b3014c04d8375c56816a" },
                { "pt-PT", "810ff6ae13c95ccb816a14fd4d14fa696495c51c7e2ad61bd70b30c32e2dfbf5a9c58dead1a547c7ab5591d5455d33230326144bb9662d8628e891e24c1265d4" },
                { "ru", "3e1d0be138fa404ec34099d13abd499ba4c0f6b770942988a6b33f92eb2f33eb32f027223f94c458f2cf728b373d25f7e077a2cb20890779a95eeff9510d3fe2" },
                { "sk", "5096771980481fc9df3828a0fbd497bfc8362b1904bd77ee1e95478b85bb6352fadaa9084c2fb1cc4781279ec18bbbe7d28ac3b651fce0ed7add93672348dc3f" },
                { "sv-SE", "c24b839976e9ba93bd0e7a6d0f58a0a38cb4e5633e629c105bef11ee28896e4070eb33d3257acc2398799c03633bef750fdde0335df8c481a548c21256d9023b" },
                { "zh-CN", "8466213f1682828a0da9f70397d54f7e7df67fdc456dcca8385d049864d361b3d8b9940f3794eb846cadef35cfdf5669ea12238ee81bfe17eabe4e9da2a531c8" },
                { "zh-TW", "303f8b6ca59e1cdb706e15a54caa313824be8dba00864facf381e697de339015ad2cff4b78c427c43784efc61ddae1b71b65848fc277fc7043419cafea1b864f" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://archive.seamonkey-project.org/releases/2.53.20/SHA512SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "35e02e8167e06a65dc3e543599ab4d9a091a6c317a931071cddced803d03c9b1c2384e593644044be4d244624e8ae28217ee298e0c4c34b52f59ea2db372268c" },
                { "de", "98276e29600c8c7136dedd38860daa015f56a913522d945dca18e56169040174ecd0ef3e2b778707b1c048058e3b61468cf22882a7c0914744ecb6d228d979bb" },
                { "el", "a918f98d124d5589679126652acd2b62713920a3518af5b0555396e990b68c1b542e6fad14fdaae1f6b8531c368b3005bda4cb4d9653ea709d5276ddbe8038aa" },
                { "en-GB", "4791ff44064fab38ec7cb47f4540c03c95f428ab475f1cc2dfa754cdbb1a7799134d1180f6f7bae78ba4d52264345caa662abce3a321327e8e18d006a0c92c74" },
                { "en-US", "0ca6c7d8067462834bee93cad1ac0d5babcf7a3f8d13f5d33b35496d75c467514508390b8c84ac82d946c6bd79f4abd573672e8ce0b303eef4e0e909b733ad2d" },
                { "es-AR", "a15400b76a0cfd1d1edcf177a1fbf21fde7a2e54702c0a40322c5bba8a74cfd7ca213cbf618e41e45ab28f0ee6d331abdfaebcab2da3062654a87235eb7ceb81" },
                { "es-ES", "86ffa9017550f256c914b6c06957908d1546af78cc32064afca2577b5cfc6609d7126057623ea7ede141826d37206a5e8245708cb6dfc510fabd05d315f8f99b" },
                { "fi", "4963ec38f00a200c90c2d8d9fdb79bc2a61112dfd574ef54224e032bb04e333ec9006e70328f015f7d869cd76bc3cad04e4dd4a164e4386bdb2604bec1347929" },
                { "fr", "9422743d08860502506c4c80b93c394d408c8d482433d02603aa4bd335816f4009162f433ed1d32a2d7c02a3f3ee2922a4dbc5fc335869879caf46deb368ac0a" },
                { "hu", "ea29f933172d2e1cba757fab7635cd27418d704aafb5f80ced4568a8e59cc1c32e7e031da249fdea5551ee1081119064b4f8a57983d57953cc099e8202c2ca93" },
                { "it", "1632602c7ef32d4549a7bc484d082f87fea8a257fe7032ddf6aef2fd7cf08966a6b3d3ff9eeb7ed5e3f2bc0f9a2d32ed5548111364007b359da66879fd992ffa" },
                { "ja", "808cf47b7ee52cba1af0e2b9ee260397dd7141f2eb78f292ec75d5b28903035a64f021bcb9f7055deae0de680e30274b7c267036c5d6904c15a94cf2a4845b00" },
                { "ka", "6c37d28e8818af8c773126539c8fb9b6c26d7873308047132501b60612bb8f45ad767f0e12d338d6a9ba3b86d3aca85f8277bbad383651091832253501c94ff0" },
                { "nb-NO", "6f66a20b0d264286a40eee7f39af230e603f57d661391107931fef4bed3193691863ea60504072587d32fb3cb592b22d3b6f74a268e4e066b0569f341fd2d752" },
                { "nl", "2c764b123352a4202405f300a18e2b1572f76025452cd508b63281015ef1532325a4c6aadd2889ceb998feb3c2cd2b55e43824e608d2077e9ab9acc60e172618" },
                { "pl", "67037016be4f8ea06455871f90bbf335430697de68c019ca9b143661d25575f3316f8ad6e57d9d1ae037cf534e4e8bfbaf2342fe13146bb74e6087defed0aa13" },
                { "pt-BR", "13412ae5b69a477c1b3e6a4909841a6de88174f459dbf87e8de25ee4e76f1fc277f7af0f286d0f8c26deb0070336ddf9ab59c4d03bcd8e0dabd5e75a09f05188" },
                { "pt-PT", "99fe910642b36001b73659044160afeb6823b220bc32956d627ad75065a1072531b17609468bb81dd347f8bae034617649963d79435788fd7c10e249ba84befa" },
                { "ru", "b20c8976d9dad25a06d69986ae0636d79d3a884cd18f72b27d824e8772bf0a03688b1984f51128bf69b942a6cc58f2974ea1f99d5017718e42a378166ca0b423" },
                { "sk", "95f8dba7db46140888e074cc817771a710b4cddea685591da21a17bdec2f7ea29f84c5fdef9d0da904cdc339acb84c3ca919979905126bead2955bd766d25175" },
                { "sv-SE", "e9b94013c4069a2fdb66cae3abef7720c49fae9754cce08a714d291a8d8ee1ca1630b72a49d4b88adb60f6b06ad0d33d970ce0cd9a9da7b8f483c5e485a44d27" },
                { "zh-CN", "bbf60d4a01e4e457ddc0013109290113e633079f58935b38d0765d0c7b0c62635bc4f45c6396ad4a6bec2f9f462077b2f2b97a384d89b0086874145cdb1ca709" },
                { "zh-TW", "7bb1be3c65149f397b3ced997427a800e862de49fc9730344c38c8c68064c8fc82bf87c9a7c49155ca883eeea914b83c43cacc1181a5ec8212a8b4ac09d89550" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            // Just go for the 32-bit installers here. We could also use the
            // 64-bit installers, but they have the same languages anyway.
            var d = knownChecksums32Bit();
            return d.Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            const string knownVersion = "2.53.20";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("SeaMonkey (" + languageCode + ")",
                knownVersion,
                "^SeaMonkey [0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^SeaMonkey [0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                new InstallInfoExe(
                    "https://archive.seamonkey-project.org/releases/" + knownVersion + "/win32/" + languageCode + "/seamonkey-" + knownVersion + "." + languageCode + ".win32.installer.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                new InstallInfoExe(
                    "https://archive.seamonkey-project.org/releases/" + knownVersion + "/win64/" + languageCode + "/seamonkey-" + knownVersion + "." + languageCode + ".win64.installer.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma"));
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["seamonkey", "seamonkey-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of SeaMonkey.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public static string determineNewestVersion()
        {
            string url = "https://archive.seamonkey-project.org/releases/";
            string htmlCode;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of SeaMonkey: " + ex.Message);
                return null;
            }

            var reVersion = new Regex(">[0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)?<");
            MatchCollection matches = reVersion.Matches(htmlCode);
            if (matches.Count <= 0)
                return null;

            var releaseList = new List<Quartet>();
            foreach (Match item in matches)
            {
                var quart = new Quartet(item.Value[1..^1]);
                releaseList.Add(quart);
            }
            releaseList.Sort();
            var newest = releaseList[^1];

            if (htmlCode.Contains(">" + newest.full() + "<"))
                return newest.full();
            var trip = new Triple(newest.full());
            if (htmlCode.Contains(">" + trip.full() + "<"))
                return trip.full();
            else
                return newest.major.ToString() + "." + newest.minor.ToString();
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://archive.seamonkey-project.org/releases/2.53.18.1/SHA512SUMS.txt
             * Common lines look like
             * "be06...690f0 sha512 40284320 win32/en-GB/seamonkey-2.53.18.1.en-GB.win32.installer.exe"
             * 
             * Version 2.53.1 uses a new format. Common lines look like
             * 7ccee70c54580c0c0949a9bc86737fbcb35c46ed sha1 38851663 win32/en-GB/seamonkey-2.53.6.en-GB.win32.installer.exe
             * for the 32-bit installer, or like
             * c6a9d874dcaa0dabdd01f242b610cb47565e91fc sha1 41802858 win64/en-GB/seamonkey-2.53.6.en-GB.win64.installer.exe
             * for the 64-bit installer.
             */

            string url = "https://archive.seamonkey-project.org/releases/" + newerVersion + "/SHA512SUMS.txt";
            string sha1SumsContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                sha1SumsContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of SeaMonkey: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version
            // File name looks like seamonkey-2.53.1.de.win32.installer.exe now.
            var reChecksum32Bit = new Regex("[0-9a-f]{128} sha512 [0-9]+ .*seamonkey\\-" + Regex.Escape(newerVersion)
                + "\\." + languageCode.Replace("-", "\\-") + "\\.win32\\.installer\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha1SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128} sha512 [0-9]+ .*seamonkey\\-" + Regex.Escape(newerVersion)
                + "\\." + languageCode.Replace("-", "\\-") + "\\.win64\\.installer\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha1SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is in the first 128 characters of each match.
            return [
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            ];
        }


        /// <summary>
        /// Determines whether the method searchForNewer() is implemented.
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return true;
        }


        /// <summary>
        /// Looks for newer versions of the software than the currently known version.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Info("Searching for newer version of SeaMonkey (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            var currentInfo = knownInfo();
            if (newerVersion == currentInfo.newestVersion)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if (null == newerChecksums || newerChecksums.Length != 2
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                return null;
            // replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksums[0];
            currentInfo.install64Bit.downloadUrl = currentInfo.install64Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install64Bit.checksum = newerChecksums[1];
            return currentInfo;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return [];
        }


        /// <summary>
        /// Determines whether a separate process must be run before the update.
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
        /// Returns a process that must be run before the update.
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
            proc.StartInfo.FileName = Path.Combine(detected.installPath, "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// language code for the SeaMonkey version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;

    } // class
} // namespace
