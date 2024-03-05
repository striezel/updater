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
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code for SeaMonkey!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://archive.seamonkey-project.org/releases/2.53.18.1/SHA512SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "e9c369fc31d06d933063895ccf0adab47ce698fdbda4a31eab0282235cf2a3ca9e3a55335f301005b7b5716520a9d57db75e66c3a2d6038e106587a2da4e5637" },
                { "de", "afb506172157a8ca257f4d168783a7a3b9ae58655d32ffd3c5cdebe60f1fec47beadc81f42f5a1d2aa57f426539cb7e5390ed0900255781e7f3e56c6aea5617a" },
                { "el", "14cfa5ebf799b7b0b673a7d555a9b69a3ab17862f661fe0dc62b5c6e450f4fb7f5939719547c0e72bf2d8acbfb25325fdcd9fbadc37a9790e2664d12b5ae5c2e" },
                { "en-GB", "be0663e953e65b1c1addb084041ab9e7c13fb4f662579114de662447e7ef37a641671b76017a9b60e8c295dbe3fece1a2221f6a03801fd7182fed449c9f690f0" },
                { "en-US", "8ff5d9125245bf30079d78d18b6975c6fd2d2d901934aad88bbc2c372ef037f63603ebea043cb553eddecc23c9d83d72a37b81d517df541af9e7312007364482" },
                { "es-AR", "3cdbbafe59b05f5903c129a6182d1f03d5d4faf941326516821263cf1ecc170242ec47e69aad69eb61f737617670f7800fc902aafcc283dcda4f9f3d93b32e2c" },
                { "es-ES", "357e1e1a04062ef280f6972da0b87cac6565630039cfc94fea251ef1a884aec76a86dfcb51b810fc0326b689e8d1cdf6daa4a88e1bf12788a50ecb2ca52f4464" },
                { "fi", "2435c4a2afa0cee8c2e7b6b7d0d883f8b0f099be3406878823db44c974e5228184f67d27b6217fb2e4b34a45883b0cf5c828b7accf50d1fca713ac9479fd864d" },
                { "fr", "4d46bdbeefe83092429e5b0c67728206399c4c5c29ddb575f75415806e12c690ef68d268ccf967c84dc55810a13b183e250fab596948022da521a45d25455713" },
                { "hu", "b4a509cbb77e68bb0498acbd37bbfbc10f467df796bd165cccdd2d49884e326dc3fec8c0ac9bbf0da1b73398d8afd8715794baa7cb0b54b5b7d41b3026e4197c" },
                { "it", "a60782ed7212dc147d51864b31613d22237b005c701b3eb0dc6aa5c546a2014ce7acb619b303897627a910ed52293a30fe8494874517a2e0593d13714787ce71" },
                { "ja", "dd7f921511e09fb9d7ead15f8c4bb3869678b2c6e6cf65a433739b38139484e910da0c6a19929765a5a4cc93119a5baecdd38dc1594d718467c3aabd603c5a2e" },
                { "ka", "86ee3511df65297f0e7a9e40140029b4db66caa2b688724c420c2f3932a55504473e9a5670ecc19fa0d55f56b3071c7be595f2178fd791c7e1d369f50284568e" },
                { "nb-NO", "bd19dc683049426d475d3232fb593412258b64d1359bcb004a9b9af73293089861fb7f0e571a5c879f9636f598db334a92bb117f6cf2081fe6ea89f5e8d78171" },
                { "nl", "61a6964405f8f864f3a6d0a9ef13ff90b030fc5f21b88f29158219cf7bff17c8601073cae5d9f99996d2928b84d9fa6376f3783e3f8e46f9413857a167242baa" },
                { "pl", "6f9f083915e21da4d4c2e18342fd6d5d2b7ea4cc0f521175edfcecdb736c15725ec9a12962a91474116d5af58d6d9d1959a684758f08fd1913f3eea3d157f954" },
                { "pt-BR", "c457951bdc0bed52d98eade4bf1c9540f06c3c3b419e02da4d364c465c59a95642072b64eb3c169d7c67797b7258f5368f67e3ea2114ba1eec9ae50f6635ff8e" },
                { "pt-PT", "fb33aaaa17da0662b2e443b62822bfeb5661314ec7da5409858f0d564e1552f1e43d727d5cbc97c36a2da1263eac2668f8b547adc5d048d43ae20e33e9d4ad02" },
                { "ru", "b7c5cbc3b0d1fc64a6d005a33711327cefea04fc36f1b123b65f38ab8aecde9df53dcce9ca16242b755dc38fa6a0abda7af83965880f7118e85a090c1ac21c1f" },
                { "sk", "9e9faef8fec9af12b6fde110583f5f9962da190593ab0c2dab0e490352f9054e1cfd7677eeefc9c5944ac806a6f16534afadf18ede4b0eb7f069bd7cb71f9dcc" },
                { "sv-SE", "90304d5e71261aa37785d6a63846fab30732173f821311324998a0d83ff53357af6ff955231f0e76c7f71e7f3b7798b8142c3dfbcb607e1440a198eb11a9781b" },
                { "zh-CN", "4b119ce95c68f1de244132a50b4ca8f3f1dbe196556c18bea76ba89e7d2ebdfb874fe42555fd9533d157bfc2410b625c3b30ef94d4bd4525af47b0401db09b8a" },
                { "zh-TW", "12e071f5c94bbdf258035c50d72c1db3af516507eccb00642e7977e5d46e9c500c3225d54a9565d0597aff9f4ddcfd6cf0b0a9077cd8c23447f897c37a43f4b2" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://archive.seamonkey-project.org/releases/2.53.18.1/SHA512SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "e6fa076818f3bd70b1dc8b4825e3393448ae9b61620f6101a04c71cf74d3ff35d2042c752521d48f575cc68b7199410bb0afaac5a3423a388f5c2643ca5be590" },
                { "de", "cc18a5120ae8b75af59acc9936dac19bda16ab41a3a01b28034c99da85459490aa94c484884478f3c6c5efb0e809c94a7dbf85691f6cb052e6af473cbcf14407" },
                { "el", "09c8343a02e9db25e432fa2c3d11d886f3587b088ed33a12d7e3d6d28cf3e4dd52c541758b72d48fb78acc9fbee5f60e2976e688f1f006972667185006424709" },
                { "en-GB", "1525880b08ba9154264c627bc252b4702ad11f5ef522b0262301b8fcb1ecae28477a8daf00902b9a76aa9a96f4f833f77716b80e84425c5ae7ee024866473c60" },
                { "en-US", "6568ec17c2c5c69385091c85a7b89cf252853792b0c6adbda3463da0fa82e41f6f16fd8ac3c9552c9fa2517d64a121ec4778c59e6f7e5bcbc60bd2887fabb3dd" },
                { "es-AR", "b1bd8e4201a7219de0551fd38bf46ed0d803b09495193d2b7434194b66943570154aab488c3c4888a45817b3ec14dc852d4e3532fdcf736a41d36d7847607ce9" },
                { "es-ES", "20c2578d965d646aa7982226c332ef432d39e54cfc4349ae272829a9bb78f78aac1f4d049f0c82299df455cc86845e1ef9913bb6add1bc144fc8747455990f49" },
                { "fi", "d8cb83c64caa615219d7b18aa31d9b064b0f0153112424b7148ee6cd0f8799fdbbf8ae569e5c217a11041a8240ebd9b9cfda3a57ea79dfb72425adc1b1e56f7c" },
                { "fr", "6aaa938da62dbc17e5b1ae0baae157f74cdc628c4fd08679119b2cae53ae558692b4b32630dfb845e36d99e36e61c55280a37071ae56a1d20eb75e601d1e330c" },
                { "hu", "1a6b57712fd4cd265b4127ab09588d7ae6d590faf72e86dd6574d00c6aff6dbcee1163fd8a327443e40a3e884183d1a363c902d26eedc2b32b9853b919b5fc88" },
                { "it", "f9916fa7e543134aede9fca220814e3e4b70146f9f7c7ec0b239217290d158bf96408f40c700720da65a43dbd5ca83a90f97e0d4222ca3acc5fca59b2d108e29" },
                { "ja", "a1c543a868e727829f43f1e7db3775fd3c75477e63ffa03bdc7a28d34c6c1b27c380b5c4ec7b25fb4a59333b514fc34a21716e5c615e28a8cd269b87975acd10" },
                { "ka", "7a33c64d85fd049a2abd20386a891d80daab929228bafa333d1b62c23e28d52a7073dfdf5da07fa9d146ac80cb56e214220d476bf960eb96aaa2089fb94d9507" },
                { "nb-NO", "569b715d7b1be52c85fb0284b7e470b6dfa54ae81224c37cabc3779b28102d49f65915e51f9ee3cdbdeecabd0994bf021e00ce8260eec8ea744c4eedf3aa68f5" },
                { "nl", "e4b7d423f81b83b229e45524601aeb89cee3265d8bc75264de64be3cf9c082a9e09d22fa55f9f782a6f883155d54566a7faaa02525ee4c61efdee82bb2f7731d" },
                { "pl", "626154a85969c53ac5a9e8a6e3a2f6bf36a403c778454885ed669fd9b324651535e5d7ad5cae0e29bb87f6f641047b57ddcfba06ef6171aed160f5808f3cca76" },
                { "pt-BR", "27228899e0da2fd9ff86eff8b1bf3419c69d4be2557ada6664faff1ef9270feffab649a710c646f3e48092cb7877fe9dd12e71d11267b559890d603836448fcb" },
                { "pt-PT", "2c8ba805c56e791771d51ad2ce0b6ddf014f616db00dacf2a436f0be2d3ccf9b3c15919bae865d9429d8907b5091b4e35e740112f84d3f50be755cd63178da17" },
                { "ru", "cf4e447c0f2efdc9d682b3d5410ce068d1b6e842ccab1c58397690c6268cac6b48c3780155130fb33d8e803f6ba444f926859e4f45e0a7047d06273f12fd8ac6" },
                { "sk", "cd5c6035d7f5951f369a04b12196613d842db9bbdbdcebf9ec5df20406c41ef67194fa2c8aed308906d33c6201e3f070c223011d35e58fb9c5ee3bd0b59d36f1" },
                { "sv-SE", "d339ba2a836efeb1d7b33f5df64b03fffff8c8999f1e16b7d899a2c4ca028be41c59229606730b6f818d0ff3ced7154923059067c775f687d4e9c628f77d96e3" },
                { "zh-CN", "608ed3e21a312d10c66d6e2bb3958208443487a7ee89b692a2b711125773918273c2e443eed86f2e802a2618730bdb3c0705e4c89477acd027fb11ea00a06563" },
                { "zh-TW", "41135418a7723f7075f7154e310b4ebc8e6a0e1a987356f407e06b43b5872d53a2760ccb28f459fe5d1fe1b1a1e39ab40f30d8f5222cd7955c958b2bbbd43ca5" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            // Just go for the 32 bit installers here. We could also use the
            // 64 bit installers, but they have the same languages anyway.
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
            const string knownVersion = "2.53.18.1";
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
            return new string[] { "seamonkey", "seamonkey-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of SeaMonkey.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
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
            var newest = releaseList[releaseList.Count - 1];

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
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
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
             * for the 32 bit installer, or like
             * c6a9d874dcaa0dabdd01f242b610cb47565e91fc sha1 41802858 win64/en-GB/seamonkey-2.53.6.en-GB.win64.installer.exe
             * for the 64 bit installer.
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
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128} sha512 [0-9]+ .*seamonkey\\-" + Regex.Escape(newerVersion)
                + "\\." + languageCode.Replace("-", "\\-") + "\\.win64\\.installer\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha1SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is in the first 128 characters of each match.
            return new string[] {
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            };
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
            return new List<string>();
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
            proc.StartInfo.FileName = Path.Combine(detected.installPath , "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// language code for the SeaMonkey version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;

    } // class
} // namespace
