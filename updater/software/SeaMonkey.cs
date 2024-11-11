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
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://archive.seamonkey-project.org/releases/2.53.19/SHA512SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "2cbb568507ab6dd438f98cc49b6010065dd62d377d97f375596f130a0911c08720d890b5087553f84f485c0cd1d309e8366d3b894388a87babadd56c00ac4d05" },
                { "de", "4731f53363025db357f7c8027336c78b2556094c86a093f6cf6e198f30d19fb75401d6b2bf635a2295d2f5430517a279384922e8ca52f97a5bde12380117bdcf" },
                { "el", "c1f27b47abcb2d6ed910593f425a64245a8bb28eab5532b879b6e73e6d0e837aae21c1d50ce97f4175c4b16f8e18528c8f362f37435180c22e93b45bd231ef1f" },
                { "en-GB", "82423f7316b9ff368f66061a1fc641ef045f77cce2a4fcc847901c3b9e8f7de953eaf570c09b2c7eb7a42c24d9a34369151ac2fba145d625e7d5535b3d7d4d99" },
                { "en-US", "ceffe90fffd40c11fef0759e18184a2c2e7d0a3e21d487b01eef5440718ff926e22c9f0d98e53eafc5751d9a86db3109864340a0e72b099bc5e596353cf4b71a" },
                { "es-AR", "4da004cca48a41796b6ccdac66ad6e2c2e3d0a5f337820aa1755c7fcfa73d211bebcb00a30117da24140642bb46e0b20030ecbcf3b97f2e1c55f76220275d205" },
                { "es-ES", "e90e51331383b04f076fa0cf9330e5756c188fb6dfaa8545639d874a052673e3b72658b71dabb7651e4b9025bda964b6d0e80157b3be4bd3315da12fb185ed42" },
                { "fi", "a3577e02b5e847af979ddbe302443c0790ddedd1808dfc5a47030fd340e15ad4058a838762469f1c24ff46e44bc6bacc6b13f1a76ff4ef4c4f10313c4c81d127" },
                { "fr", "917531f1081a76f3304b42da32798de20f08ddf6678ebb06e0e28fb0e44e0d804c8c4c8630ed14d036d8801c561594e41b0a4353d6b380ef6fdba9f2e7bba5ee" },
                { "hu", "6cfe7db472837831632959ffad56e40b1f534be00db4661e8cd6ad508ccb60596520d42862e841534d0b609d5f0a67677d896a0ff25279009b07b8253f9aefbf" },
                { "it", "cb983160c501ea7a4f6b6c5fa12f358e6dd3ddf8b28611c428da0423bcc2b23a50075d38464fb86fe0ede2b25cd98b3f3de60d4d7146c8dc9138c906d2674d3f" },
                { "ja", "cba28b397b5d25f4dd333e0a6b2b788910ca3daacc7cebf43f8b550e1c46b53048a5e26f12417d410fe57f6e939c61c64dea5d3d96d4cdc2e0089d058f9c3787" },
                { "ka", "4fa2f4b25925f14d0adb626720f6bb341919ab959ff7d789d3f5429fe14f4d6308fde4dc9596171fb9c14d1b0d968cc836e0f509d114a676aef07295388184c5" },
                { "nb-NO", "d491016e7b58aa618c8ceddd67472176af670ac7d7658cb76116c975d43c53b7d9ff1fda941482b02323f6e22082aa51fb54c230c7bf21b7fbf034fdbba259a8" },
                { "nl", "7f4fc2c8a72dfc9f51d9891179c63c179f91370069995f1663a0bf39716ff051e7f18053cae3589f3c2891722431ce51ff780d78202c6b2211ff16f651f5b96b" },
                { "pl", "4a6749beeee43cc9a721a8ab4110252387a2f8f273a97587edc6df2e960baf8e40f8d00f488a5b1a5b3fd6fd88b21f02258a89173ba286830908b20c56639871" },
                { "pt-BR", "a075e920093631cb36a3342ebbc5e73445f62871ed2559d419543b5fc3c3c7cc11407a724e0173ce79b0f4aeb22d46ba6b9da31f30d6a09b9ae56ff11e986e6f" },
                { "pt-PT", "3965f028e22822c4bbce39bee455367867b6e1bf2c387e85286e9827b3f4fecb021b3babf4bb696f7545502b507377f6e754d865fa590fed1fe8d7d893eb8740" },
                { "ru", "eb9609a143c06f9fadd566b7b64a51e0f7c3041c91d6ad2b0eec82f1cb5b8bbe392200bc14c3c3f7be174734f6d8b84df1143e49217cc91b37ccf695613279b7" },
                { "sk", "aaec0b0d230b0c981c13a699cf21ec7813777d1e01d075afba7c9d9e10af84deadab14e54fd4b04e65eebc785b77518be7b5febd5be7ec81240ee2b0c674443f" },
                { "sv-SE", "3f2b720984c590809d0b39f13e0db2e517299a43a51b2d4ba010d30dcd7df4912707bcf4e3b9d7e4b09cae84d1d192d81919982988b6eadc903b15ade6fbaa7c" },
                { "zh-CN", "db2b93ed7d0dd7089e0c841bf33d7ba730dc1f4ce7561f5d441c224d94c5279a263a12cf9316c05930dcb4a9b8bc373cfa6028217e56235a7f2f778e131fb95d" },
                { "zh-TW", "15aea9cd424faf9546fb99009d8fb5a92360820cd7b3b7c321640478540cb9f803f4f9889c2f2d666cd77964a5f951e6a24fe3663de688eddc7dcc188aec5669" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://archive.seamonkey-project.org/releases/2.53.19/SHA512SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "859b3ff7f8a9f1e6f998a9e914302f8115fc86703f74cda9e5dfd1724317ef5a09e76bb77b842c4c8f6965b20eb5e89ff166e92c753ecc6929d1ef54a4b67225" },
                { "de", "3bd4e5f6ebaac97a57d6d4ce75a0fa8ed3d110198041a6120b636ef8d1a2f45f215692a4637343c05619d3ace0e9695089810661b70cda67a919c19a0af713e1" },
                { "el", "d8d56249124327b14d4ab11369062ac73593466036d51d3327a0bf5a700d3dea530cd7602d8d9a014783a299f4c30582bc8decab9670a700fbd693d1f4176611" },
                { "en-GB", "90e523d7754f887d4e524e545053d5f04a560390883bce80fc17b36bccb07dee35957a483952d09576341c40db76ee1efa408e3ea3639ec0d01ce1d84d999e02" },
                { "en-US", "41026697a2e1da5471a11be61ed71288e29d6e0ebeae244ec40c06255f250b2894703d62a32cfbf1d52df759a93e21e126f8f57314c4d49ff15a26cdb6d3b4cb" },
                { "es-AR", "58e8e91c6050f2acb9c6ea3dee0ac4ad1209a4e3f0cb056413a29aa762a71f58d81c8d9a9c5cc27de6df2b1f78854461e6673f7b1487a45c231e6dcf71804d53" },
                { "es-ES", "ec7dd32e898cfa7a325474162f8dfb727bafadbd1c3ae7b0b88f3fef79fc1613f7e4018f52491ee634ebf215d6a88119e0c391f7fa935f06d9bfcdf44072d93f" },
                { "fi", "c531c5be28c82150697a02f17f66f46d0b99c958f9638fc726b836a9248ab41109a2655aa35ee3530ed5b58c3d0c0072560f44c4fc971561a468d269e7f0eb4f" },
                { "fr", "3a69540104d09690b19c5a28322111735d9c9c0dd5b83abdbb027830f8c83cb783e2b7ca2c8a4716a5ae0250a60ef85b8bcd3b45319b9046146b38f9d04b6a33" },
                { "hu", "029314927ccbedcfca03efcca8f96bfb001d7fc51115089a0a2a282d7345a29b2100dac283b62273017475dadf1b5cecbd1e7002fb18d172ff98dcbc2469a54c" },
                { "it", "dbeea13cb7763499c6b691fdc7a019dc2992dc170009602f4755c289f9ef5f7432cf796d7a319894b6e49da1764be6762ebd02822dbc20331a2ad6d09407370f" },
                { "ja", "326d81606237ba1387ab47a7d1a96392ff634d3ac8a2ca1294a5bcaa2750211c0674e9b252fba821a5b1afb86e7a8ee54ac728d32b4f19f3d5ea771421af084d" },
                { "ka", "62e6e8dea9ced4bd73725db0e637430cd529b766c3e095dafac6a752a82b2b3a6ebbb82293f6691a284a62cc93f0e552cd36858c6318ddd43070ed7adc462069" },
                { "nb-NO", "119129f025f9d5ffbed3ab463ef753270981675e08ceed9eba4ce50311ef86eeea89b3ef2b78549a07f061ca79883f27decff019deedec4bdef3c44db88fe32f" },
                { "nl", "2057f952b45e45a0f9f2ff088698d9637819a60f9d7cdd5ea465acafb99a67aa727902f7e802fb0c88e88e088204f622215b780b07548e0f8932a7e8648484dd" },
                { "pl", "1b5a5b8342d31035a101af6c4f9c08d1d952e4db4157cea875bd64ec67f8157cdc89603dd52a14c0932ac241c09a0106fdf3f96456a366716815957f6a793403" },
                { "pt-BR", "fdc1fc0deae77a1b16667ec816b6d27712cdb090b6d9421888ae7638b25101aabb2eb14d52f562eacff6874466f4d4591423185381abcda9d92fe9e3e77b9bbd" },
                { "pt-PT", "451d1b49394dcb537faa9dfc7683514eaa35375a2866759846a3136b87d14f0909c25245a1669be5c821eff72701b08ad6b32de563d98cfa1f277e0589cb40a1" },
                { "ru", "3c8a6b846644f69927156fd90d34fdc9a554843054fc7a568d2c69ee357ca32a71e4a94f5ebf52993688aa1464f4f4045ca5c87f5986fd5d779e85e75ad0115e" },
                { "sk", "6a7c6fd965bad334339aba6dedb1fb669f263454b5d16cd4a62829bd120dd37a49cfcffddd684153967bcf5f845f1ef52d745f16b41c6ae79e4a2de61e563994" },
                { "sv-SE", "7500bad265c1e3000acd8d4f77a7ceede09f6d7b0fed1d3e9e8eec99ebf1a02c5b693b8db669d9913c43ea77a8dc170b7924b2b081ea17239ab6aa620b2e382e" },
                { "zh-CN", "454b46750483cbc476245e20c314ab3a30f0ea5dbf02c34ad6d8bebf27e380c1b24c8f149ec6aff95bc7142b70fbad811e8ff6e66ed0e6a4023742ef0427e0dd" },
                { "zh-TW", "cbb6202a31922c1547272312be7328d4d14e6c4a26de95650bb08b39508b9d1aee1859d5fddbdbceff3fa0dcc0fe9aa008563056acb21849fd1866014181951b" }
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
            const string knownVersion = "2.53.19";
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
