/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020  Dirk Stolle

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

namespace updater.software
{
    public class Thunderbird : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Thunderbird class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Thunderbird).FullName);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Thunderbird(string langCode, bool autoGetNewer)
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
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/68.6.0/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ar", "9085442db4f1502ebfac9d3c6bf8b19d738d18c1410c45b41601c96fbdbddb0a5b19d6fa01b717a4467dd9ff936b48367a9cd81d7bc10ce79ae28e786c632d88");
            result.Add("ast", "a8f1385931de3739f0fae42c9273b82d19901ab7945060107e0c61e729689c33c3dfa7396f08cca9c710fc59adf414269581f11745617a9c3970be556f584f35");
            result.Add("be", "5d41d54d09b65f0a2ba764a9b106ddf713e39ec01ae3a135b970e820a3cb2447472f4356f8348d4072e572915150601e96d3adc8f3aa5f37c4b83671e0f3c09f");
            result.Add("bg", "ea739aa50a0fe3b3d11468959da6ba5a225ba8ad5b27cec469b150e2dd241d396867af6e84755197c692f6f3931e19eb78fd1efb0b8843e90c7097056a4b3928");
            result.Add("br", "5951456a74efd2758fd2a4830b5b61cc69920c2ed4fd59b19da22cf0a69905c8fe76b23661c692c7a114ee4cecee8d25e2d7b430d89400a94e5df880e7250a5d");
            result.Add("ca", "4db9e9e4b1ab37c5f8e0b6c3ecd79711e0f7609104e3f3e071d31eca2c62e5dcb8ae105ca4b535f6723e1baa712bd30a05adc2e576c4f38f52c5e1e1a7e8663e");
            result.Add("cak", "103d0958ab5df991d8704738dc7f2882d27b24aa1e8a815dd7caab997674dc4f15c2a8a7fa36fd2d36355393dcc3a17083e89430c66fa7ce1cc2b085ab889e00");
            result.Add("cs", "29941b66d4a7d5d7dc38e0f43e33602d59b6cb02412ff443bfdd932ee5c92140c04872235bd02ccfc34e7a674517fdc05d9fa1389ed1603cbeec398e1ef12a4f");
            result.Add("cy", "cdda8cb350bed3834d04f123083e99f79c66fe4d5bb6451e592c58a0ca0404dfaf8a315954656baaa24ad96f96f64df2c1d8495c3ecd338fbc71c30258d579dc");
            result.Add("da", "31987fcbd79326acbb60e1cf13b3572aed2ec180258aa4b30a44d29d9d078b595e2d7e272420cef6db88edda89486b049137dc49e0ca0a8cac7a6fd7569942d1");
            result.Add("de", "b47049bfe5abcef0e49d3aeaf8028839562cf90046f9576759f2babbae42d4a23f06392bf0da1b8868289d322ba4ea9c16ca472872715807e05ea0a5dbf3afea");
            result.Add("dsb", "32ece6e9c4dca1b8ad217dc5ec0935c543ddd0e9a856c62c229416fa32ce0e15298ff82e15d9f15bcf2caa698bac041bffdb7e4e9b4ee4a75f144d94e05a0fd0");
            result.Add("el", "b7f6963489405eb6fb7831f83431f27bd44bd49bc549b4ec6482a65fc25e371229c44b6a4890410f1838da48fac75e6705cf9a8931a8197b918ffa70244027ac");
            result.Add("en-GB", "164503f946ba81dd49c0036db9cb75cbb0034ac7115f49d809c22a990996ead7c207ba1733efa5178d416323c22452f0ae32216756ca417718a8bad8f4d46c2a");
            result.Add("en-US", "7a52a569e5587bb92cc70f93d719a84ecc476ab6fe7d1f39e24b15fa70f2bc744950a43e368039b9d409318a84b49aab684670b9544db2be24fab3f81b026afd");
            result.Add("es-AR", "305d7fd3064fe8aea0c16dc7c3685b3606338790cea495b490fec4f57b7525c0c33a169d79ca1ecb8207bfcb8a79906000ac4caadf436a20b616d76b47bd7ad7");
            result.Add("es-ES", "9dc65df2639e71b46a0d93624fdc8c7fbace36dc689830564ee1b7ca7c9bd26698f8b4b197fdddf71a2feacceb13a5e1ecc38e1f9111b2458ec844caae9954cf");
            result.Add("et", "425907795dd6349aa8352445a5b49f19c24eb8f183b78a56635813b54cddb8a763dad108c06e07b36a4040031f055cdfca47da28aaa0a3ce89dd959a3a07b1ba");
            result.Add("eu", "fbfa41f8b190650413d170935e2762726ea4b5f30b37e95203abc399e52fa264e57070e39ee7a24b667afa1d741b530d8cac0c554fbde04f924e5d0800f2c864");
            result.Add("fi", "f5109c3b045e8589e3894edbb35e3bb3451774e94e63ec6a9fcef4d711f950cb935b154a47d4e0b5c57fbf2873e9705971e1e859225d47d28e9b91fa6a2f7c4d");
            result.Add("fr", "b8474e6f61859fafbf315ce23dcdaeda35d032a7f6ad76becd6314c4b9217192cf3e9ef673435bd25aa4746da9f906f49a3a7ba1dd8ecb3b9a875903b5e8c901");
            result.Add("fy-NL", "5ed956275f70b32b8cee45139a163b7ae0af406241361297c58041a5a884fbb3085bad63b7eec426e5f9b532d500a49653a5f7bcb75a7d0323b2b4eae46f8570");
            result.Add("ga-IE", "5e2954224e243c5dcb4eac6a5a8fbc54ebc56b955d85325ffa21db9a8569cbb647bb92965c17c8b4c6f6aa7e33fb5472dba0346ca6c572c6b4362b9f8e111b23");
            result.Add("gd", "f056a83189c4232c0201a2cb75f0b147b38e45251fb20536dc986aa70b6cfb7df250685cfa22235f340e83f30312198e0272a21e16bdc866634f59b66fde89ef");
            result.Add("gl", "c2c4844720ee104eb919162ba7e736dfcd638f09af61be12b252d06fc3edd6f660d7c5889626495427caca7e4dd4624cfb95c64e5ed9cb6f357e83fd984c709b");
            result.Add("he", "7bf6bf270598f6a4cccedea31b91fe5fedca19847408915a852f4d5601738a5500d2de07bef8c58b9ac8dbdf9df2f88adc6d028296db0632cfc781a3a47c78c0");
            result.Add("hr", "56119be78740956ccf473561b85c23ac41583711a0cc12f5e2057bd0497278c159643f4bfa433e953f2d9ce81ee09a10b21476fa7ace391f11434788e7ca7c91");
            result.Add("hsb", "e131f32d06312c40653cdf3600b070c3675ef8661ceccbba4741046a7980ca423096090e80d4c06caa7396863d22b952c8cc6bb03a3fbda0d56e5f746c457306");
            result.Add("hu", "be23d0be2150bafc891687cc43ede98fd94cbec7a180c3924b447b026b8e2f5f9a1ac1552b345b55a0b4d1d6f0b48e717536391eec338bed49b0f5b620035940");
            result.Add("hy-AM", "4ebe83b01a3c32ce9d4fb15ef126c994d822a928d6591f2fdd47b1035357e94fe39783f4f4755c7c4061b0f6a232f567d4c76cdfbfb47b267db69b4252c1c6d1");
            result.Add("id", "e377e11a011e1e8e10bb2c0378b707c9b820685135483b3551e7ba9f7543b5c418452b8717084e9d05cfcb3fea3147c0ac7904e5c3237d590ab86b3a3a4a464d");
            result.Add("is", "c303f6ed466676aa8635ad2a8592846193d2326b616e19228bd9b65778b8e3b8bfb6bdbd6213e0f98e71ab74eaf1612e199cc1d544e7a5a9e5ded10faf5caa37");
            result.Add("it", "4b948d657400c89539a7846772bf4f771f7110a4a105366c30705e07ef275e96a629ceba7873a2933e1c955acc1775f14147678abcb5ff062cd882c861534ba4");
            result.Add("ja", "0b9f3b2ba95cd0619510fd44501fadea82cf162f10743dc6bc5b8816e2df0e50d2be724f43068bb470e1bd67e5094b64cbbe62081b17b2a06e83559b7406cc68");
            result.Add("ka", "43c7b1631767715b199711fed53bb7672a614758dbd503356aa18980671d62c7a01034b85810a19d6a67caa5fcbeb9703c00aa53aeed26d310da8c6e75e7a6c8");
            result.Add("kab", "0fe0a5a013bbdad31220f3d37c050c36a91004080a6223940ac3877c180c3d3d22dddde8d98abb31773cd7e3ae184a6c510182dd23729dd399fa6ffa5e9a0fab");
            result.Add("kk", "36317bd909e8065f161ad8a28333757e0c820dba149c48ee56dcae661965f8c0f32cc9215661576bce54b9276187f9fc8180345da5c53dc3103579e0fc5c5dc2");
            result.Add("ko", "75bb361673d812503287dc36ac8a9a545ae58d3931832abbc4debbbbb7f6244996d35c07578f7993d8fa8bbf5014a23ad4d05d9dcd79008ebac500b0adb4aca5");
            result.Add("lt", "2cee4ae736250a1c0c634dde25cae45926353ffa0324abb893fd617f525d13e694d46b2837309a382b3741f2798fe017e61bab3b4351668b8520537c0968d9f5");
            result.Add("ms", "a6974514835aab19435a907fad4e7f78917fa45d415105889b6406abbc6e11322a10c459ad5456dc0d6c10a168a8f8c8721a223db897732ad57c07a26cec46df");
            result.Add("nb-NO", "4c65db6926dfa3a5500afdf62bf1790728243a62ef1b853934a4bd3099fef9d8ea161fd99cb46edea50c9c722ee5104856201907dc0bd3f7f56673bbe4786f3e");
            result.Add("nl", "99e2605eeef58f5a7ce1399e47c5c032a602360960ada4212cb6fcb59b7d56dd5b251fb1bcc819f2bf89fdb08dab832a660e9395f22aa6e712f102872cc8f04d");
            result.Add("nn-NO", "300c44914c06983a737e51fe76639261b8696813652ed839383999999af981b85fef8ec38d7e3f65f0e82a528f3f0b0b7ae9698c1eb43d7b98bbee96e191cd4e");
            result.Add("pl", "952bb0bff8b5c136286773b356f0c6656f0b09e3d377fdb0bb94548965f610626addeefe1ee7a71dcac8034e41c72a7df844cee124ee3b8905a06581c759c213");
            result.Add("pt-BR", "dd78dbf64da850184a4e972ed4c44cb2048ed36274509afb7a97bad3cf8f7bb6a2735fa1cd36abc07c59b9e4d12b76d7596791ff7ec5413089762c83201da138");
            result.Add("pt-PT", "334fee3e08c4430bd46cb76dc2db60991f2ea2643a5c7710b3e05e24ec9d856248662c7db70c20034777ce7304350831501e69a545bedac82384060685c59f41");
            result.Add("rm", "7b37427a0f020c06b8e94a68d7f39d9c9cb5d8796f5e25030ca696c43c2aae6c6e9c885e0045dc740b87545a18bda94862fc29c6ea2fbc0bfee8cf72c609d8a5");
            result.Add("ro", "23c10731fc32499e13c1b0f94a74abb95545b64ae90be47c3ff33ef13f85c5a5f280ecc487145afd87ba9b32ccf8ae474b16eb10369c4d0a847bcf78b8a140cc");
            result.Add("ru", "ac85accee20e2e25943acaee94657d493f97051eb54b4e9196f741477e82e663e595cac956d52c816e833caf4b95272c47d0c255e3a02765d99fb3f82696dc75");
            result.Add("si", "0f33c36ec5baf60add6db56fecee0518d422dccfd74aca9443a8d7111223c578cd9808870f33d8120593beffed1fb8069cf3571b99f50f2e58fbb7a2217eab28");
            result.Add("sk", "ea720d62d1677e3bda416891137dcec8609e50941ebeb258a85b73870e77e7cbef483111cebb6dfae00b212a9a88d2dc39479fca2910827d87022b7950f7227a");
            result.Add("sl", "9f8e56573df6d8c457c2e8656eec8d0514a490145e1ddf332fe5b9b20f2cb7b14a4ff099c044ee3e37cd3980d2e6eb7a00754dd7ea030fe0172337de7e89589d");
            result.Add("sq", "fb5f03007cdaa8718052424eab0ab70c23c158a4240c7820e7328809297b53426b9dd94d4c0835405d90f725a0d9cfb90ee75eafe6726693aae0e4268642226f");
            result.Add("sr", "1448e603638a9f04042d01cf7801a4f602164d4856b67aee4eb20928171582f6ab29c1ff793821cc40b6099d655db31babecec286f550b48d4d404b8e0c284c5");
            result.Add("sv-SE", "8b9567ea32edd67329f5b2062a5cf3a52a6a09a33ec264c2907cc0ab331272f5f5884f0f31535b7c1736c815b41f7e57c7ab809743ca97331620ea9d1fa02442");
            result.Add("tr", "47a8df864dd0096868a37ab18de25f716d5026fb08e5b90c65a37de2a9523b34c6dc1df0cb24a30703b683a7b7667400829da8ed0fce553210c9bec65bf6e1a3");
            result.Add("uk", "1d1674cf444c3a55730a644b1169e0afe5c4e93b4fb51e0266a02bad5e77bb7e985f918dd4603a77e9d9d4a5639a71eda8b8f3e116c3b1f0fcc326b33e13773b");
            result.Add("uz", "333fff473b50c5c8aaef67c59ec9c284652d3905324aace8d622381c9f0d5d5157a2e0e2c13a00a8a0a448196d4c69c9355856474a972769c9620372523addfa");
            result.Add("vi", "cfa970769ae3f63ee103b7645142124f6c7e5d61c5a915bd698e077542c8b0e88c0e853e3f55b8dd7d9d1d078b41f819cf33484970c317107dd70069f0eda51f");
            result.Add("zh-CN", "590639bba3666993a16ccc97cae1b9ac9ee5e07d40d5e7b5b651225b9f8350f7fe10b5c5a060a9640042e81dd8932786c202419407c21da1811a8dd9e6c8178b");
            result.Add("zh-TW", "2fcdd176f370c9ab4f8ae368d90e5303977c28f89eb3e54f6d7ea7c16308389014c48d42eeeb4f6f878085e15a70861c1ba8fa90d01b8cff015f918915e5aa70");

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
            const string version = "68.6.0";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird [0-9]{2}\\.[0-9](\\.[0-9])? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                null,
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum,
                    "E=\"release+certificates@mozilla.com\", CN=Mozilla Corporation, OU=Release Engineering, O=Mozilla Corporation, L=Mountain View, S=California, C=US",
                    "-ms -ma"),
                // There is no 64 bit installer yet.
                null);
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "thunderbird-" + languageCode.ToLower(), "thunderbird" };
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-latest&os=win&lang=" + languageCode;
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
                Regex reVersion = new Regex("[0-9]{2}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                
                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Thunderbird version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksum of the newer version.
        /// </summary>
        /// <returns>Returns a string containing the checksum, if successfull.
        /// Returns null, if an error occurred.</returns>
        private string determineNewestChecksum(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/thunderbird/releases/45.7.1/SHA512SUMS
             * Common lines look like
             * "69d11924...7eff  win32/en-GB/Thunderbird Setup 45.7.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "/SHA512SUMS";
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using
            //look for line with the correct language code and version
            Regex reChecksum = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum = reChecksum.Match(sha512SumsContent);
            if (!matchChecksum.Success)
                return null;
            // checksum is the first 128 characters of the match
            return matchChecksum.Value.Substring(0, 128);
        }


        /// <summary>
        /// Indicates whether or not the method searchForNewer() is implemented.
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
            logger.Debug("Searching for newer version of Thunderbird (" + languageCode + ")...");
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
            // replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksum;
            return currentInfo;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be update while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            var p = new List<string>();
            p.Add("thunderbird");
            return p;
        }


        /// <summary>
        /// Determines whether or not a separate process must be run before the update.
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
            // Uninstall previous version to avoid having two Thunderbird entries in control panel.
            var proc = new Process();
            proc.StartInfo.FileName = Path.Combine(detected.installPath, "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// language code for the Thunderbird version
        /// </summary>
        private string languageCode;


        /// <summary>
        /// checksum for the installer
        /// </summary>
        private string checksum;

    } // class
} // namespace
