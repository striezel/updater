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
        /// gets a dictionary with the known checksums for the installers (key: language, value: checksum)
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/52.0.1/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ar", "99f081d472a952d929b96f5f55a815526295e271c6838b8e59ff7d49216f89b326cc56721e6e45f0ca6d2baf1ab17fdc193dab896a2fa2aec8977b39f86af9f1");
            result.Add("ast", "12911842689338cc7657ad5d63d9a9795ae1906c479a96259b15ce00627220ddf2cd188e9938a7824ff0b8762c161ec82484a7958a79bd1a284fea55b7cf6a86");
            result.Add("be", "2aac9422315f3af7bc7d989535d56835b6168f2140a2be9529ad38d4bcb0ac703f618272548cfcd6e44e44c2dd99695f8077e869e90a3838f386d81c451ec103");
            result.Add("bg", "9a50b652afbdd6e2a8148bf2bb4ec85772f6e124e7f60a7d67b614cd68ab208b3e097079ab8ea837fb18f6f8e277f1be2bf3bcdba5bcef1f7b914081afaf33ee");
            result.Add("bn-BD", "233151b6a8f97257625ef237800fa6a50d7c6e4cca9d774c300cb1503e52f3ca422258554ff11bcd118c488bdf63cdf0542a943916993ba4077181e74c44cf1f");
            result.Add("br", "412d55ff70fa58412159bd2c6a85c360dbd17b3074d306e07f3927981e88dd0de688cf74dab20200f89b9e83f6963e7fb507644f199f312e9cf7b28b6be945aa");
            result.Add("ca", "b3ef504b88b0d18d28a6a4a528724597cb57b01e8f5a4a77601b241554f844c30cb4564b49927f6b0805eac22390f4e1f1807e0ce6bc490805cf2c72652e9976");
            result.Add("cs", "907024a43c56dd17e4e4c15d8654be4d30aabab5cd517521f109b869c6d52c57fa3d9fa9d7e29ce1cad6f4fa32718330d66dd88fd56b6f30058f3bee0dd14690");
            result.Add("cy", "4f116758831d1cc0a72a42f40104220bff39c0caa8e171db6de81f13946a519ea57a11f386c43d198b6d766417f6da1354ec73b467d88ca9b150aa08c71e8a1f");
            result.Add("da", "75108cd58490e9d09e19b29dffa2956ebbce8c956a1acca6a8c70d1d016a6fc4a175530643b7f47cae8edc0d3a59c2d567232d036c0b95c609d4c9f5a65cd51c");
            result.Add("de", "540c7a6af9f4640bd36851d48ac685629dafeb5d3757f8359b8d58c0325430882cfd125ba16f528fca9cf84faaffad227f6ce97c7ad3f08ad85ffc3a2323d65b");
            result.Add("dsb", "0efa99dfb15f8c9cc9f769a001d9d4d3d372de3246d17b075f281eb2325ca81a6b0bdf60a066177026b7a9cf87f99e0e00412b16daec49a3c432b65d4adac7a6");
            result.Add("el", "7daa07725ba805ab93214dadd8a432ec6c11c04e8871ab6ee1c7020753576b31fb596f5102dcc5b4e9a9ff7f3ab57cc46c32fe457d38e34db587fb9d57110045");
            result.Add("en-GB", "a40e68fed03a48cdf161d1c2be7b3950273c5c12aa3f6a6e38612db871799d81ebd61c07ea2bec5ca00d91c8173f393cfb96a83d52b0fde027d9bac40a6db645");
            result.Add("en-US", "0e70d0389d5356930b938f523311e8eb7f9aeb707ed6d39443e78b27f6434fe3dcca8a9e917b6826200b8bb005493e4e4a25bc071990cf48dba3dcafdcd079e0");
            result.Add("es-AR", "0798fb63f228c47c6493c071551cfba5eb0b5e60ba2828e80f2a0993dd1e0f8b12262460b44a35bd6c103e5cefd6402b9e25e8f4b8d345a670202cdc2825278c");
            result.Add("es-ES", "6331e5f084b0658066113f1c905a4098cbed000522db358a7bcd42a55b175cd390b75efa51ff7313871189ee374760cdb64108d4709ef14a3e424d6dd32a953c");
            result.Add("et", "9f4a6cfb90ba167d696e894e5c767fecf6c902edc18ae465c34d20512a695568b18b7612070245a13d7c74376a6ffa9e731534d70da6b0fcc59355a06dbc5ae3");
            result.Add("eu", "443f32bf75f423ecd2c6a97f00ef9e0112eb063970932ef8be25e1bb998ce894f579131058ac9a42248cd8d277c0bd60f98a3677ad28e8cdb9a8f636941b1dc7");
            result.Add("fi", "bcd8a09c2faf1d7dfadcd883565c3fbe166d2a2bf4bb254afea12249934346c13d236f606bac0be404108a157b53a546e7eaa05e1c061d7ca9527829b9fcaaa5");
            result.Add("fr", "2f35f0aed10c22611ed88b9fc2496383e232e21609c62405386c3f8bc79c6b53bc9d6c08e11287d61ee3762e0cb32e89f2a44a14f258f00f8bfefd0224e3d1ae");
            result.Add("fy-NL", "81d60c8b186c1668ee2fb423f668f51457fcefb2c0aad5a4994f7910a3d1228ff1be6ee835a2c9d54b6c5ed1ca587017dca13a42e55d354b3722da58ef4e2f68");
            result.Add("ga-IE", "df5da2b4dbb130577c8770f02cbc41310ef7b0f004038bf39263723721e087d9d5b5d2dee35545e54054d19682f0b5dff745aea2d2ccf02154632c2071f4de70");
            result.Add("gd", "09d47eaa8c92b2608296d74e00dcb5e1806ede0bb68957366fa48e00d84d8bebd94c2271bb35740753d4c0c5a40e89b26e52c3394a1e072e59bcbcd8210b8e08");
            result.Add("gl", "5fc24cd000a41c21f1a48df618e5fdd1bec4668288888b33f4155be3ddab85e3dc2418aab6ce593fd00ea8561a983321914fc6fa5591b6cf7477241cd3c5d1ef");
            result.Add("he", "0d97ab27d9bac37ec68314fd1c36d3d9b788921b13d2091b257a30704fb01a81c12e75ccd641cc8670079929c6b53c14aeb8fdfa5abbf54da87f8bd2eb3d8f40");
            result.Add("hr", "b677ea3b913fdec806157554976da69509f86a8249348b421c89a7b377c6e9135e1727712861b2f48eb5861149907ed655916aa340f1263991efc65bbfab2b45");
            result.Add("hsb", "a1acf1b2638235e0c9f11e01aa7b4a52f77257c5b04250742df5ba6a1e4c6bfd67d9923ace7c9c909b25aaa352389dd6b1224558511f31d09a07738b6c6a401e");
            result.Add("hu", "a340c99663f13e1250d75f0292f49bed214eb0d40240f57263c9d453d962a60e7e03cabf0ef7862fdf070c2d5a8dade5f87af39d9438d63af0b2d60093e3e22b");
            result.Add("hy-AM", "a8cd5bae55ab8c6705638613a5707ad27dd3f450feda4ca1b3d5c05510e2c2bf46f978ca5da38998fd98b00fa6d9f3c7f9a13a6259479a04aff1cf3bc42f1798");
            result.Add("id", "77ea199fd2a3bc1fc1148e95517cadba40adc4e70710b98dc5a413541be6e8217f96aceff0566f7c2908a6e34ca2dcf54f20a5850afa2a135e7e9a03fad8baac");
            result.Add("is", "8bf2025749b12f4794d8e38b2e2b639e10d8bcb0b99748b71eb768212f21a41dcb269d0fb5450c92e4e417c8c6ecd6afa23c4e138136bdae400d08c70b4ebb85");
            result.Add("it", "82f10b2ee7161f0e81fa9c055fc3ccca73cfda889956aa0635fcfe52efa66a407b0d073f2fceff05873d9ec2a0e1ea369bd3eb972dab21ff015115a06e372644");
            result.Add("ja", "89305f0f15d30ac170321be11771b17bf3b8898ea5e30bd589bb60d930fa148a5a56e135f5c35d3982681cc0d448cee4bb80d87f724a90ad66317cb6ccae1fb8");
            result.Add("kab", "9e6175f1a5a707f5662306910e3b1675b57f0935ff5ff89eec50c4eb4bcf409a5f0149365813422d2bdf1aa0a2b4bdac274d7d2d23f6acb9138e32c1cb972797");
            result.Add("ko", "f7053a0339c1f60298f1ee62eaa4abb99f33687c339cbbd1a6c6ea2a5bbb4d10e3b67a05191776cf0189290c9e7b57e7a358b287b7ac2379bb7bce2b650e0827");
            result.Add("lt", "def502e9d14c4eb8840de9e1b3fa72b06f36e5cb535617b7074f30584db49091e680033a5a3834a7fd7541edfee80984377e292aaef823f43395847c9db7e7cf");
            result.Add("nb-NO", "3c91a440abab49b6534cd5fb2ea62d1fc4cf88896e22732476f5cb5857983db4511f76cda8af4707a4c9c4f98daa268d59b0e909e7786c0c9b4bb34dcf106a29");
            result.Add("nl", "395d2f42617c8c146308a733e9e4ea828c6e932cdb801c76e85473342890327e52fc6b5b1a02f2cf2833a3d2242bfcdac8f9686ed59aaeadbdcb8ddcb865279f");
            result.Add("nn-NO", "4def33e485e22734d517b6aa3aeb1e690a6b20eaf1a1c51e05312345fc6c5f867fb4e6e26b48a8e81b866eba37589c087eea5807e19b80737cbf9842f07fe573");
            result.Add("pa-IN", "c8e16d8cd3dff6171a4bee4560ede9041211ebe6966aed46773759f048e3fb896b15cef8cca4b2100957d4386374e8cfbddd720956a08e95ace0bc54b8d0a3ac");
            result.Add("pl", "495ea0d1734ad7a7c0e3873e16300520123b85cbf90895053f2aab17f8090b4094ea1cdfa1ebe8c49b4fae29d3a56b1ff49c6a13cff61aae64021ab151156b6c");
            result.Add("pt-BR", "600534dd47fec389f50ac4cab9e2e90764fbb08b495b650d67d23ec57fda0dda56da9ad60607914f3319f2333228caa4d402bc7c82c88af11832c14a52056c7e");
            result.Add("pt-PT", "6a568da59f68d639f1dd5c52ce0953d651289dd2c1d4aa6a765ccdb475b3e926e885305d342dad5d1f95db3d1c5eb9717dbcfffdbae8fd0dda01a20ff060cd7c");
            result.Add("rm", "ae01c5eab5b28a7a0891e0ef96aa0ac4d1b357f3896aab7c4252ca01154051259d9ea6972caeedc77b4b076936b84089613bcd2b8f4edbb974e9c73dd40a8f74");
            result.Add("ro", "0db6a9b47e2cc33cfbf0c34fe03ce00932837e0a649902d95741b4912838f134ece43458acd831265c6ec52fb7b2051d296a30930ecc0a874d0585f3ea65b6d9");
            result.Add("ru", "08e8219c8edfe9a288d22fe5a623e8382f37ef60d52924ee5f8e336fa73efc9be600f17657d78d8fd99d2117b02fba79f276f92723f994842699408d49a6d589");
            result.Add("si", "5131351d638d7e7347d480afaa432f405477939ff49bd0047a3bcd3728957d224a5b983bba5d892a2f5a7c3114a1db24537cc023cd4e2cb6903e18c9326ab656");
            result.Add("sk", "ab5061b4626b1f62b98ae7daa56d9835ccc83b5713f91a22d1c469088f2b32b1871e6f9420a9aff429df10725fd7f227e2ec4c6f7af85e14ef6d3d5da53c00fa");
            result.Add("sl", "77712ecb568b5f4e7c28fee59f8f68aafb988661dab1a4bd84496111fa6bc735b53d5551ad61ae406d1622470e31ca40a9ccb3a73f3ae8d60f7f89bbaf82f5c9");
            result.Add("sq", "345b16aa33bebf20cac31128553627ffddc398e81b1570d18fbf4c55fd6bcbc3ddeec5469cb2b10b60148f7cb540bd656070a21aa03f8a3c84abf706367f7ed2");
            result.Add("sr", "63b4eb1073fde1cdd000000779897978a74b91ad577240957dcce1bac916250a1f1577d976dcc6245f9cfa0e372f9d4626a149bfffbb7a8d74285c0a28ed8664");
            result.Add("sv-SE", "7db3e84a90c8324811954092dc8f30bd2b6f40b1fb4f852541e25b285a7c2d0afbb89a31be477ec19e3fd933bc554326f3b6fa9c66789176c98118db11b7fb52");
            result.Add("ta-LK", "c3b45f0b4cf831ec2f934ac1f1499428331b2f695c273cef8c4c90bc800151e385aa9b315b60b231747f5702a8f64e0c707a6bb651450e6d6f2539051ca6da8e");
            result.Add("tr", "7696312ae9c0c2d403371563bafe5c83dfa9512b8697f5ae1e94d111e015556c5e7c5d9f27223515e66d9dac257757e0e2eaa85bdbf8e7430cc5ae704a88c959");
            result.Add("uk", "58b6fb8541e80931ec0c7b87b789c520b302d4bef194e0a9f1ea5f77a5a6841648364fca85e6997270d8a6e89dde2850b03faf3ff938f48f2094e09e07a06274");
            result.Add("vi", "37d2aefb40d3bc5edf7e01643a7ac6be6974ceeab79c3a645e7a361db2624e0d1f846471fcc659a6c3b60dd3931eed582e01d686b1423f098eaed5276e8b18c6");
            result.Add("zh-CN", "32d47732f22279751ffa81f1efa07eace21ac6cd0b45e4eadf440134ab7d18242fa9a1e4cee8c9fb95603a7d7ed06f69419e17d427b0b105823e14aa024babe8");
            result.Add("zh-TW", "0051f3d12a1c76dc44263c8771097ee7c04858390f9669e671a42543114e519159a0c312e77cde5f213e1bea7a84dd52e0775aa4ff3e1c703ff67b4f90e841cd");

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
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                "52.0.1",
                "^Mozilla Thunderbird [0-9]{2}\\.[0-9]\\.[0-9] \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                null,
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/52.0.1/win32/" + languageCode + "/Thunderbird%20Setup%2052.0.1.exe",
                    HashAlgorithm.SHA512,
                    checksum,
                    "-ms -ma",
                    "C:\\Program Files\\Mozilla Thunderbird",
                    "C:\\Program Files (x86)\\Mozilla Thunderbird"),
                //There is no 64 bit installer yet.
                null);
        }


        /// <summary>
        /// list iof IDs to identify the software
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "thunderbird", "thunderbird-" + languageCode.ToLower() };
        }


        /// <summary>
        /// tries to find the newest version number of Thunderbird
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        private string determineNewestVersion()
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
                Regex reVersion = new Regex("[0-9]{2}\\.[0-9]\\.[0-9]");
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
        /// tries to get the checksum of the newer version
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
            //replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksum;
            return currentInfo;
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
        /// the update. May return null or may throw, of needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            var processes = new List<Process>();
            //uninstall previous version to avoid having two Thunderbird entries in control panel
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

    } //class
} //namespace
