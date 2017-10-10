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
            // https://ftp.mozilla.org/pub/thunderbird/releases/52.4.0/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ar", "f5f96c054fe92fc3a67101dbb139894e47856413df57548ab9ed3e37e933dc5b7c7eea67f9e3cda863127b065366b9aa8a87126463bf127b2a7e73b555c40413");
            result.Add("ast", "51b4c34f90cd9b9a2daaa21723b7abf9e08d96d59966798c6dae84445b634b7808f3f8e58041455a18c7755d3a0985d252f9d537f2bbb47fa670ad94ad3ddc39");
            result.Add("be", "fb91e15d7989a57a536e843cc5321ce653d547cba0bb5f2b7894be254b78ccc9cf3955a1470e913c7168483467bb813c9f7ffc374c0e44a50fd414dc40183c0b");
            result.Add("bg", "ca9f6c61135557ad07c8b37a51f9a6e64838dd52e6d48750cfa69454d75b6a8189748fea55786aa645bb1a06f9398facc166f2caca7cbb33e7beea4dd0e7a9c7");
            result.Add("bn-BD", "10d61380a7c751e6f2cb0b17b5f97d94f99d7021e0c3c808b8ceb4478f3e38a4ffd8c749e6e5ebf4e17408adba08ce8c90c8dcb2f8b27d807e9d5a947d188a3b");
            result.Add("br", "7bd26ebf54814f02fb666e52908219c21b5b5e04ee7000939609986cf334cd88f3fa3e3dbc29b845de0da03ea5acca122bff78c0a89c35ca6e2e1bd038a5d86f");
            result.Add("ca", "ce5d692e6ddd326c66bb2fad6756e4ed8b11455cd101d3fc7cbb633d6e0d023aeba496d365ff24f5155c995158138ab308f186e2ddaa60edfbe3274698de075a");
            result.Add("cs", "abfe7cd883d0f8a86cc5853801095f3d660ebfbac5bcf092193c7871c27c886b216090d2870698403906dd7f55a5bc57f3a174cf4b7b8f0290ac0762581efc93");
            result.Add("cy", "0753846de8867e2d0956c4bf82bef6c0cc0c37b101df04c9794ea1f1bc3b0245f0fd5ca766118fcce5c84c8c1e49df53671bff249931aded1690b775834a56f1");
            result.Add("da", "de4ab8d4eed8167943b94a8227dbd0a066d83759eb098613586a4a1e4a37349c6ab173b7fbb1e05ae3ff19bd4dbfc8cb3be355c44a49a6dbdeeb05b1b4770514");
            result.Add("de", "a90b6f2b056d7bc1e8b9905d867eda874761bc661a5de09bffe3c5b9b3c04c7d34a29ba203373772371863284de7d0c27ab73ba8b9b3376935ac3981788bb878");
            result.Add("dsb", "d18e0fb20fe7b0bc2378dfdd0c588a88fe8569436b5ae3325adb765f6232537d7ad511d644bf72c2474b08840ffaa3571214f52809e72dc8830bc0e158c4979b");
            result.Add("el", "f614dd7ecb55690df6c0cd20b85761209461536b5640189fdfea5f863daba0156b1599e7eb74f596a1178a890cb8c442717a44b9291219d829a327d43a10838e");
            result.Add("en-GB", "e568210267c5b48a2084753f026ebd95de357769b15f86c4613696639a95ae2223347038a72210833f2ce7b283dc0c2ca768d82f583ad23981f3cfa5e56ba966");
            result.Add("en-US", "8b765c62495a7d4e0674b1b53d4e4077125be40dd1ed468c633e5ceefe377632cb89c53b2a0296c7091c962f90ab8e74d375651cd203cd0dec2d2e1d808d6dd4");
            result.Add("es-AR", "4e55a43d2c66845e721d7a94e2a408b13f0893649f5a0734162d256b19af8ae6d5b74691cd4323d0774277af5331b88476477b8db0eba48d82479e6e2c3bb218");
            result.Add("es-ES", "c76eb12a91f0bbb86ab5fa719bcd3e09c9600b59a1ad9831fb6848bf81002013c925311482594a98ec9384b28279f5f046153fd6aac16251a5b2cc751696a6b1");
            result.Add("et", "7b8ee498658e9dad1dad82358dc1a7f8eaea68701b3270e74c88880a76aff16be901559ece97e593da408c5d42fb5dbf701661e61dbee41c28f7b089d0415c21");
            result.Add("eu", "87984d2e6e957dc5a6ec17dbe323b8ec4a8a5e3bcbba67ebe97c4f9c8b24368bc6c70b50d122efaa78f396c899b1d65781ef191fea00a3e198577ebcf8874b12");
            result.Add("fi", "ff6f22a8640f0611e60eb5d5719701f9fc131b87cbeca57e8ca8fd15587c20c9e3471e30eed8db24050efecf5592a3d0e38682ded7daf6fbc53acc45b305c3d9");
            result.Add("fr", "f659e7d7563a75341a0836bf1a222d514e54afac9e62978d32af53548a1fbf7ecb4093c904ecbc9bff6d6f6ec85546f3f452055081a07bb51eca37d77060bebf");
            result.Add("fy-NL", "795d39d4ea7ea1b5549c761f94b25199192567a4417784c96b6988edf856c331186ed88fd7bbc458462c2ffbbd37338cd3890623a65ff3aee450ab33e5447dfd");
            result.Add("ga-IE", "b7ef0ef4670ff8828894d8e06a1c95184195f962784f934640113050d77d7830502b97b8f28a8f73bef90106c62761d3ca1a08d6cb7b53e07294f59c0d3d3e4b");
            result.Add("gd", "3d6551e46e0ed938c256f0a833c25d0cbf86cb7efaf9b4e68739fec2b1427e424b931f06a191898987c49eb5c08db37ce84caafb8b195ddcf1fa73d7e2ab8f29");
            result.Add("gl", "add3d04fcd139943085f7031a435cf7824c1dbb83ecdc549fed213738fd20451634e293320fd0db616d647158182385f7a87ce971f965bbed484b842a6300146");
            result.Add("he", "c6319ffaae5211ab590b63368c3c0a87d6ce7fdb10d9496953947d1242f2238baf052f524f7759a84eb2dc599061e7367a813b2c6c3832f930d06022a73d384e");
            result.Add("hr", "20497f6b3e0b19c6aa92bac3d86beb390f90c887655be82021ba3baec0fdda25e7e123b78deb23b4b7ca5fbcadcb4c062677080660f2ae95e5061f0e575968f0");
            result.Add("hsb", "de68ad80c090d8dd3b9c40866c7a7882190bacd4cacf2d0b3bb4300b1ff5e67405bf203df079a4d0445fb44eb3bb1f6048c7cf0359bef07bcb87a0d8dbe8eb9c");
            result.Add("hu", "f19e63818c1ed66102ece73f7fb882cd7269946e75908738c6e1b9e9697b9545017457e4da04fae6083f1c463bff7595aa54eed424fd51473e99ad37895aa4ba");
            result.Add("hy-AM", "40486801a0ad603becf194b7bc2aa6939ade197660ce24e16d82ec9c36433a268d9cf74d4e8d172e60f51a820e1f27b92339c6b8b9d78cbb4967cdfa0fe1437d");
            result.Add("id", "c4b5cfadef0760b5b908e6d6ad002c1f95a1f56996fb3d28515c34124fb7418f70348c9e410aacfdd0cc97cc91f6d8253479e8c438ce91813e9860e8459ec884");
            result.Add("is", "9d5e00bce643d1da1bafb6976fcb5981b5757485050d3ec903993bf60786419bc796c9e2702e9de8c0862a7dc8552e951e3a4003dbfffacc262bd6714d81c9cc");
            result.Add("it", "e4730ddaecd6ff426ef72fdb4cafa2fa47b55175a65482e3440b78d84ab697b19df73009a7346c3a8822eec57e9b964596de11b230081e8b3ecfd949bcd2e058");
            result.Add("ja", "b4ed6ec4e0b2d6c8c3b2a042ce515f28d2c54720a632e5f15c7da2919dd7670cbbc6e0eaab080f06d0c1a8a23829f4b7a5a0e8f6bfc2f2555a89f0baff8e4d0b");
            result.Add("kab", "c41d248eede14a107df87f405be75740abf752458988c84aef2ad5ad31f110eead65508104728847bc03c475d70b2ff9dca27075c13b41cae92fad60518c0770");
            result.Add("ko", "af7f2f29d45e1b52fc42350ab5fb8dcc44cd26637a190bc3829cfd636f53951e5781cf9c4c119e6c9eace8dcd2130c0203d0d5eda86291530778982cbaea4a3b");
            result.Add("lt", "c1225ee7a1c6a3000202e70886fbde5b764aa4b43e66fc51f01ba438fe8c3089bafbc3920fba10d2a90d595bd7d30ea6d3342d0d494e84edaa5ccffb78f58966");
            result.Add("nb-NO", "93bbd61699b765f80f078a97485db93073ca73bb413e86d7fde3e834acc2d43adc30a46d3edcdd571d5a9784d895bc6d0405d98ed5d42b9565604e5221cef686");
            result.Add("nl", "ed06c92ea8ce94538085912d3c7fbd2a20923cc51c05f5a84074232a6ec1509694fad383d760a5cf946389a6e2333309d20f99d052d5b50c277fe2356c1d7436");
            result.Add("nn-NO", "9e94552261ff4621c9097f3e6cec65b667ed539bd0f6ff2f8cdf373c144a0770680b428002283e25072661d6d5b7fc1a2f74752bfac05840c9d937cb883789f2");
            result.Add("pa-IN", "17ea58b5901e2290ff520d35673c77e836f2dc098f888497b1f634cd4a995ffabd96da9e1167703a000703ae3946ca2aae1d3d99ce1a2a3f2db2ebd04ea06a83");
            result.Add("pl", "a759bf93de47158bfcaef7cf3523800b72d19e4b206d549f591a14ff9ed71ffe295509644025ba3a45322c021c65a2ba3b4e97da6e3b60ba5a95a4acb1b1aeba");
            result.Add("pt-BR", "f5600d5e03cd52f69f005ab8dc5a867dd209a7bd96cd000289aef4bc88fd0024b692d77afda09c70c80d1b6bffb5ae4e3777ede6339a50cf9a2e2d10dec4f552");
            result.Add("pt-PT", "19e1eccb7b0596f6d8037654babd64e5484c816d2ce1ea565fe27bd68d309e145920043dd32273088e98ddb94fe0caa17de1abe048e0a61520469a0e5cb11cc4");
            result.Add("rm", "2c05ffb1f1be8db3b08192a4c0c7aea3c300b196b6539674c65e43e9a7695e25e9604ea9bd4d5a6a2b06954d1e4b9bab409ab47a7eecd0451fca7a28429b4733");
            result.Add("ro", "c55933ca64ad055903b672d63a1b09dc2bc39107c8cfa60905c4f6ed4e8184bddb0e9802b64c125da982d5ebf9a5b67454777e10ca776b17727a83f25bf971c8");
            result.Add("ru", "c34f7e1fd50fa80a1ad009b2253089c82b996ae7b4221c1166167d5209a9b130086853596ecb2d48615390d2de5762c792dd9bb8ca591d3f4e52b90b4da3f113");
            result.Add("si", "64d496fd97bf60e56a1ba74fa9f1bbad0a9b2f0640d9059f8d5276c98ad4491b1642173ec46049d1a389bbc5d1851b9f392c154939b36cbb19550d76c1ecd181");
            result.Add("sk", "3ef119d2cd5cc9ccae41e87153a918c95f1c13d18120f11c389dd92b6a41ce816db4fe63dcccaec4d8c8091fc23119ce60c9f075ab4eb3f824ad29ae61abe721");
            result.Add("sl", "e1ff65423e8f0e0b939b4cd8ba7ef074ea9805f42a476f52773a13866acdafe3424b43dfb3eb9d7e43e08c159527c725d88474d2e4b851806ffade2da03cbe41");
            result.Add("sq", "8d328a1260d586926f4476750149ca49c98e6091ae156fdf0782bd4cdddaaaff577c1a173903723f4d8eb64a8be99ff61bdaf276f3be7c387467a8c3b6e80a0a");
            result.Add("sr", "30db7f36ce7524e9eb37b2fcd014ccf46c3a21f3f5a852610811d4c605c53cfe2c192896ada0339425b09c390c49b6dcfb42ef4ce72a990c4fee7d5d10adf228");
            result.Add("sv-SE", "6de1d763277b0d395b2d2eabdb627570bc6558f77b2aad379465691523ad215eb8cf57a234108c7ec7837294945c3edda70cb75b7cb5ff33dd7b52ef1dc77d08");
            result.Add("ta-LK", "1b161d4759c4f701589d697d32a19e8d7606fd48304f37f66072db24906ed55ab01c888745cf7638adf434e8942a60e8d3d0c3ffc719b0b92612c099deb0e61c");
            result.Add("tr", "2ae879edec7901214cecc6078d7af6d6ce5f6411181de527b51148775cd2664d5c09997e264ffa52fd2353735398e2faa35643f0ed582befbd84adfd4d9ab6a6");
            result.Add("uk", "4d7babce70a88e149dd45bd257986febce6fce66f7fae21d2fa29043099cfcc9efcb13ab81762758c4850325d166859885a1f4793752a19743f1c26375ef637f");
            result.Add("vi", "ba31e02f28422834af2193cb456dd6dd948bc4e02f92fe9af2ad83d28053b9bb681af51e33a50855eb50599930e35507e1d9540eba604f4425015bb648180b9d");
            result.Add("zh-CN", "dc9d458553c862d72aae50430a65afe560dc743963d1199e9a5a5e8e662ed058ec0688070763e59d848ef539225f1651163b98331cae384d01f2d274133a8a83");
            result.Add("zh-TW", "794051f5223af16240286ede2618a00893189a694cae1c386f66527acca0d68855ffab8c678805823ae9a2129a8a983929ec938c00ce54fabbd5f753f17eb9c1");
            
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
            const string version = "52.4.0";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird [0-9]{2}\\.[0-9]\\.[0-9] \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                null,
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum,
                    "CN=Mozilla Corporation, O=Mozilla Corporation, L=Mountain View, S=California, C=US",
                    "-ms -ma",
                    "C:\\Program Files\\Mozilla Thunderbird",
                    "C:\\Program Files (x86)\\Mozilla Thunderbird"),
                //There is no 64 bit installer yet.
                null);
        }


        /// <summary>
        /// list of IDs to identify the software
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "thunderbird-" + languageCode.ToLower(), "thunderbird" };
        }


        /// <summary>
        /// tries to find the newest version number of Thunderbird
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
        /// lists names of processes that might block an update, e.g. because
        /// the application cannot be update while it is running
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
