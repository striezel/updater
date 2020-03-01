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
            // https://ftp.mozilla.org/pub/thunderbird/releases/68.5.0/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ar", "83f5da2cc27efdd6cd12657bbecb04dc7a234b8ce5a85fd01aad130c7f8ced4d7e48e64b83a29dad6424113ee951c520fc3c25d67a612bf2c32cc45366991ca5");
            result.Add("ast", "5f9901ee54639189e5a8fd2916bc3d3cf79a7b0c13364dfb0500648f924b93bb7a7307aa769d8af36e33ad2dce7c9c8d0955df65acacfa9885c0c60c6a353fdb");
            result.Add("be", "1bb6681b874c434ebfd6157c85f946ab317520758b65c06880c8090830ee91ad6b00bf45870f227edc4a3be5372f9cfc20a0fc25f30d5d73c3eb1442af23c057");
            result.Add("bg", "9c24e53ce093e6f7a31573b76fd2e1200bcca7405084a01cebea47c29fbdc972c7c2efe0e6a456a081461784b4b68690bc9648745f783242e0a2d7e253850419");
            result.Add("br", "81bbb2fef402923ac6a2048c8b40e15232ec1239d7bc87ba13de90a233802b641c6e43ef2c5bdd8c1ed1d759b98936f457e93c9d1b237e752dbcaa6b77d66b98");
            result.Add("ca", "d6ac732c885a8874f3c32c99bfc1c4e7ac1a21942baa58796f25e70fd7615e550a3520c5993ec114564f4c8757da4fb33995487e23ceb9d9a9dbda177ccaee7a");
            result.Add("cak", "1b42a1a5e4e44d25a2a1069757920426596a76c1e275f8dd8ce945cb2f335ea154a6a9e36b6e9a6b4a694d0e47b2e4778db823afff8b16ff8eca50bdee13ee98");
            result.Add("cs", "569156ad74c7bb6e476f111e9fcba6a96e6d04a89906bd5e6f9960be10b0903493639114117ce192c28c084deb6a8878aa3b14cf3b80878e36ed014ed6f16882");
            result.Add("cy", "deb457488200cfb33a09fe85507fe830ebf9c00a387348e929d6d0b32a44bb53bd223d6109c9c1baa97dc9bf98448ffbee14cd2049c703c081e52b6e3406bd6a");
            result.Add("da", "cb3ec7de59a5c5e405fef558d18ddda6bfa7f728ea23283bba8127f98aa7948baae61c98a7c64bc8a188a2d13f27fb53fc18b6d501e2989e1efc779f744a4da6");
            result.Add("de", "ab9bc8eb1fd3188f56f9a3308f3b7039e3ee493fc90c4125cbea76a4a3f71eb14bb80caa02e97493271d6b5b614a8eeec2cc21b132195999c902fab8713d6df7");
            result.Add("dsb", "141ea49251834183f7f20c057df1b649415522ce3641768fed8dd0c599b640f0a0c7c56bee286d36f5197a671361a89a9ea23bb2e50877ec8b8bd4d5cc97a32d");
            result.Add("el", "0317d3c1ee1e5b758af77a588ab9a1e7235bf485ef8b027eb1fc48e4c361b84a9e8dcd187ea72dbea9e4efb298c8632a94b0fef9b48686b055dbc7ec8f127877");
            result.Add("en-GB", "cb8d4daecee78a82d9bdaa2cc84f322d612ee081fd0423ee021d6086be07b5c7f6e36574850882e9ebd078b5ff37c17c7d850b154a6995555a0c4028c9be8990");
            result.Add("en-US", "2924d74f1d96ad7463a8b0a28014d18acb3b4cf4e3c5edfce5049f9833d35a0935484064eb5801b3c1651cec4a7e6251f297c0427a6012817ee9d9a4b30bef46");
            result.Add("es-AR", "25859f08df64575df8e377658a838c4eed6b2bb0f0f677ce3319e5d9e550bfa9d97b3f469699b4a90fcd610e0bf07aa88fedb784bce0bf0b2e11affc8441d51c");
            result.Add("es-ES", "5eca1a7802e3dd87c4b193c8cbc7e97938ec1f6384694f50116fa7f7d348280365362a2fcfd17ffd140d1360305129176d07262c7ed1cf6af30edd40804d8139");
            result.Add("et", "68973fd02c3410cd1f999832b334c1e7b8420af5cfe030e3ec7b65b4ef4fa843c6f01cb44a0a76c7ed6ad2451bbf79a7c621a2184357adac5cf96724cb4e01bf");
            result.Add("eu", "b28cf435ce6e7e5466de40a619f1fdf422059c3aafdbc61e175edf33ff83f8140c5dc67cac1c4f67ac673c2a13a0244292ae4eb7565db394cbc1c80d61832f73");
            result.Add("fi", "7c4ee37112b879e37cacf416b186a59370ebc3a776eb7b6af7c9b6c5c19cb6db3cb2bf06584287f8113bc98fc448663339a7943a889c45cefe43d917c959e81c");
            result.Add("fr", "5f992498b0a298c072cd3c6b032cd63f3e5dfc106820908879669381755df291de393d04f57211bcbba65bd1a5d35cf757632345837defbb0ef4dd8381c81fbf");
            result.Add("fy-NL", "fc604b850d43fcf2b3f670c6bab6040e7319fb6d537a040fd3ad79865eef800584ed62abd03ad93bc29b1e0121a2cdf106764a13967bb6154e8d0fc162918bc8");
            result.Add("ga-IE", "17ff975a620d9ff7e3a3d2274b52337d5a54a1b1196e205bc803d59b8d83215a3fc4e643c03830278a6b46dc98ceea9deb229c547e9590eec36839cc665bcb68");
            result.Add("gd", "df3a635e4789a54803a1e4100b1f24c7d56887fd128646ca2e06c1f1eca4dc72b4b61d96cf3151fb3836440cd9bc9cb512b6ac1bf5f5de91bd39fa6e17623b17");
            result.Add("gl", "e83281fcb64b1bfb17bdbd4c7b7573876d8140a6eb9d874f0c57bd8485953426c20f3f9a510916d5a9f4c4729a56c961ecbeaaeb9f9564dce0eb10f3b7f85927");
            result.Add("he", "ffe3ca9ba08937b0ad16636087c64156a4bd46ac280b5b6faf4b831e18cdd82dd236a26065e20aa9555d7a8257743e756e886a9243e05fc656d3ea35be0a27e8");
            result.Add("hr", "d7b4d15e02cccc9eed5cc27ce4754a8406a6aeb3fe27b0c5e7f0bdd8320225ba942fc30d377c3955b0830100173d22579deedc1c7d6e948aa20e1905c0279b04");
            result.Add("hsb", "66df6ffbd827d4d8f0f5d2fe48b1ac70473d3b5a46c2c270ea0fc5f61151767455ee189ab447ceafb5711a22c30a62910eced68a127fe05b545c32d0d0b59087");
            result.Add("hu", "a5e61eb9747f823582013c66b3b4aee8703de9e8ee5eb616267b040d3d22d6503aefdd35a72a185b64444c2d6d774a01743ac791ba29fc13868be82a2684e181");
            result.Add("hy-AM", "fe40709bac762e1d9f5289016739cb7e7604c5061c8190b7bec43ce734c1a0d501e4f7c6350ee30c87be0d0ef27806a2e2c145a62c533b57e83aa2445ec76e49");
            result.Add("id", "f5a1b0ac0173150b65985c1aa57624ae5539591901aaceea15adec816e146c56ea84c46295e4090dc02df35972fb4d53b14e4c1e9433db95756655994ea2dcc7");
            result.Add("is", "e271b110f34b636882b60a0efe21e085a5e6d862ba5525b0dcca41988eb7f5ffb0289bf9d483c2442e624b26839123d97a073a1280d4d68c2d44f2469dabaee0");
            result.Add("it", "99b997af0a0af280b10772c1310b88d012e9addb0586e602dfb86b30957cff030b4e8995cce766e4cb781845e7b0053cc1d8e465f3897369635eb39690461894");
            result.Add("ja", "460629a46945a74379073391805ccec3ab772f27aa1ec93863ebefc89674bd67918f2ed95584652219201f7b51411c7a5bc179e35ea77e6b8acddeaf75bd770a");
            result.Add("ka", "520073b1a3708ab1b445ab1cfb7d3264c4c9aaa656a68023aa31a339f38a36709d7178742be18af97a65aee73486f2dc285fdd830ffdd7c630db191e9e813555");
            result.Add("kab", "8f56abe2658aa748262924246107f1df8433067d1dcfbf5fd235210a92c116fca8deee6a6a2abafa5487a842e9b0918c34a18398d749807c2d6fd73fd334a82d");
            result.Add("kk", "035127725b07751032d47847185d57fee16defd950ca3a68657604222836598c05d34d33fe96bdb61156ffb5451f69e174ea2f141ddf5f59c51fe9858b62b7ea");
            result.Add("ko", "8c5a2e201fa2b3464c3936023099ca15de47ba32001a7143f13d73c7ea302acc98152ac188b1fb7de423315a1d7bb991505037df0d5c28b61809406e23dd9168");
            result.Add("lt", "8cf68310078a744291c18c2137dc510fb9d7f989f06b4d30e21c405b2d7720756e9f629bab4ed21d0f626033e1baed66c992fed5a6a0cf4f0b0141640dc5cfa3");
            result.Add("ms", "b45522cdc0143e439b0740a8559976c23b2f4507eae64bf2771dda4a200c5384a0c25795117b6ff872a649bb5adb17830a616991ab444e0026eaebbe45adeb5f");
            result.Add("nb-NO", "77fc56379c4632a3ff8a619bfca52f360f7c55d17abab68993cd91750c02a00047f2614810717a120d0ac58d78d27ba3b157d9b72608a6f4314c3de7d78d6aaf");
            result.Add("nl", "6d1e01c14dc659c8d2f254c0b5c466eb031bcad9b89a97e93d907049cc24b7b43bbc669f1a24e9954b56aa69e56db24f9584584447697bb30e519f0940ef3c1e");
            result.Add("nn-NO", "f2040a3172f7b2a3577a396fae21b4a51f3a43223b369845d0d1866a2317eaa9a9622e6a621c3592bacee8afcbb15e524e9c8a8f1d69fe10d307bf668b521109");
            result.Add("pl", "9e393cc29838207d00973fa08cec4c8b3f57050341a8dde1296c1329d67681e1df43cb15bd3dc9ce18f94c413b3148768635d8e9c1466ba953ed576fac49fbb6");
            result.Add("pt-BR", "5e044879502e516fd7b0097a8072cd2969c518be22753d411573ba79131f3d52cc6e054772d787289e647857071747fb0fabc2171678c75636f680d6a794ca32");
            result.Add("pt-PT", "8cf2c2cf6ec54d33033c0d5b0e981ead101f16df95dca3eac9114b13db919eafdfecc8d1d7937f0c4e1d38e5fbd5fc6cc4a180e1f5df07f0808c1a9867acd38f");
            result.Add("rm", "6076c99591a8742dd6dea81cfce83d669c5fc2f4eb7b3ecf610a1fe58f84dbec4c2832cd08e2b6ce06768a3264d9dccb03a23648c7e6d21f9a71a7e6721e6317");
            result.Add("ro", "0e271a63fbab6fa325cc096186dea7ffad0b54b27e4829d9a775a4340ccd775503417b1ad2f3a2eeecea8b7dfbbc37b23c78bc049c830b7ae02e3aef0f0535c0");
            result.Add("ru", "c8676ad4102e62a08ad0b487c9af09a9379ebf6310323e503513bd2cc2824204051026f350027f85148507c29e5cf6470d2b1717f1fde78daae74c49012f5cf4");
            result.Add("si", "30e0b423c876501de53f4dd904abf91c33333cd5a01e70306b648e246ed155c0dfff8b41926f88eaf1d8993d8cfe4d23cffb5d575cd75efab7ccea9421795ce2");
            result.Add("sk", "2aadd11fe13c83d146ad9747ec55408435bae4f62727dc9bd5c69d2392c2afe97080efc7272bc21c02ceca15f5ed6e385ee171d035cd3872bcc207d386d80b31");
            result.Add("sl", "7ac94c780ba547261bffa75f0b2f5c72c01f7cc3b366f7cf239e84c8dae59e3e6562c9b2367a862fc522112c899edd12789b919fa81a1ad1c2e2f9c7ba8e81f5");
            result.Add("sq", "5d61497b91916b428f722cecec44503966d5453251ed3625d0b2359766b8ae5026e7cce1f70fc9e0689062d04d1df5834db77c8075ed3850face9f64fd371972");
            result.Add("sr", "98023f6a139ed3aec2b6b7e071993052cb126b998e77317a84b66b628d3fd3e265232937b069d9dc77f35cbdc06ff4d85a96692e65bc8ebdc87259d923ffeb1c");
            result.Add("sv-SE", "36a25fb9fef70cf7f27a5ae6789bbfa121af1423fadac70656fc3b745a416e211610dd7ec1e573a1ccacb71a0a7452019023b3bafe83ff952c0fa7ff3d6de7d7");
            result.Add("tr", "ce8941df45a6755216294da59d7604822933cd3ae9e80f84d441964c69d0e12048ebc4a91cb4e37f6d96a0f3d3777e14d712db70a53b5ff39dd6097ac1983f81");
            result.Add("uk", "d4aec821884eea379d0400b788a1b4b39a517c1a702a0da4409eb5d5b85716b5fc7130a01a02c837656471bc405a4ecb7cd1e4aa299fd850ef52f93592a6662a");
            result.Add("uz", "cda43e54bcd6c0fa0f6cb42684547d1a3bd9dbcd8832e16277a0079bf447703cb796218d0a380c874f34cd76dcc13de4dd0b539a645b8929ef19fa38b4c54627");
            result.Add("vi", "5aa20b1e412fcb5b53a54b80c939445581cf49c587350b5e6fb54e8792607a7bf76851516ed9ecc0515a0a58e86a6dcb1290f38def630a2aa6c197532e534642");
            result.Add("zh-CN", "fbcd45a2b9ff95a322708169f1dc18854ddeb7e275b87d7d392409558fd8abaa554482dfdba14236f1d3cd3aa94851d4d17363cfcbe8fa12464c34993e5d706b");
            result.Add("zh-TW", "8fafa2dc1224dd74bfff2b4bd476c9b645b4d1a0f7405e13ad748ceeb575f03cd0386ecdf4991ea60dc0525b4220f7bb54f89a0841d105e906f90a9b8d241efd");

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
            const string version = "68.5.0";
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
