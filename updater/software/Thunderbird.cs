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
            // https://ftp.mozilla.org/pub/thunderbird/releases/52.6.0/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ar", "2b252692c10a1b904f66288b7bb8ff754e97f6a511adf6e7c0474dc0b8a8caaf174ec20e1456bcf14c42738228185ca3f940c0e08b2c60d8dd913f140360e292");
            result.Add("ast", "f9682fd6b88e7d1e1c42e34419d00daa05e28819f5d1a0c606255ddd610493d3e5a9866e118c0ad6fd867de12cc2910af10541b3e2837d7067de11b7a35219c9");
            result.Add("be", "47e7408888694beab6931182304d8450c8e6aaa87706fbedbfa99295eb35e4c38c24136784a1a53a20c60bdc05095224526d09754caf40799f03f2ba47aae433");
            result.Add("bg", "4f6ae87d5ceb2c9422ee88e2d0645b995219de6890d499a7d4cad17434f2aaa30f8f1742c62e8c8ff64a253f935849b90b012b2ce7efc324699a7913917a6e6e");
            result.Add("bn-BD", "2aab5bba4031ace6977da4955781e6c861ec50a0b06a88ff970987bdd851ca07b93b0f1231858c0dd8f3e910754d8aed860d1119c79ff2a79128a5f158f8ace1");
            result.Add("br", "caf36cafe981db18199ce7be1194109899a78f32b790b894596b82118dccace9eb9881e9d3d61af776f336619bb10c44d2f76d0e29b9883968a4346992404c74");
            result.Add("ca", "8a61033d200a4e2192966917ad411b0b0bfbd4f2b0e93313d9e77a63de304514dd3ed3ecb46b3dde9a038148b6e4839a1f03444836046bc7d14b87c8075398a5");
            result.Add("cs", "2328c7097ad647918244a491b253f9912fb216694aa7443d8795ca7d7b537e1db340ff5eccff755f8726d33830734f53520aefb144e63ae302130e6d58346926");
            result.Add("cy", "deb998d74a1ac7c823c6a6824fa2ec896420c881d67e907c238b12091684951c261d2ba47066208c3c2cb789d8c15ee1d1bedb50669839ec80966f47b303c51e");
            result.Add("da", "ae5972908439c816b1f11e8061683ed5abe52d67edfd8d10942c0bda2868c9cc81cabfa85a0aee034246df8cf55b433d51bb9835eeb519d4cddd1d9465843574");
            result.Add("de", "39a2e14ac6802c855d6e4037d988da3a9807c51e25410e648eb1ee5f30a6598fdfaba2e1f111951ea520486d7d344fd541c309574fbf1e75d0a9a2b35bbd774d");
            result.Add("dsb", "17d6fbf3223d7e29977ff8d5ac7f37f486e4c4ec06ac382d2d505317c55aa5e9ef12d8f827cce703c3c6708c5fbbfb17494987e3429c0731a44194a751d2a42e");
            result.Add("el", "82d8b569e380467439345dd331fb8722923c0f2ef10c81602a9717cc6d43348c55c12b5130bcb0a1f00a81502b73f909aa20558cb1d8e14cfc184d541f2cb588");
            result.Add("en-GB", "6c01e35da238ff847c21373f8d8c0fef4bfebabf7742bbe5768de9f4ffbfd0566ca56b92b413640886597f9fcb28e336259b0ea6a823b431b779549275cc2605");
            result.Add("en-US", "ebf115d7a253f4e89f2528687855ddd2200421dc045c33549fe9bc1221f61ab3e9c5b86929fd9a9d89be99b2cbaf552d912bca3fa8c4df2f6223f859064f3c83");
            result.Add("es-AR", "c133b378bd03df954555673a7be6564fc0484eb16abf48c01df9433e56f4a8b4a1d936774731a731b956a4485d3791d90fdbf06d620eb56162df743910504107");
            result.Add("es-ES", "c32252c56b29d0c82c199195792466b0415432dfd46f98d59eac08fd3524dbdfc497ffc61c5eb72486ffd7e5f6c9f0b6af417d54dcfa4b54bcc259397f5db55a");
            result.Add("et", "adb84dd13108086f47a38834e0037cbf68b82f38a5eb3b0e55f3be1426bc91c59d19d5e8fe45a56c6a284a7877f28119e3e1eaa068969e883c3beaed18a3d464");
            result.Add("eu", "e8b2d0149989c1323a7f620161a92b7d67df16f01227c075290f54a7ab937ab1b540406d40d08037c34eb0abbc238a6b731050021408b9551deafa90c599a593");
            result.Add("fi", "66bb26dcf619d371ccd989866414a88aa456c0a9f5e956171272b90ea7071070daa36e12f928b200480871932efa7239f5b36a96e2c13fda858922b63162a666");
            result.Add("fr", "2b2b90f2511f936ab486d2026b989af326b0cc51a2706541d117f61a67ad9c2fdacda7151fc49e5f0c88097570363a34be93c272801a392cac893ba7ddb805a0");
            result.Add("fy-NL", "cc1f517e46174e10b5f6d7c8fd2361bbac6a3ad8577ce56282dc0ec1ed3bbd13643a1496b712b412d1ac7f84d3f96a69afbf0ccaee6b805358452b6e2233c429");
            result.Add("ga-IE", "e4c302d5b64aeb1e3b8c2407636054edfea6476b38982e1a875fa9ffc1cbf7557780b59877cc7052c3b037462a172cde431197fa03bb4a6b9582aac67b6017b0");
            result.Add("gd", "0513204bfd3ae86fe4d66b0cbaaec059a209fb89e533d765be9517df734bf630b151b1f710161cb55f9a651f041b5f1e945aec89470eae23f42faae0239515e4");
            result.Add("gl", "d6997a1a531111950264be2916b45fcbd51b5b1340cd72e0cfca3d9d6bb9870b9f0140e81c69e714349f87730d8e2cc1e87c7ca67cbb2aa5de1e5020aba32619");
            result.Add("he", "a16e9697c9535fb42d5120a476b94eb9032b73b29249a6909193f977b0bc9afa3962804816dd4e23cbd9c360274cd66b603c5688dcb05bbd9f5e533f546096cb");
            result.Add("hr", "a34ba3f8622069849d88fb1fd3ab1b3ad70cd78072524aa9b9174940c15e00c127c254da490df9ae8a0c2f051f778fb0ca108fbedc77d2b0a98750b7f4d261cd");
            result.Add("hsb", "a4c7d13204c7179b6086e31068bee1f123b66680832b0359a305d3a405341da904b41dc80f5d52654047564739dc335591f31a8d5de63e296bdc4081340635a5");
            result.Add("hu", "4c55976576804fed474a94c9dd7a6f5b2585188d931fa60b368f937252d91af908923ddd536e3e2e8e5e4e107f90899b525a070a78b119e14f9a5b1b0e71b499");
            result.Add("hy-AM", "7580af095954f70e1af63e772a962f008e739a35442099d62556f76a34d5f40125e982817e642123aea3886d3127d294975107bbf2076d6bd1999ec15c34f2fb");
            result.Add("id", "82a0c01bb279a345cff6a05b2a0d99b5efbc913c04481df01b4bad39c3682ffe9a260eb8eda923b9eddbae8214b080451dbc88bf1c042f9228c776bf0a785c80");
            result.Add("is", "912d1040854e5e6a9abc89d73f0d9987ee94fa990807a5b01589951a36bd4c1b6d4a06994d3e740e7429d2051aec44e234cfffbd493a83c582b7dfe77de90464");
            result.Add("it", "d203b1d24c1285cba1fff5be5a1f471db4ab8ec79ded456508007768fe475c1b4145897c9b48ca80774e0565e02941ad6ecccfd3808b8ddb833c46c433241367");
            result.Add("ja", "7d20879d7d1276ac6f07bc551140c1217723fe7c9e0bd80ae21e8fc707af3d45cd2f553adfe501156e757f6a069df87b5b667efdcc69d1fa79398786352bd1f4");
            result.Add("kab", "42979ec2ae91e190bfdc027b38c062d2c7d5c92d4dc9680627c15e56521bf5e9e339ea7120d1582f678544fe9cc4ccccb062f67227a19cf566c422470588efdc");
            result.Add("ko", "29886921da9cf1c166d88bbb26c7bb55198c7a8a9d0662b648c66ff060a59a8174f284ac98e5be77d5398e41af69a4536759737679539f58b2f780b0bea7d58c");
            result.Add("lt", "a5c387950b20acb65e5f131a7c529a25a5c595ab5ed08185c95b2f10d098f99fd10c4cf72940aea8b11a0579ff94a0d0551e91197fcc9f0fbb3d81320f4f450e");
            result.Add("nb-NO", "66302b520b35da92c62c7cfd77dff7fd8f8fbc56663c9b14c998a27ac4acbfb9e43c5bb870e5ce0118d96ea49501ecae26084f26d6f8e7b4281dd3470f15b4c7");
            result.Add("nl", "1fb1455f9b604f209dfb3a85b9ceb41abbb5bcef64b0a17bedd31490a06f0f254c09f819ce5a7260c0eea72a677b08cc5e955fcbf968972b820dfd58cf0f6f60");
            result.Add("nn-NO", "a6068058bd8632093bec8b5fe3fb53e97dedfdc979b67de5021c22af8caa9a5a0142b553bdb45c256627a678ce147475a16d2e24b883f4a794f098da00c60a55");
            result.Add("pa-IN", "417de7c57ac74c04a3dd8f520767a81680174f0fe8cc6902e15b6662d48ebfa1a66232bbcd34d408ed7aec27165cd66cb110e7564e4266975d84b8fda4424045");
            result.Add("pl", "34bd3a731f20fd89aabacba55ae869885d50970f92801ba8c39db1ba45d6f2c5d8b8050380f14066cd70bc4c779f0ed29580f80c8ef1a5fd040fde883b5fcc34");
            result.Add("pt-BR", "d5231b36b2f19c35a50a5f20f74aee6f5443f5647ea3248dc9a0f819d3c065580065d30e5bd820123086dc42eafc71a462757892fde615a58465eea44211d54b");
            result.Add("pt-PT", "3308b9eec57915f5624b58020efbadd2a1eeb29e38c9e5d41dee3d9a0b98155934d9ecb9ca686b62cf28655316cc2c6318a805b122a9064012beb2c36d9635a8");
            result.Add("rm", "2ff449210c2fc791a2dfc37e0c828b558ee9b80f6026db3196bb85a29bc6a185b4ecbb73d6e869fa0eb330f8365c150c470c444e3d1b2769920c914036ca3953");
            result.Add("ro", "50e9a57d479f175374755f0a0e493a16dac00bb2d99234d2f40908dd29aeed7dd7a05903415f682295e193b8d9bd9fe10d86a4fdeba58458c2d3041b2d64971c");
            result.Add("ru", "4b7f13e1f3d0fee7abbbfac1123a71f306f9578f5c4315cc8c86c6b069fccc43b433fc3746aed2e60409df1611be2ce1c19ad50b6e3a25c896246f7203c8f44c");
            result.Add("si", "0f50bf0fb5004fdd6b635ab1f1bb27d0a8e064e3c5876c7459c3c884a7c0ab5a2170b0eef5f183ad59a85bb9848d21b101ac9c2d8842d6ed10fc1fef9dd419d9");
            result.Add("sk", "1a696fd76cc77fc5cd1d602bc0b8e62dc74630d27b897d793e11b92e118ccb6878c8c893aa02446b277f008e79f6f292334c8902e7ad6863ba33abfdb390dbf9");
            result.Add("sl", "379bdac209e3afac54edeb8a4fc720242131de617dd18978c3fe0d9223b78394099ff32aa4929bbdf880db928387abb5587e28c83e309995c41569a57816b44c");
            result.Add("sq", "e89b8bf336becded1fc953fc7b544d0e4d0a5c3df89903f4cb3eb044836dc04845fe7d97c87a4a1cc081622ce7b36d0b6f271267d2bd28abe8c86f63b46f9529");
            result.Add("sr", "d057d878ee1650725a5dd15f177665e8e9b8a061628e69f43b8f5247a807b542bccd5ee09ab51513e7f96c24c20dab27dd723a5e666abbce2b40823aa989e6c1");
            result.Add("sv-SE", "ab3dd32a69718e1665860cd85e190d8619ce075dc834ccf0ab4c4f3a4ff96cc2fe2e0526661c1facac1832f5c49e78ad6aefe83f41b8f19b9cccc620341e6b1f");
            result.Add("ta-LK", "d9cf81fd7154386362d759f2c4b73d9473433703dce6171037df329e5fd6a82b14d3fc86e05ac98d45ea5bbdd5258e36cccf8c8f0e1b96d4b187b513085f0d84");
            result.Add("tr", "2c0f8eca4ece5dc757f6a7262e0e6f6874113d61132e04c6b424c62d4f97b9896efdb57f9c3587667cf38291b1acab23709b3aa63b69755d992f68d48cced696");
            result.Add("uk", "86834ade619a5cfee994e8ded2ada39c6eac52bed23f2fccd02f569692a90d1cc7692ab60956b00c1eddac975a050ea85802297d8e37bf52cb54288f09822698");
            result.Add("vi", "a334ba3e6a2916ab70e7a8e566efad74ac0e4589816cc1057f9ee1008bb5522f8b80ea27a72fd518564305a839fd044e2db1a4f5608cc7da0d0efa04cef44c8b");
            result.Add("zh-CN", "552ff3ccca99505e1964a06a1260a85aea992f4d8f39f565909977937718a637abfb062b4c5e26d3ae2c93dd994065ce0576456ae02b3ee9f4d481457c7c7dbb");
            result.Add("zh-TW", "7ee0e96afa9b35576c62d1b39b7429a307e674692b3164b4691255d84098fed0c3bddb54ccaebc20756d5f7bc771952362d66b9ec7a600e5040501e8d5451508");

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
            const string version = "52.6.0";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird [0-9]{2}\\.[0-9]\\.[0-9] \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                null,
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum,
                    "CN=Mozilla Corporation, O=Mozilla Corporation, L=Mountain View, S=California, C=US",
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
