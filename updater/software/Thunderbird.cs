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
            // https://ftp.mozilla.org/pub/thunderbird/releases/60.3.2/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ar", "226cd8e5fc69ed12e978d128592c7a1f0a822b89c567e79396723ba5bfba202d2e104720a016f4bbc15b12d1908b33b24e4e65f9e98572251647f26af1598d73");
            result.Add("ast", "18daaa3ecf5213e43c7f4cce63ef1e1242a4f71b0c542347f96cd05ec21e111cde77d22723e742c7e4e3b05da61ea9ccaf18440f67bf7363a0afc170a12b7dfb");
            result.Add("be", "95e50b73c4fe08903aef9f818a29ad01b3d40283680eea02c78f0b1d2f2310acfd07a3a221ba33b1edcfeefe4f9ff575d85e0574349e7b1f35f6632ebbe7af42");
            result.Add("bg", "08fae49daedc7466f3916e3a289b68754fe3de047d8d52c4fa7b36114063b82d50b41d8a1799d571d7f3cf18f6a1af2906488e4c06a2b0048d3012a5d8940204");
            result.Add("br", "74cf5b6c4340ed37bd7db3ad20943ac9fb16572f7307bc8cb4a707a7d95a3141333b60460db09ac07f4ee3fd25d0574a53038f4ff0f398c6e5b59bd9b5960f48");
            result.Add("ca", "17a02bc41fc3f1bca1056f449c9a5cf6a52ebbc517535905abe7888b438a77904c2feab011e52e76fb51cc92cca09bb30a408c2b614de50b51f74572e3fc7b7c");
            result.Add("cs", "35b568d069d5600eb70d48a17b92a738a8353aec055f32e16701b2ecaadbd738a6019613c9a016897d61c7433417d984774d0e9024708c2fc311e66ffc42c288");
            result.Add("cy", "d5bca9b9a052df5aba05a81132973616119480e99f3c57f7447da62cda59f4df636799f4f99549a22cae330a575bf6d28ad7616daa7973105c84ad1fe918a8c6");
            result.Add("da", "6110ab24c33b7aff5fc2946147e27f224e18239ed70767b587fb702260ad15d5ae3d6e37c3adb754f5c452aa274b3145a9074aad04f91764af0ef7b0f562777e");
            result.Add("de", "e69bbbbc10069b5c4bb0fe5bc140378f43bc6df411fc70925be7a9296640ed79ef7671553e89f257c87a269ab4b22464fa63ec21d9bf4e694f8d3309b24ae303");
            result.Add("dsb", "9ca59ae77d1b0ee5f06912a3f28351d320ad0f4f18022ac986b6d68d938dc311477ba39d04b8819d1a5da14c7fb7318dee85da1bd703e43f59391e0f504ff03e");
            result.Add("el", "0e9d9af6e1652a650cb413100b628b91a72654609458f7e657a303bc78f8a2d2265ad1c3eb9d597de9038885b5bb3d431afa04765e5782df1c38d3d4c0d10539");
            result.Add("en-GB", "ab18fe9883acd67f0c2d7c86cb76db31f8c832254620a546271c33b42abcecda373c6662c614b7cffe7e24428616b9f48fb97ac478e5e5b47241582dbd036154");
            result.Add("en-US", "64c4c854f383542594ad7f008bbff012e97da70ceb82ace938189530e02603759e99090e1b4882d7f63de5da2480f38a83df67186d231f5823332a0aad1a1d61");
            result.Add("es-AR", "1126e40518f03aeaf3cf7ad131b4ab54dd460d8e4fabdee7837c5319c63f63905d24adc7aacf643a89264b24586e00f60635eb8a2571f38e32feb1322a426d9c");
            result.Add("es-ES", "3f464209635a70e8be1bd4095a8d08b5f7a74b6c7cd9c00aaaacee08621b23f78b2e91c568d268eaa284bbdfbe05acc543f08e41842417cabd1eacf0e62889ff");
            result.Add("et", "ac1e1133a41ad8eb1ade06ba1fa4d787e23fa78594067c672cb0b911253b0fd7f96ddee00f3e15d197114fd6ba2784076a60bf4aec0754201330910268171b84");
            result.Add("eu", "c2a4978d74d167e04d2a42b6c547f6c925ef6fbec7237a6c84b5f33fdb6e720fe36e7991f9c16dd6e0ee754efe06532d5abd636599108a1b351426624ba1e9ab");
            result.Add("fi", "ae4aecffb95dba6c94b20f74723b0c5463cd41ae86f630ce35872f658532de0fae5c2ae0683762e4680357d71cab86c501f80f2560568381c2c3b722512a2569");
            result.Add("fr", "dcb60539219e3ea36563f9fd36690ac348d757dee6edbd306b0933f87dfdc4b0cb1569bc50b52698cfa4be7d285f36c46ccbce505fa69c530dfb1ddbc3e17506");
            result.Add("fy-NL", "1acf66b42497bded0f4914a32cbc9c24e12174bfecb6fbfa470810a86e7ecf66567cd16d947c090d4db25b197ff390a0e400f296a18fbc652c611bd9cfc68803");
            result.Add("ga-IE", "9b019dd8e49bade21c876f0d88985a4f2f17ef57b13788296dcb4300606303d8aa64f98f97932201a9591771b87baa29c3622d7d4125b21711a9eb7ece25194f");
            result.Add("gd", "c252ebcc4cc7ee7da1e43766abe12408ce3a12e55d46d15bef1750b897a4efbf009b99629739a16529a9381fb57520074d759180709f22357dc0a7d8d104c4da");
            result.Add("gl", "7f147c6e662f55f8dba2eaba4e6b7f94d72337dcf9c921dc501d198e4ccb1f0b07fac42ebdebd5be2a119e79033c4861be8f1384b780ce95396236ae679a0782");
            result.Add("he", "76673bb36b9e86177e209f1175da039a08af26be715a555b073c1fac6ab9319f7dbd09f6f2c6b2aae7ac96c0c899781f7aeee30ea9c043588acfba3d317a50f8");
            result.Add("hr", "6b8c6bc8ae0203037d171562020b374309c1b18405192baacfd388273948c38ff13cdabf3c4818988e03857f0f5188027bffe5bb791e63539fa2f72ad9801504");
            result.Add("hsb", "f589c3cd55d9c12b117ca76569e7d792ab4326bd53dc3427e5d6632a1f3d40a02f6ddd489b2b183f8263ad8ac2bb11e210b75726ae3300d62191c0ad36fbb689");
            result.Add("hu", "f118ff3f306e2fb3c6f67ca0208da17de4ab200a7cacba4f4fcecc63c740f3604afd08e919d36832128c8fc82eae328c331251945a0a404a118e46f58701a81b");
            result.Add("hy-AM", "79b235710fa725ae07af36efe1f02a971084cb6a7bd35ad77e266447586da2ed42bcca317dadaa549fde8c746b99cae159d4618cb1647102d743d102fa4ef870");
            result.Add("id", "80e2dce1b104ef0ee8a11b4809bfe05df9deaefebef6c420913631a5265ce8bb202153eaa8a0ccabcefea5ac48717131aa243ce1244e67a9e2cd9f4cb0da4e93");
            result.Add("is", "3dd3e9b00b46c6b59e0a8399356d911340789739958fff06c1259991898f43abaa035854c815040ae55f9f624911d328c0cc69a9e1a6406507c3e7389f773e19");
            result.Add("it", "8d6a2a03b2e16d35a58c3d5a2d3e46fc287319b0d29a89ed9b6dc6e8a6a345e2a51efc8d30c5eb60fc9a51191407336790ff7f242301f537e9337a409e730dba");
            result.Add("ja", "f14109124107e8e3f6ea8988db3caf356251212894b0537dea1545ed8dd563ca527342c2fe6f283e3903e928a67c2bce89aaf3248f4ac011011b57119f369768");
            result.Add("kab", "7d58deca456515123d84fd31bd9f64a4afe81ee925fb1257e397260bbd0d4c497a31682a95376e71a9a472d00906e5abe9f32bda667e7e4d77a1663de4d21781");
            result.Add("kk", "74385b42bdd4004be01b5cd9355cb9620820be0a2ef0bb98e22486f78db67ef66e768e40ee0f21a426d43ccfe0ca2bec2d7d3c3e18e29405f901b25fb218c098");
            result.Add("ko", "5fc7a3cb36f35030a2af5d48a3e48df739e7dcbd5df47d5abcfedf2b9aa0bfa31d96c19311b3d559be8437e0cea21c36d0911309b795857a7fb154f2a0844844");
            result.Add("lt", "cb94554b7bc27fddc5e1fa5ffe315df6b706e12687f15149f39869e7b0bb14ae9971fe46b1a8def436f364729027c69806b67a3351bf4c635d4e0fe167b47735");
            result.Add("ms", "2512a11bee53b287ffa4d14d1c62e08754a0cab8ce55e653b6650c1d2cb7140dba1a70d4fe622f2e27708857b903f08079cb5639226091c687f7ecbfff842441");
            result.Add("nb-NO", "e1923091205490b605a666c4ab22ccd2aa91288e9efc7bc83965c8877c2de08ed1cd727cc233edec9fec6d07eab7f2aa8d429bf9ae74ba28caf9abca4cf4a461");
            result.Add("nl", "2811b14a7fe1d07327f4b3f12d9224c04da1bb8efeaeccb8bf99e1fe02be6eb5d8a08a8f6bd5c1eff916162df16e44064311f5adce11367369ee56293d5b20c6");
            result.Add("nn-NO", "a79a969d174d0bca2f7d8f1c8afc710735dd6177936f7a668bc322efc0cafc638d8ed0c207bb93431e070ed9ea52e55c7647f2d434113913ee4e65f467f00f2b");
            result.Add("pl", "bddbe3fddd2de3734925706eddf7d7f22c26430e675ffa97b2066958eba3a25fd69656df4ce7bf7327b266bb4c19724877eeae439faa11bdbbf9232a19e3d385");
            result.Add("pt-BR", "b9d5c093e43c94e597d070d373e245aac94d202883834c0d5234dd08cc54e20474d4fd10b767ff9fae532b18e868386dc97007d59d43f196d59fa41aa284d3a7");
            result.Add("pt-PT", "12fd53c54dcabfd5745c2282ac26cea31afed8204162ee8b94174286c1461bdfe07b7a3549c9c2d0c8cf66a82cb36c8518d9042f9dee785d773905555ac2283b");
            result.Add("rm", "b74f7ebbb98fde51bf0f57fe45a8c11b1e6307a7304a19535e6f5640b518a8bc5f894d53e89f25f21642336ecb07f638b2d98877d1aa51d632904cd39adcf2b5");
            result.Add("ro", "5b05f725da7b0cb8adcbb24ded0032e348805f5afbb840606fba06fa6b6b68ffc3495de1cf3f875d22cc8e69721005dab4d5a41800fd384189092ccaa34caf99");
            result.Add("ru", "976aad13c3f948c630cd1117b28c7370431619be0524b6799d0a85df4356686d2e20c153bc4a5d3ad75d0e7fb1e33c4a5711ec1dcf44802f9b5c8aa50e2719f8");
            result.Add("si", "6a08d8db7a27975640030d429e05615243d658010e574815875a92ff65341d66be3352725484b1da7ce66106d49786b2a579e88c73630efa264d75d42658b688");
            result.Add("sk", "a95d4682cf06f57d599923eafc2dd20d430cf7d95f4497e0eedd3690ebf6bef88c11c0a3c861aa00b0ea7ae24c93235e3749416f59df78499a3921367cc0eaf2");
            result.Add("sl", "253113a9d68619045993e380bbf12054dd7c00ffdbd32b006d3e7f7563c0db04f4e09cee8e3a18363bfb6fa1b63d3987bfb5865fae32e04ac12a8bdfd2019c78");
            result.Add("sq", "f7779331804ed4fd992cc173e0419574ea430be24f579217f1217d89ae362359515d2ec843f62379dcf27f5aa6bae62cf844f63cea2b2b6ed412215c47ce745b");
            result.Add("sr", "8f4b4d2dbc00c614920156a5a987d8de559d284296ec9d3594349b4f45bfe1936e9a3dafe3d0df3c65bdfa3677d6e9e5d81d1a38424b1cf23795c35c3e437c79");
            result.Add("sv-SE", "ec6ec40d4de735d9f1d7b8074f92d200f0e33ae51192cca92b979951b48c4b75450933fc4866996267e5650436cd5dc2a68369fb6d3e514dfa15d93b9bf2e598");
            result.Add("tr", "e58eea535bb7663282c8b414d22086eb65d8dcc60716402e2c1c2c638e7dfcb7170b3978859eff41e37abac953fb623f8a66ef5615fec750d719088b48c1923c");
            result.Add("uk", "f1adcf0869daa98dfbc2912c80044920fc11f6d4f8b4577ec1010a23b65313d52c78dc9b47bb91d74a5eb4807e52b8c7c89c67071280b00bc97eb462eb391679");
            result.Add("vi", "35de20256c39b74e1795e257ffb1c18429684ac8d3ac268c0b818740e186db2957723c22f9835f3980a33029f68bec1291b409311bba48317af2ff342d2e0889");
            result.Add("zh-CN", "62219a83eebbfee0763a63501c477ce8d28ce15f8dc77be95b5dc4f267f80a9683bc0b7f8d39c3f1c6003abc7b6a13ea18497b736b14c5203dca5dd4a1a9bda6");
            result.Add("zh-TW", "bbce546fe806ba1b9d9495fc3f3e6829c13a5319b123ecbbc492534a04c8b2b1772ffd730b9b15f2dd0ff79ed69fb19ac95c6fae71e5f4981b30bd720ab4c81a");

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
            const string version = "60.3.2";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird [0-9]{2}\\.[0-9](\\.[0-9])? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
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
