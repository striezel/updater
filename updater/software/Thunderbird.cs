/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019  Dirk Stolle

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
            // https://ftp.mozilla.org/pub/thunderbird/releases/68.2.2/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ar", "8af417d29db05bd92fe5a9cb3b95f1f1692ca677a666424414d5d444abedd06f332ae0c8c00c4d968109c69e7a224210da4b96cdc5d369efa14ee8a7c761feaa");
            result.Add("ast", "a1a60382c3124e8f82abad41620151821285002d93eb31e51252f847d834bb27e52eefc63ff9fa3bc3ff8bace6b3d7bd2398636b36b38d93180cddd06343adbf");
            result.Add("be", "ddd534d8b89ddaaaad30b8120ced8f2ac020ea34ee70576b2f26f39a9d0ba5ed0396952018ed2ff657cf1b758824a50694609958ed2bfb759ac5d884dc159cc5");
            result.Add("bg", "54e05dbaa37c28b376a7b82f50ddbfa0e06acedb45aff8cee70ede26a06a8d3380ce02a2dd5863b13896c6d2aedaf8e2807ce80c550d39c8346ba6cb059c62f5");
            result.Add("br", "78aedad17308c5a1a54df1db0074d9e782cd7f3b1e9dc1c5c48503579bf728f90e991dafc5eb6eb9cd2e9858352b8bb077dbe04bf8c8131d656a88a86c7a2bed");
            result.Add("ca", "8c4610e2de284be0ea5e199a48ce139f6ab5c16cd35e0130045102cdecb23a2cc6e8f90ad989a3a3a76c03cfd5dc187e7d7c7b04e2f527ebbcf036a9fbcdd419");
            result.Add("cak", "a16e300ecc712c08a0063850e5ddbd9412c1e03468b791ac9d6a840df3343d081d36c85307010908be1799191e32026146a18f2391e46aa1573a3df5fe54a113");
            result.Add("cs", "14d432fa9df688f6678b7937cb0e1f19ad419635c7a64784c0fe340958cd765e4ea6400ecd9bd004b02bcd9a5337e5cdc8f6362b06398c582738f83c909948fa");
            result.Add("cy", "1c6f39a5b1bc27e02a1dd23f6b20ee7f4e6d4887957d98885c3877dcf8ed341da06cd18677b27638801201f14878f44903f1107f07d60bcfbde07394308996c6");
            result.Add("da", "68e8e8b0cf8dcecb7bc598471ff42d1865cb533c68283e3cd65ac5a0172da7c96371685140d8dfbd41861f4493d35c71f6360708c0e3e0412ae015c11cce3094");
            result.Add("de", "53dc9551cb9c729859a43669907dde5dccf655c3012782045a1479dc18bfa1a8d885834c8fd62992092d32835ff209adb6601db4efe425164c5edff5fdf9a627");
            result.Add("dsb", "02a35f75927e9f2cf8ddd7b1cad34faba21ae71e10d101080b9efd28ca0005e265d93526cbdeaebe54a32a1a779f93ebec148c4255a125c0a67996d87e405d2c");
            result.Add("el", "b3b6bc11721d09c646a466a4ab726cf18a759a47eb58c72f78c3075e4797f091c8c410b21c3a2d559739e1f9c32af4a04734555bbb8812ed21447a7d80886d61");
            result.Add("en-GB", "55bf7748a2ce9e9613c6778aa428370a943ae3d8b9609bc2beb69a398ac9080f60678fb0de8b65ae107e85162d86ba2959f570ba7c5b31a1ebdc36b5ff8ab171");
            result.Add("en-US", "be934d12fbfa6a8f3d9a589c99481018bacd393b878d8aa152fd5cd9f3756fa5e62500bc54ca6101a2ee4befee1c98296b8bd77138163734c0d5ab0481a162f2");
            result.Add("es-AR", "8206012c759c1e750c6f7aa2967158818fa672a4addc6502bec8e37cf6960a68b243d2dda5d128d9db4407e1112248a5aa2d6969cda989a09ef2273db4f7c8b4");
            result.Add("es-ES", "ed07d255461646c7a87ff8b76e4aa0f515bcd435e0637932f077f58665b9eb0a2b8539e53a1d2fa5bd22f9f61a5ac262e73b4d135479f511e3725fae97b43e78");
            result.Add("et", "19a51506c97a10372cee775a59ead25802a28c1fe309d95028d98cee225e115e807fbfa83b282a0c9c529369c605f33e0d94c4eea86dbc6f9fc3b15849c2cbbe");
            result.Add("eu", "cc19534c48895927bfd4914b0d78de380c59e9437da7407f4f65daa1b5170ca9dc7bc19b3ab01880bf5383d10e0f01daa39dc6f757bb22b86f18fb9c5c257cc8");
            result.Add("fi", "ef944374a160978f291a2d5d858716a74573db0eba4e69bd57e2fa420de8ca264c680dc376219429d3faea7f40931bb091ee3c78687d2dafa95447e7f1a58d83");
            result.Add("fr", "e5b00d722acd1ff53dbceddb1b3b73179c5e6e4d0f2d518b1f787f5e699084051ac3db279ea6c31910d085027c5953392ae52d08f13ba96d1eff62df4d31f598");
            result.Add("fy-NL", "0c26017d83ef1e2c8645bd5242171865b52e77b42698d49ca47db73b11cf5c945cbbc3d1cb67714539ff9e27560643ad6b80e65230965a5d27d406f1f473e7c5");
            result.Add("ga-IE", "6d57a51b8c1fcac4a6584de4fba16f24ee14fd5bccc890c38e9df35bc1d33ea87bf9a3e524e7e60b9601051fabc0c8781a2ea7097e71993a9b55223d23b9ecdf");
            result.Add("gd", "b4f3866eef58237ddaf9027cb63cbaeecfd58bf9c386e7254cf399efc995d1c0bc8921ed70cf954adbe0eab91ea096ab9914a1823c52a7bb3c211b3d90893775");
            result.Add("gl", "bebf95c8fe14845f977ecd392342cfa5ed6de1ccf576970e754f36fc216128a7c7621b12e14c6608249cdb19759ed5e73f1312defe2bcb2bf3a78b4642606005");
            result.Add("he", "d2570f51e322eba3653ab6c751fc06bde4be5ccef4d86ec2277a81c5691a6cc1510d723e14b08fbd63b153d89c8411bfe705f756f9255e076d1e0fc7082c8709");
            result.Add("hr", "0a8316e22c6ab549bfc1617355e5a2afdfc7533c78a00d8dec5a2cd44a6edbe22bf91ee3c783c8a465192ea59bff2e1e803112db608ecda7e3f3a4fd05bbc6ca");
            result.Add("hsb", "94168f1da1e7d16fde8644d6f8594714ef4ebbe3bd679f9d4feee58fa4f7eae9bd94fc683097810a45539465da66b3e2ad9352b12dca0532e1f46a04675a99ce");
            result.Add("hu", "66316d6791da5f3e5b8137f1930d75c53146e3d5a27f1caa79fff6c6d3d6f525a0c88b3e04fc19a71534ce5aca8efaca4bec66cb0f15fb106e6591dab2ff9422");
            result.Add("hy-AM", "c8159bf8766178b9d55291ce5736ecf52f66f7606e18dbe3cff9456da6f8cf343eacc87c04784373e686a6613ae19878a0df177fa95ca08ac64ee01bf820600c");
            result.Add("id", "9a18f170ab80c02a204f56285a9714c4f74a7358a966325a673e541c477be4302a99d9f6c01eeeed1ac6192c10905806db4fca93be7c24b3cccbbb631180fdd5");
            result.Add("is", "f2187c86840c1a43ef266fee65226027ca4dffc20c0b2c3396aadadf7da274666f16a05829427caa55fd56bab268d2abb4e4e1cc3c1da06467e5f75041756648");
            result.Add("it", "cb0e215fd26120a38fe8bc9012692b88273d23839429d23846d346a43c5f11b4a6393ca39ac65084797509166759cf31dcfd6847743202076f5f120fd47b916c");
            result.Add("ja", "9d893979ef99b7172a45d1a4cc7b7f4072c0037a9d24d49c6f76ba2aa625e03fe1811ada89e4fc8c5024d2dc5c161d341e1be17070889b6e5df79d514af90a3a");
            result.Add("ka", "d7e10ef09ebcb67a3c7ba474e18307079fb571905fa15281ef55b724cc49f4f4878a572eb07373c0fba22278616e23c88c218b4ff70ad4b4ac5e9778b1c80cad");
            result.Add("kab", "d45acd567d8dc9939c06b521c2d3836dea94f3105e5b3726bf1d965d0b8275cd92a50a3fea0dd999c81861b5a1be01e84f72bdbb240b56356bc7710888f19aa0");
            result.Add("kk", "4e5e6d26a81f295c307b05cd83bda8af875660e2d4f1cadfaf36e787c84155c372a504928fa21d95580231f394342b4d9a0c1f8a8769038feaad315c41425d9d");
            result.Add("ko", "080f769f58fe8417fa57958fb208bbd2c972e038958d5a2270d148711cc80a4baca5ce951a284c4eb2acbc9ff411d27c08c88b52602507fd4954cc04cb5f6a0d");
            result.Add("lt", "b1bfdb4043a3ae87153c9324f65b8419e169efa93c17b38491075cb922b540380842f74337683cd2d6fd39b8413e0e6c648b8edb595c92f8f2518d6d314c5019");
            result.Add("ms", "346f6db4d6756e718c3c00c62fc4783a954f0c33bed7d541945858a9502116e3802f50443ba95b629743feb0f6c25b142968da1f2e224d6599a6c5523ecdfbdc");
            result.Add("nb-NO", "0f26b681183ee14aea122f99138f022a71918219cfd3d3ae7ace49ef906545a44e6f8ec72a9e817a839908af0c422773fb4a697a25e61033ede7d99d20400391");
            result.Add("nl", "954abd933d4bc39d1c340289987e392a4cb496efb27328ee0d9d7a666bda9ffd342318159bf2ae177eee71bbc7808c54228917cea64c2b87358bc04a257b0926");
            result.Add("nn-NO", "da36df446e088f35609a37ea197c4401a74586a5fb48f72e9a86298f7040d84f4fecea2996eb7100cd6004dbd1a41d7b6a794927bc7da11781f4d7f8f4d2e58c");
            result.Add("pl", "8e4071bb4de87e0d7cd22ca58c22e68530b3b6a01826854f8d3b5cfe9169dcce0f0fd00891a0bbacdb9e423207d8ff8c183740f9bd11d4a82c2e0783169f0382");
            result.Add("pt-BR", "45144c7375401d011fa6923fbd15f54dc6a24c08a5c1a662c00a60a3fe3223b3e2422de26b5d6b725d1fadf17f2f6f385330b9e0677ad3520ccce744f3c7e378");
            result.Add("pt-PT", "be5d17fa051300157afeb15198103c8776260287320c74f7d53280d3ecbd3a049fa2221e8cefd22f86d0fc9b3682075e07f689909d5aff1b981d1b28eb672863");
            result.Add("rm", "af12eb514e3e88f41cc3625d286a39c9e2ae7e3a26480cc9c52c6a676b3645e9226512e0ab4355806ecce2a1dedf00c155c2173567bd74c4fc12f7185abb8b93");
            result.Add("ro", "1fb6bb36b3c06ba909ec4f7fc1b6688b1874c006302df8c8b9c938d588c346a38e9fc2604aed80a2dbe6f8ea74dfc90a097d0a5da42eeaa7eca0d69d4050730e");
            result.Add("ru", "d3947bb7ea9720b00bc1f5fd24f5c81ea9f417949fc83cb7c2d78b0ced543916b5b48a9860dcc106226badf16166074413272261f5b4b39bf97bfcd20ece1dc1");
            result.Add("si", "a1ee1728e8fdae2601f58cf6ae2bd68c1968e7f6fb540e770659e665a53b7e350dc39464483d399dd092778ba3f9836c888745e5a3444608cf99123f59eb23be");
            result.Add("sk", "05e777f0809b9eb806f35f60020d3f104c9b2c1f54d6bacc6d8ddc041295d3afc1bd403a925deb62f69241ad437e46757ee551e16120e8d2d18e45d34f336d0a");
            result.Add("sl", "7e5109bc7025fc5aae22d91f3392a524c9493ac770bdbc5f325213b71e312cf5063962e213b797ff6986af4939f0ca515da53f9f2add257a6f76272be13be89b");
            result.Add("sq", "2f3ca7094730b517a8fdb3cf3032487d7a648e64af5c7f9a28786f72c4e5700ab7955835fc4fba6c54835f3df1d9fb2a0e082a5672ce9718157c82fbbf9741a6");
            result.Add("sr", "b434f13523378a87b187ff422e6cbcba46baf92062b9f0b580339f33698055611589c367a2b50de7afbb3da2785cc3edc1c0ac4fe503c8a96ba49e6d7505b3e9");
            result.Add("sv-SE", "8497a7a9898081f379ff2545e51585bec6720273f9e080676d920475f8600db633be8768f6ae8312a4fe64cf16942f19c7d7fec253e2df11a7e06845e26a194d");
            result.Add("tr", "a9d95a8f0d1692e61f3498b4ff5637c892e9495315a06154b8dca9cdefbd1bf8bd6634decb66ca11ac37a87d7010df50c1c777b0d902947c121f9d86a19ce265");
            result.Add("uk", "c39af951244db0d8560a7d289cf4483dc93e8247775c9cddfae5796e20dcb5d701c8732d915836c923b1436a1318e95c4c1b5b56faf9d0d64a9f022dad73b576");
            result.Add("uz", "4c6bbdb37e21ca903d30857ac8e8b859f9535d8a969528d12f940984c4e5837a5f37e76a6c8d48d04acc5c573cc6b72567a04cf21873f105bf1ee42c08f0b5af");
            result.Add("vi", "8804775976d0cbd2153f04402b1b3ca2b2cec6d18d0d4283a0fc32ef6d54fef6b4a78ee2b97acf5dc4f1eacf76b666042ea447b93e62a681ce9a5bd79c1d7adf");
            result.Add("zh-CN", "43f4a2484ddcc9f08f3ed8703bfdbbf5b04bccaf30dbed28aa37da40b05eb23c672c7297b02c575d36915184089d36275bc5d6d5069b507199e53f5a038c1e3a");
            result.Add("zh-TW", "5ac2222d2744495aadd59769b3639f4455fb1e46eb1294625de8f6a8802b300198c197f9adfd788040418e8fcd14b9236892702629465ba1799bd904e424ff7c");

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
            const string version = "68.2.2";
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
