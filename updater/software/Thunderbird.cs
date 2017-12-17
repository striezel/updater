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
            // https://ftp.mozilla.org/pub/thunderbird/releases/52.5.0/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ar", "0671ed489e2f99491c607cd72b8f8b921ab78f0982c13ca5872d928c0080f19ad26a588a8dab98359488e484312ab4b5014b6085e6ffc9a23914a344cdd02f89");
            result.Add("ast", "dbaeb9f9e552c131741858a1d6c27e982f41bf4c812fed91e3a074dee8264cb1281a549d20c2a19be190dbba5992b90cf567885c79e44c98d5e7f673db93bfb9");
            result.Add("be", "90f91f8284851d282f8815855074146068b906be63d122e85f22930311e03d7ce02ac1a63dd2ae47bcef80b45e71eeef811d90136297814ad07d4d1015f17e41");
            result.Add("bg", "972612f975fdc013757ebd5ef860243ac4f671407e0c184e12029e09e70f3880c72e7f7302f5cd54777e080a346e742542b9d86fcdb205dff40384253640fb38");
            result.Add("bn-BD", "a3022169e3dcee7402e40b76dbad095a139c039ff8ab605a7ad715e2ae202eaae2fc5d2bd8d52a0bed7e3c144bd053e61a1746ff47dd6c45a6a4432537ce0539");
            result.Add("br", "8729d06534136003d99522750d7ba5efaa4211e30f9ed9de700aa61fac71198a251bddf15c373954ced797b763d7a43bab1d7a70eb801fc279c7c8fcff97e324");
            result.Add("ca", "b2aa028d7bef1b8763c8e9f159c42ee2aee5148a2a0147201dd0235bcc93a691937caabc6c34f98ad0c4bc90cbc47d3eaa179d45b0cc7ec0d6964ff8eebbb72a");
            result.Add("cs", "46d369343f696cef39f4268132ddd5b39b9c90dd3b874779a5859d9668e56090b7584ff72e32ec052e854b25cdffe2ac5e11cd5e9a0edf38bbac88c697471ceb");
            result.Add("cy", "735ea136b45e4d90f553f46fb311a92151f5ec4ded06ad3e5c26a83e76d62698b28bffe83029653982ff37824921cd6c9ca72f5bd9d2c7b5721965d8924efea9");
            result.Add("da", "8137a520dd4930997be46602eee0466b3a647ab526518413db230281a67a45fee29d653c2c4cf7edd7f6f424987a58e6a28f7f036609d587c89c35f2966dc5e3");
            result.Add("de", "45660cc27f5b3668a23d477573b8b8b3245a6ccd2aae35506e13a0b022cc5bfca23f592c5b3f65a8a196fe3a4c993a35e3bcf71af50ba1c47871986dfe49e6d9");
            result.Add("dsb", "93a2c59623d7aa80fa2d1f14dc07171770d7b3e118ceb819c56e5d664fe8af7c3191782daae99495f4a13992877715854fece83db9e5a05599765505c3149756");
            result.Add("el", "4b25ce9daaadff4876c41b02a2f96c269ce23881cc01602ad6447aab14d2422407e213e4409103cd122eb23bb5d117801345121b6c7fe95a3e46f42f468ef92b");
            result.Add("en-GB", "b4ca61f5309cb85c6a68ca537f0aadff968a99cc6ee0cdaf73f06cfd030d8eb9d35c955d6dbd7acd95c257f4df56eb7fa28d67f2d31ee072f8110eb9e312ad12");
            result.Add("en-US", "dde6d5c083faeb4aa50f383bfcafcefe3375e55eb117550ae5e0e85069ee2b28996f72b868b4a2afdb90685741402de84f14428f14f8777163a4dd2ff780157d");
            result.Add("es-AR", "2d6265c26fcb05ecd7420796e18bf17575c9e79512e63847dc823889eedbe5283b4b461ae636ddebffed5f2ea28bc247abf3f7312c676ea6bf691acd4ec7e0e1");
            result.Add("es-ES", "2c63f2a043f7bbb4417b916956894b3f4fd7a25aa98b220b751b9ee274720be73003960589b43dda2237eea642d378978ed882934a66cf75ed6d61f774694544");
            result.Add("et", "a30233af6468272bf53c9951c2e7b04cede74593d7c5df17e2fd2c13f56032d4598c396e70b23f86707abdf65591d5380ffedacbb40c03d14de5ad9102a3edb1");
            result.Add("eu", "f271039f244f91e314f7266c53e3f3d33df9d13bbf00f1ccd8c89ccd2c8d384d0075e75294ee539ccb4acc7b06b33de500501bdc34abc028ebb75d408d9791cc");
            result.Add("fi", "b6b2496f0e5915cac1c71a7273210f0c58daae5597a6b76e0014c70b9a71b21b09fa6af00b0aae1b91113a6922a0d0f137663471b335e04b2805ef62ba58269d");
            result.Add("fr", "b8df1f4f1b330c5074596a5cac932c225dceba8bc5d7018d60f52845e357d441fa0fa6779e8ee631a4f74fe8e9cb1a26715a2dd8c63fb58be3ec84f6f284b3f2");
            result.Add("fy-NL", "42ebb9408e9601acbb3758b30ecb8a05de28303a50262228c9bbb87df6028877dc0f4b67f4b6eb53c2675d27767e449cc0ce4deb0c2be667a03207145f3e767f");
            result.Add("ga-IE", "03c258cf66ea2a2e3f61c7140fc188952adf225cf02c25965bb2a5283f6c557ca377d561d352aec654cb0609945ea76f46f666f3466cbe93122580d4bfa246f0");
            result.Add("gd", "058e0a1cc6f1cc7d6ea2e6e4241ff3270f26664e7124855c32f4b128133a3748c562d69d4b820a0249a56bab8980e28e521dc803e03b8db1821c57da74c97c38");
            result.Add("gl", "817568507472ab3136ebb2e8a043c4a72f959708448b46374c3266363628e218af0ccc622d89eb12cb6a96bad4c4b83776b6baddca4fe571d42d1dc7c1de3ccb");
            result.Add("he", "291fb1e118c5a1e562998bbc065a0fc5491bff215afd98a09ec4c86ee90d61d1980c529334a3f874ea9063f9d50aeb56b36b627e59a25e3a6127661ccf8f4047");
            result.Add("hr", "097f35f476ca4232cea0eeeee611b127bf6cd3a2c71a9d920b24ded7d85219681fd06c3a5436ef05188a6fa439b2fcd30bb6fcdf213e1cde4bd71244737870e1");
            result.Add("hsb", "bd11f4c992fc5abc5d12e91e9530df13d3c6f851cff69467a415f18b24132068781d4b69c8da224bdbe72de8f86c1deeb2b93debd8b31f4b73e9603ddaa5420f");
            result.Add("hu", "507435ce53784322c3c33752c87c7b4108feb4caec0a01f54410d38b91b79ae18829f90a9a8bae79648321129468bddbb5e98f730cdbae7f9137380854447edd");
            result.Add("hy-AM", "bad299764819d2a1569069b57f3dfa362e070e0b64733ce3a9eee27eab6b6ea57204c80480c01a071516e07c46f58a47ce61e29a4533c00c4879495897d2112e");
            result.Add("id", "ec4aa1fe510d7a499384bf2d69ea64e7bfbede9255f39f18268d73ec06ef66dc5714ac0db8d253aa76a9420c694112b3e8ec4377862273b1f1d60725c6996101");
            result.Add("is", "df7e3adfc1f29e9fe03ebe6a9376a8652f7451550bd2c813cf9acbd622985bc938ea95b75ed1a2c585c1bc7d60361aa75ed6ad2dd5cff320d6ee4151965c71f8");
            result.Add("it", "74612816da5efb160293b8210791f542e375e3f41ad0f530b920629bc1b8431ab6a9d2869944975c02147903baa4202f6eaed426bdf2b473d6cf1a6575450096");
            result.Add("ja", "43e3a2f712d757b1817856f13da5ad1db18040c6de81a36253282c5f09ccc6a36be5359e74d5dd63ea876f625ded4bef82a9d17a1d0a7464eb770b68db42f24b");
            result.Add("kab", "a79ed813f52d50df69e58fa363bb6dcd97399023c20626a9bd59a1fc6e7b4166ab5741d63d8812a692d028c620738158f5785b037232cfec9304a7ced074782e");
            result.Add("ko", "36255417e533d8344d3bcb1a37565b0e67b3771102307634c0bdafdf3aeba6e9a4a2ca5bbf880c6ce25ea5be6a7e0e51bd55d62b02b9d1705b68336633536fb0");
            result.Add("lt", "0444b83e2432c03ae68de06de95e6c6a48fd92ddaeb555c2e23048a108bcc9435fc1036a01e14e1d9233d9d1f038fdae0a42a50a779c73131482a61498a24f36");
            result.Add("nb-NO", "5cb88ada4b967e154763f69b7c98172f69b2e3ab39408a315521660ac4a5a8018a38e5571256496bc36dd11a0a2c26fecfd7b371f68b7ef2c07a0dfc0189dca3");
            result.Add("nl", "26a5bb147653f981340b7d16969dd417ddd34e31c86c993a94deab2694a664fb8b417b6bd096849d8dd4739958317e24b058917330f40769745d5144d850c44a");
            result.Add("nn-NO", "816780d7fab7d3611db5d3eea8bc71fd08811d598777c0db7cf7825f557755b57d7daf3e0ef5f86c90c339ac6c65a8ffce194f84afad4a7fde68656b4d16d3f5");
            result.Add("pa-IN", "b4b639fdbc4f1533f5e8ca62a63ad9dd337bb49ff9498c55632dbd55712d2b3be9a33e845da3291c226c886f8d5c740b6250f7b985f50b6415ffa8cfb0a6508f");
            result.Add("pl", "e8fdc639d83ad52b697c14f0ce4821a1afc7f9f08ffd609b07217c163991629d6ea21dd6d2e234e39fd74f0be931b5e365b9d26ac89a1f969cc2eec0e6afecb6");
            result.Add("pt-BR", "239adc3f4cc9ed6f8d14515df474f6d87497f58406ad626c2acd6aeb52767b6db4896b9989194a76af0de8a70af088badde00146977e52829114e340e978048a");
            result.Add("pt-PT", "9301d4e35f03a68e85344f9599de99a5c17969d01cd24bbc3f5353ffd7006a9fb17eb741cde96d09c66e7a7995405ad71ae3b8a484f548d9ba6e3ead9b5fc967");
            result.Add("rm", "959da4bf8c3edb0098f344489a8e82ddc9a9cdae8d7d6e96833e3f4860f86355243e7cfc65924d7e4d32ff773b40b8cbc637266bb268f7eeb306db5ab8abe53f");
            result.Add("ro", "ad02fa08097190d7b70f3feaab030121fce6f1cbd47a0c31fa78e0b4f60751434f6bdc7796f43f5eb0dc8cfe2d307cd912c0913c6f12fee27dd78969e0e26f85");
            result.Add("ru", "9a033145d0913511b04c942180b92773302885ed7966a08b433843cf620769bf3037e9abb8a353c6bc8424d19e8fb45465b85322ad4733d331702df66385d04b");
            result.Add("si", "3722dc0f6e2507587db2b662a65e1f571c90f9c326aced405965bac0957c79f739b8da1011b67f3cb98de4c35ccb28687439ce52222ed5869794d253c3b70cb6");
            result.Add("sk", "064ead02b8e6e64be5e0ae99718ece4c1ebafce40f003859bb37f8de253cba3466c8762f8603065cbab81037526ac64356473b1979acc3e5b77ed41f5fec8851");
            result.Add("sl", "1109a4ba8a9985aa7d358f2c9219fac4695b5442048def36597495c5161900634fea0b3c3ce75e1ccfdc10f21895d1f1957b751ab6322fec3ef6f010296eb99a");
            result.Add("sq", "3bf37e92df24b3b17efd532d4b39e8e8c29d4081ad7dba27de7e44f6dba2692ee1af6d89bde4b9bd6318a8c0f68ac3c6dc01b8294c2af37095c7a43be235f3a2");
            result.Add("sr", "7e50d168441b9fc9ffa1af48d82fdd43d7c277cc71d7df2fe211320df3bf43a994d3e23fac19caf08c7ff644edf200ed8ce245d01f2d025170ae1e0070f473d4");
            result.Add("sv-SE", "313ec28c259c49c8b8107c6535e35adec878ed2790aec3642035078fac481a7fb2f6d25db675d439384adc93ed501ae4ee04a1383be470fdde9944aa4338753e");
            result.Add("ta-LK", "4c4978099fb565c2daf4230231b9969715ff6f7a8dcbf9374041b1c23b5d3aa4b6f67fe428eda45b0e00e81500fca82fb85e36805f702a6ba061b6924f2078cb");
            result.Add("tr", "cac4cdfc72c93664d27e70e3569fed5ffd05af764061d69efd92e7adbadca8002b6984036bcf26f904bf05c999611f5bcc538b1180ae2448e6494e3b39e9b7bb");
            result.Add("uk", "436f7b6645f5a3fc95540ddfcc88bef7ae56465adfdbfb1f04715547a6580ace5194b98d9ec0d1d72a1838f727d9ca65aefdc38b29d8fec4c889945d1277a08f");
            result.Add("vi", "6446ccf587fd51611b9b242b3364db5b4b91e8dee68d0ebfbf11573fcb5f1207c347745a98a278536eefc5797a55fc128a17c0464825c7790f02ed2cea4ef593");
            result.Add("zh-CN", "a4bf4482e58bb2c91dabbe7f2f8b9e1925eff0ebab0ec7533f1eec84e56ab682258adeae5ee26e4cd6944a810446d5c79ac632cff8a0dfae7e8f39e86e3221fd");
            result.Add("zh-TW", "fbbe9045bf7c44e81cc751226c4d4f0b6d3510d32cb43a3aa181969627f8f33b58729575699036e8813ac01320538a17c03c177f2fe1d23afde80aca923c1be0");

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
            const string version = "52.5.0";
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
