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
            // https://ftp.mozilla.org/pub/thunderbird/releases/68.4.2/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ar", "7a72e0c4a6b9a9bd3c5ec9c4bd0a5ff445106ac893fc39bb68603815daa8188fc3ff239a40d1e750a039f7fbcccc433fabd2c5094e5d2b21bc13c9e65ed1a41d");
            result.Add("ast", "ccb69c181f51dce88d70e2b739085a89c493ff5b3f7926efb6dca14a106d28222047518f28d39bdf1dc068833815a7c3a3c1093b6ca30d5a714b118b51dbd271");
            result.Add("be", "7869584badea25296681d66b987370f6918742a6aa92f6d6bfc039ea87b0e68b80c9eea8fb7035e82b2b404addf0d898e8676f3f674724ea2fa86f4c671a833f");
            result.Add("bg", "b585c9d50317b1b511871cf2a7b82e0fb4f9dda08fd42b32855b916a0fb5f1af82b69a9d899db437eb49a70fbfa3a5468df3e4bb8c65cbac8d4e25747ea984b8");
            result.Add("br", "da009967c5ee874dd7b063e27fa2f55bc8d2434be8b77796670911bc8e48ee7e333cab54e7b28f690b917312e41f1465345a2d988fd359ad9d91383c8875d4b0");
            result.Add("ca", "e6d457a64f4175972c1d5b6eeb024bee0d103ce047e42e4f45a70833b9766cbcca5040e9e3e79d47d47211e13becdb9fdec210594a9625d656b16ae44e82e62c");
            result.Add("cak", "c2ff7b6cc7dd029eba669bca2aaf427a7afd3d629ab1542f80b380db4cb0cdb29d4605440ce699856810c687f73f29285ce5e4ffac20154b88dfa0bed56e8b4d");
            result.Add("cs", "cfe366766d059b3f6566543743a1fa6ad370bbb9f947965ed15eb3b486012b78bfc11208c16fe4c3d474904ab21d120a99e7826cfff61772af82ee0391c0bd03");
            result.Add("cy", "abe59845b3903b123d08bc7e33df723170edb98a884d13314614157c1ad9aebe6b72b4e3227a797ea5aa8690951ea9d441e4c08227233f035f637594b754ca69");
            result.Add("da", "a70d34826b473dea30cd2bd8fb5c88a87770981a0f1398a84b7074817dd7f63ed584fe41904d689e6562b00eda65e943c3b74d34531817db3ca2a054bbc30d14");
            result.Add("de", "a8df5471ab52de74e3b5268fde2a9cc9fe55e8c54a2c192d738588cb06a8e7f7e1f51ee10deefa551cfb6cbe0257b7fbe330592a5c423f11e0c2bbdf1a038c13");
            result.Add("dsb", "8ae21a3c586191f4b6162294f71c533426e66e1bcc6f237ddbd82ec9ea35b4f90c06352400cea064931ee7ff163098faf91ec8be73b0ff3f517e8a847e911305");
            result.Add("el", "ab26fb9b5962dcba812c8b0f5a46cb719c16d567ce4561cd95351c446fb0874cbf4aeca47c9a37fdc5c05981ec04700fe9130e6cfe7b9224d544cf0cbc136909");
            result.Add("en-GB", "bb8aa00bfb8021c03db194e2f800ee9e3eb49a6d8f1f4f315812d255974201adc8672429a47c0cf0199729d52b7e63814114f0334321602f831e694636ccd4b5");
            result.Add("en-US", "3a6043ed76e1e12a898897dbcb1b2503b435137d85d073e3a92c929bb08901749c6b264908fafdf58e4c19d395086400005200983b02f9d5bdfa56c972c728a4");
            result.Add("es-AR", "7e12676b0fac940eb5b6ae473402a736da59e401682199468bea77e7db128af84b0ad5ed874b35caa711426159220195d4fedab42266894fb0e2ad6dac1ebb33");
            result.Add("es-ES", "b8f87f0c9afe89acc90dbe58d42f8c4bf84ed5f6a6e960f66c6e570a670e3d435bc992dca87e6c9f359b915f475af2b04123761571b551d52870da3525179967");
            result.Add("et", "aaf785a399f9e20d502a6a873c24ba7375e88e27ddda4376466fbb8c0f75b6b2a7c0ff01d8db2d5fde71c586f253ebddcd66a687ee3c700330ea5ae42921bb3f");
            result.Add("eu", "063a867b093d641152b1962d37e0f41d07c3c93550d57b3ae61362ab7519ccf9c373a7ed97022a51459e5e18e0325a64c8035a740caa2d1d96e7c7fb815a7a89");
            result.Add("fi", "162644a387a45df49023e6faede07d84d7d1df9d31243ce109a0ef8c1defdf365871ef14a829bb3c08e1006e7682b9211d1e2aac572a519c7543fcaa04e7065d");
            result.Add("fr", "95b0829b6e957e50edc7e8415eb601f00009dec81f2db991abe5a32b903312cdaf17426c8cd4560050c1736eaeb65d7864a676050df93b6349d0c28f0452c356");
            result.Add("fy-NL", "6ee7f0eb79b32d4379a176d1f6cf2ecf936b192bf7c4141f9dfb99f0741a7119ccbc965e3b9ac41ebdee766b9ae90b0c6f9047a0137e88994f758fea2cdf1f6a");
            result.Add("ga-IE", "66ebcf024b74a03344d8c925bf9dff64c322efd0044004fc2dd9b9d2a476a4da4c4dd24c676fb662c602d9aa9460974b62b85fb33d0b7ac8aec1882a67803c88");
            result.Add("gd", "fd488db478b8eb6cacddbb826659fd757ce95b912bcf5158dbe4d5db6646010734afd18a762c1c94e48f34871dee083f39555d05690dc674e76c51aeb736a0eb");
            result.Add("gl", "ec2d7f49241ca0555105539031ea828668d4f8b4f85310a6c058a1a5bc999cc81a918c43babda2bbd5a3aa390c74cb4723a7e084f94a173491b7c5d3441ff4ea");
            result.Add("he", "b18dca8576a5cfa5e7ad3a04da84621a28c59db42fe36af7a211ebe448a3d21631b09e40491c92b5d06ba679864c460dfde8706a5ea724b7cddc066e350d48aa");
            result.Add("hr", "e020e44b5c7ee9b0aae281102f7898529fcb04eadf4a7f0a07a908401f4ccf90d3c1e41e188cfdde0823204420fff1385fd4dd45d822a6af4d34047cc0d45bb5");
            result.Add("hsb", "09964dfc5910bc25deff37a6eb92fc1e9810ae4648390ba4e7474e0ea19b98337685fce10786fe3e5023960bc7337aa865efffe3aa04e77148b3a9be9ad7370b");
            result.Add("hu", "e0d03ddb32e7a7990da0b4f8a14e9269334722e3b0f35322f40a9cec0a915379e23d3620de5c1092643e3278c6ff798328dc19bd377ae71ebfd1974a9fb1db37");
            result.Add("hy-AM", "698f871f19981f2e283595f600b7b88c1e808cbd9f66e9107f7f2a1845ff22062435b9089e3c8375b329331bc4c9e9ae9f131a7ff7c2bcaa9ed60878d784e4a8");
            result.Add("id", "cd46941de4d0356e1d118d2b7f97d942b9842fa5a9f9c4184060d65bfe78662f43de79624fef0de43a22e640d5ced5f94b42d812a12f471e6b07fa782434bda0");
            result.Add("is", "5d61f540b6cbde7faea5648dae68b91dd5d860dd1a7c7fd8956f51278788c7b2a2ebecf925e478973c36300bbba53f24d56f1a2edf0406b5af08c238501ae28a");
            result.Add("it", "b37bc2928e46d2ae95519c8d1676a36e2befd84710786db95e162f9641669ec3022750367d8266d7e8bc763b6ec1dd8c2db849d6093e6680beb695c5fde9706a");
            result.Add("ja", "c644f39993d0b16fda230c3a2f9cedb883ce9fb2bbfea77800a91e179a32dd09324a55c1ee054d671470108c73ff0e0c68636cacab9dbe282ef2ea84bf25d79d");
            result.Add("ka", "6a87e25e79f80febfcaca6ec1e72de0e55316599ff2a65e6814cfc8206134225bcd648dc510034e14c13e54162cc82efe3d25dafdb3e8210f5eb85275f3fd223");
            result.Add("kab", "85ca350360fe889f1f0c4d8ea964103461c404a75ed1a49f459d4569540bb13df8bd348042f08fc4f6452314d340532fbf62f00a51c882dccbc5bc7eaa17da7c");
            result.Add("kk", "276a22a97f322141687112ddac461bcf08ea5fda1e06155158a5928f7f00d4e9a858891434235474f244f6f6520d02a7114a5a868b39671e2c536c8d1e7596d1");
            result.Add("ko", "e37fceae3034ee84a1031f3318d8b6f4603f18a32ba6b8a967735098ae91ea9b27f65907db05f01fda1bd3baeb912186f065423dc40cc16c0ff496e712953e98");
            result.Add("lt", "90f16478fc3a69d4ef74e0b144cd3932eb9ab6b4d7ef8ff5e0b075b835f9a50f788b1d715883b8dac4e54fb96784dfc324008f376be4cf724ad02480e7adc537");
            result.Add("ms", "22cf1826067d3cab4373b084705fed287785df523c1d8b2058e9f2f50b28935f88d82a2078b69294413fe359f7cd88129703931a882bac345fbc139fb1ad4a42");
            result.Add("nb-NO", "5bbd77f9b51da90c6818d712ef54a0a42082fb3a195e9b0d71cb1fcb0b7b66291a62f534ee96560c7a080c3942122a1154cc16cacdebfa96cf38f229af770edf");
            result.Add("nl", "90855408119e34273c869c33427cff96718bb13f4c52b9d402eb2d6a450632b1bf59f5b772270a059de2d68b6497e1dff16403ed50bd49ba84290a6bee2d3773");
            result.Add("nn-NO", "6a9c2e853df6816fd327b72405f9fc24dd7cb132f56e10764202e71b75ff6aa440e7a4daead4ed1eb57c14cb7e44bcb4491cc6de015e941ed61a840e724ce51d");
            result.Add("pl", "9740579c7ac467f8360452d4e2a6babc6ca24632217b389ee240e5771a588d7413f746fcbcfe6a0dbb0c900f13b76fa2f700f9b8286e07df56f717bba712ef43");
            result.Add("pt-BR", "e6255511a20ef91432cdcf08e4f05e94363dbf5c758be028f078561f91043ee422695a9471f9cb4007df0524f14021ddea10480f20516c59295e9fe295a491a5");
            result.Add("pt-PT", "ce61d7ae706a9a1c581c4e637e2c9e5da7c5373f399c9ff9a57d8e56231219972a4ee9adb24aeab6824a516fdb84882220f7b9d6b35791e4675903c64cc49018");
            result.Add("rm", "dd2f952f3f17d23d63f77fb8feba4c7ba1833c3489262111e0c2a087413d85477d84570c8ea7901e211b432cf8733818df9f751ad9f36aade366c2d348696304");
            result.Add("ro", "afff58f5f4ab8f426b0571d73973d01e284a0df77b0878bb6ff2b59e97052c2bea18d152fb8b9ccb2218a7a1e9e0f0501a44ab5ef5beefaa03d53bc5d8da6b6a");
            result.Add("ru", "b85206fefd245f1f9342825c0dfc7960f4127ff89c386d502d77b11c21f8b15bee5e0f4464a46a4cc5db3a833b54ae7c002a7337f2d8bc686718a50d1ab6446b");
            result.Add("si", "e5bd0d651be35455ab98a2ee4b19543917abb7a499b6bb63dbc15b39a4b7c8533a74e6bfd0e831a88713750f6e58e76c5b6e8cc34a049fd0c113a734da2de066");
            result.Add("sk", "ac308f80f0299c37b2f0d589a2294ace0ca5e229a9bf32da52d88fe2329bef09580510cf6ad248e2ebf5664f89a56999b6ee69bb4ea511741560291f79b1bd0a");
            result.Add("sl", "36f62612be8217cdb52546b9552222943eda1d98ac5a6772130e13bc61feacdb19eedaa0928979461c53006deee2f3244cc9d58d8a622d0de073f351315c3237");
            result.Add("sq", "432de6bc56ed137f1964b8ff7dd33ec40d614b4a0c103571a4164dc6797f79c547bafff23c958856f1359f08a781e0b465926b715bb52ce8442c2a5413519abd");
            result.Add("sr", "d2878c260d2a9d99ed1ac6847beb8d0c81909073f5b479304f4118f93dc35e879dbc0edc05e032534ff3565a1aa6e28dac873af3febaab606d4f971704a0a52a");
            result.Add("sv-SE", "5f82a8417180f1f8e72d48e4ed307b843f84ecf499c046b37113faeea66984f8039fc6cf77082fb69cd4efd2dee2a7a592ca07781fe6eb723fafa519c51c41a3");
            result.Add("tr", "8b9c74de8953cf36728debe373595db31c0b0d367b4981f5b1df7a235d38a2f6f8a26fde0f18128819cab3f91a707c27f6a465782c5ac24420ed8edbd2aec356");
            result.Add("uk", "cf147a4da57441990e108703d84d8eaca402b31540f38d4ca185a76ba24578b38df6cc7acd9f5a641e32504c91de5aa0c452f648b551d1e08a3e331ef0793cab");
            result.Add("uz", "2ce9f3d942fa7302e6bc69df50d392df3d035623868235a564996bb186991092aa11351670756105144549af9154e49ea5e988e5af0fc923b3b0f8341aa1e701");
            result.Add("vi", "44c3cfae35cccfff72f930f7154a8731c670db1430b6ac927b3fdb0b5e4f2b7e7dbaa6c6093a7277a2d540094d7046072b70d65d35d1093880f24fbe4aee3584");
            result.Add("zh-CN", "c5730009aabe06addc4a8d7acc247ad99ea164889c5423911da8db53ab8fac241ddc22096fe578f4ac4ea83f00e94734faefada7763193c01b367c19f7233f66");
            result.Add("zh-TW", "7393a52fe2ad45712a9ac282f3eeaa2a749357c5637c2b8c9c5523274805c63bfae976283423d49b2bf3fc4629f3ede13bef35d219cf830aa6d26ac6065e727d");

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
            const string version = "68.4.2";
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
