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
            // https://ftp.mozilla.org/pub/thunderbird/releases/68.3.0/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ar", "1dd4e2eb9fba1dc3772955f1812ff8db58a87d7ce9306d0aaebe39df40de57cd23ed8997d3a0b1fff767c8886d628af853227f453c989229d6c51ac202344b87");
            result.Add("ast", "e094d46015d347a8052e171cf23a9784245d5fa6ece63b460a93d709e64c6b1cee9c7c81eda4dffa9779ec76429227589742c4471e41a85dbb5a663d6e746df3");
            result.Add("be", "da4a0b05bb5a6a71bf812ff63ffb597bef22609dcc2f56a628156887abf25ffcf7ed5c15b497f43650f9fb6e0d3588328824716316ab941cd296255359bf0a99");
            result.Add("bg", "67c51c25fceae34241bf00c51bfb8433362fbbcca6ff12ec8049fd9cbaed5ae1eb35b69684dd54b7b0e01d540c10357e5616ea7b25be17250e56d0be1db87b27");
            result.Add("br", "5d3f254c4030e5cd7b8f55c62a26c7efa114759a9d5677f5aa1913b2a2aa492cfc6d5d406000dcdb26bf1ef757a5806409389596e98102faaad2042ae0ef0c4f");
            result.Add("ca", "95c3320502f3c7a72497ba5cc1a92eece90390640cf005b5cb12fb51b56cfa17c05fff868a6652143030c5061e2dacd825aa389cdc198df16f6f14b483f59397");
            result.Add("cak", "86542f8ef5fc4cf24152836c7c1cfbb6358acd0df49fb1759fe9794307c0c96fda71300955d21521df94ec1344a68cd5da87f930fecefd221543e00a73f5b905");
            result.Add("cs", "9a5772395a70df291c5ac0442d698f2ef57040658521204ec5fe3382f7b48039ecf0b57ddb123f5b5753bccaf60298672ee514bb20b896a8a047a09b029911dd");
            result.Add("cy", "d57848afbed13398224e7c3fb947c140bdbb6ede9fc1604fcc0985859b5e51591368e714a3541deebaae486ef5c0360b6c894bdb383a45ba611a3c602b44a25d");
            result.Add("da", "c533c839fe94cc3460f54b548000f578591065770aac41f23163e67309dfea39aca3bc862081e97a5536f499a86d742ac56be1b9542705ddb6e2bf342b557166");
            result.Add("de", "79117c6815199f17d6efa0799685cac0078218bec8533b724505c92cce1542acdcae1268a7943d6f27b29c2e858e8e28b07144df6e6db67d494e2162e3e85606");
            result.Add("dsb", "a5a5feec6127ae4ea3ec4ada736bfc9014e99601feb6b7e2fc3952d3502a4538e28f8c4c645d3ae7f8a682959783c4170f2dcb6af730c3a708c2cd7dc4063e14");
            result.Add("el", "aeb3de08576de24b6a1023778fcb8e6332a54cbb0fc4b755d7c85e5fd2ab20cac828ce835f1c24e28c1acba241a9c1644c6d0f1171c1afb6c5326a3111cfaca6");
            result.Add("en-GB", "e9f1892f08cf2d1fa73db6fd38eaf60cd758f10e637ac9e1a33de9a2766d951d641380a47bc6192ef37116b169567b0ee1406d584be6977034a8fdefd8f4e529");
            result.Add("en-US", "4130f21c22dac62d21a3758fa5cbc336508a0885659e15b58cbba3cfd1ea86ec540cca062535b031c07b0878c4dd2880fd078441e58b77bee604d35baad6396d");
            result.Add("es-AR", "b356cf2d09c6c8f9e2aa75b70d47075fd03c1b1b307837522ddc02e6e1eaad20334a696383e43c787fa1f3c4577e3e50faeb5f42fca6e8be73114e627c02477e");
            result.Add("es-ES", "905d8324cdccb27b22820ad700be285295bb80c479d684b854f82cafb549c1ef8c921724bb42618c624df95d04d25526b09378d8c1f57b7259e00ec9ce5b3fcd");
            result.Add("et", "5837844fdb308884467819967a25453589d8c0e879c034a243ce0f203ca7d1fd199be96becb0eac95854bde34edb61ee2c5af031c48bdc156de61e8ee704a35b");
            result.Add("eu", "b9583fa67e99b5df714d300487dc6dd337cab0468c2859f29ec50b9aace34679e26b575511902325e91cc2c4616bd80602d38be9228d458f4b0a2cd73725a397");
            result.Add("fi", "ad8e376ec6cb8c0455d5485ad8d6a1baccf70c78feaf1343f3934725b67e43fcc4d15ae58f0d36090da97f96df2dc6269994301851662699fe6f3fa31e895e1f");
            result.Add("fr", "fed6d52505b2359085cfe1f8d97d19ccbda5b777dd4a666cfed989e820eac00603a9cd4c00f5520848a5f14ab4641b42089e949ac18c69e3e235b1bd405901b5");
            result.Add("fy-NL", "a5eef98c49cd37d670e36ee85a6421270cd7a5ac95cdfb1370890fa704b6fce1c4da666c3116855386d842d95b7680cba01ee37ce76c13e45910c1df99501219");
            result.Add("ga-IE", "bc53aaf678b77ee87c04bd360891236d4f40d2e024db8d10caa092ccbc32924ca0fd9cb0043ed4755cb03dd74c89610fd5c0ac78e94f1b3026caeaa2514e3ae0");
            result.Add("gd", "3d8f819f5bd661b878f5802640d50025786eae60d2f244c51276602ef246aaeef82839fa808477f5bb501b6420826dc87b5d87de86103a6e05773b6c842be4b0");
            result.Add("gl", "488cb8756dc2590c9f098cf6e6c0d9775734caab9a805e91047e8b3c8d7372d0ad3396e635137609dea21e2a43408668e111a8e473c474334ced6e733ad6b1a6");
            result.Add("he", "77defb1211e7a9672253a1583a174aa52f582155d303603d8611587666b30654891ec7477d2512e20df7a316d8f3d6b735d0555b4f8ab2111488a20280d3e628");
            result.Add("hr", "7c4f17f4c9a5da1d36ae56b2caf2ae51d7012b6bf1966f271a8bee450c20917640f67640de55c4c1aa0012f8137c67f6a75cd41c4955c8a2c262770f48f301ab");
            result.Add("hsb", "3f96a2a34b42494057939641ec27fd8aa1d926c81238247a21cd5a33b21020d06676b89e93c11618be0b01a8f1ef517eb95a0bcc256d12f59b1b53c58d83f6c6");
            result.Add("hu", "82d24ea18bf9587e38e4a9497fdc39fed37026b9617ada042915f0ef46799e1f4dfe0cdbf1c8ec1e7c7d534b936814d0fedb587607feceaea87883b9ee19bdf2");
            result.Add("hy-AM", "2c17287ad5867d075ca7f62a77d2e2f0d9e748c2d14f01ec9f82f8147b20b1986e981163437830ffe844e2cb7b713332ec7eff6798ddab1650b53bc1c3711fd4");
            result.Add("id", "8f0f009af5c47a00c3e9f4119587b18096524ba09dbda80303056ae0dfae3b67fb53183c12a298db462391f80b29a492c510fdc5ae640ad4fee68bb9585069f1");
            result.Add("is", "0d68f3a6fb66e01b2717b7b1fdce0920055a3d44bc4e80dcbf41d61f0461f1203abae3c824858443011e15d18ccb3383696744fde51ed5c6c5a6fb2178e3741c");
            result.Add("it", "41556fce291925a78b2f7cd21a7339b9266714cf2d865b79d9b11ab6b5fe34ac0748346bcb165273f433a633878478f1bf805eb2baf7eca70d05562b6fba37d3");
            result.Add("ja", "6bcda87595af2d4f84e6571f1277a458ccdf9d43b06aa3695807da714acec5c39fcb88fece4b6afa8296f0510b7970ff60743d28d1ea8e08fa04dc7c5ccb316b");
            result.Add("ka", "26f232ef13f20b5ffb5ffb40bf09d46f6e5ee4c92f8a9fe9528adcbbda6c5c918c7f694532cd80cbe16ef995e7fb24ee551d29169629422671aa00997a5d3e71");
            result.Add("kab", "30c5a36701aa3b53ad73e2b3d1153b6c47d830f400e3b85d89214eb8a750e02812e2e43fd3dec8d771f51cc2c7b152065754a7907e766b3901ee7be0b2419605");
            result.Add("kk", "c0408a86b5a5cb2e18a95c3241f674fb4aa282d26797e3f73d366323b84b74ae9ea3f6ec503190c50e7f90f54f0c978a134777d5044c90deda92fb44fe5782a1");
            result.Add("ko", "f15bff7791df10533c0c443830185eeffca0005bbd945db8aababda6a0dfe8a8c5c896c0de49fbc754acdbdd6bd3c427c86d8a4623b0bbf0d428b241c5fd9c2d");
            result.Add("lt", "8e5a6b7facec6d111b4d833c99bb7fcfeb0f7c821c60f4bd76d121f5ea64eb50e0234477fd6be1b438da6af3bcad020b6c413b1f75472605045eb6c478633b05");
            result.Add("ms", "acfc893fb0c739435d85517710c6e56b443a6f222069e6434d1a062525c6096ed594f6a1d3ae9b4b49813dc356a0169b90c34f405f8233add2dab6f243ff0e8d");
            result.Add("nb-NO", "4543ac4171f4ace718f5fbbe1fde8496e5c7aecc66a70321d2b3ec3945b7ca7bd7dac05e0552e68d3c3cf7eb3cc849b0b5a9341550755f2fec1f409276591b93");
            result.Add("nl", "15a99619d07e24e0bf37d822f87fc43a518baf695546b21ff2d8461542c18d91435455e98340fbdae0c528106109844286fd5f034bb4a1dc50d36a7930708a9f");
            result.Add("nn-NO", "50afcd11eb6131cf2937409e354f8d9f725ec67ccb2cca49822affa75c0d205d222890e047003987e6d57849e3e8cf9739fcbbd9fb3d224a0c4f3e59d783e5e6");
            result.Add("pl", "a062b22eb2e6373204616cceaa41407dd013f407c83d70489ef2e1d22178b127df4975013452a22aabadb700420c2bf84033529ed4658587cbf69a15df81c0a4");
            result.Add("pt-BR", "5b7625e548ccf2bdace119245e72d1070c58f0e907d100792ff132ddbf30b745440383630a7f1f65bf545fb0600fb86053a8e6cea7c0eb345ebff691e5420737");
            result.Add("pt-PT", "e7045512ddd85322de6da7ef871d07af546bce036b002ee9da012add88b17fcd98f8025708b65400b5b93135e7c995f1d5ce0c736f715ed219384944fe789b8b");
            result.Add("rm", "9c54f5fe3575a09ad61d29ae08c11b8d811b50a4bc466ece67802f234d317731a35d04eaabdc38da942ab432750f5e02f1a57beaab2dc50a5838eccf1ee10815");
            result.Add("ro", "c1ac8749f5daf4e551c8622001bf008f07b45b717bc54a516bdc95ae53184d2a0278e4c110d3471477945a9b742cb151f8ca9c6a3ce393d7c0e662dbb06062f9");
            result.Add("ru", "3c2c0a8f3d3364cfc32e4bcfe01520248034305d0bbc14ae170f5af453de5eb3490490bce9c97b84b3479c8384c3e6e2be90ac2bdae369dc533e972cb0a62f17");
            result.Add("si", "55cd118ac89ae67f7ab551c0157146720f9867d3bb1b1cfacd7077cd9b2bbcc6693eed5f93fb9cdf2bc7051bcfa56a801f83625d87825c09a3fd8be2505bafd9");
            result.Add("sk", "74af1e5810a8fd31b3c694d0333201a48a6048c2547c266cd7a6093d3c0dcc0b8e96021e55be8028d6872173eb70ed27cdb11374e3082c3a8133785680152dde");
            result.Add("sl", "92a4f52a4b50c75c4fdf84dd4939946bd1d2fad5fc6dab7788e4486ae45eb1ad6098a6b46c653a72fada9343d29c8b0a64e5382c80801eb6ba873a528552105b");
            result.Add("sq", "42b065af6e7879ef40142d24b77cd81c51b38e8d2701a268c6e3f3b33bae846ec4f58e31c1b489b30daecc0c48cad10f7be35fc2f0d3cdee4fa4c5358b5b91fe");
            result.Add("sr", "d5bd214ce813b557998dbadfacbe8d190bb9be646e366dffda37fccdb6b3171bd0b42b12196af8d4dd01b0d69f2fe6b5aa473a77d15981e28b9da4e7bf2711cc");
            result.Add("sv-SE", "0edcefe83eb6b6c3f53b2a253823dfafac51f2322183532e99eab063374fc6bd6e2328622a8eabc1ac3e3ca474c80b2ef23e66498f1afd8cb6553e699eff3501");
            result.Add("tr", "037a6b59fac0105ff355c6e28b32709754374fde15541af2d5286b62a4b1b9da60b69eb3865862c6a52e8f4a6a3245f88bcd1d41926454d9b58741f2fe8990e1");
            result.Add("uk", "d952c465a2c937a2c505fba74b731c5de9a78606c6c18298d4e78f8017b4d6720c831fc07a3acc0987609be09b1d327f41c128a5f80331e16d1d0ab5a307f19c");
            result.Add("uz", "a8cd376f93ce260218383b19702df2df251a16af777bd7a49bc6ffcac0f3e3bcdb7489c08e5ddb0b2f4812fc13b5b8aac32896634e6ac85c0665fdb1cecdd978");
            result.Add("vi", "b9537c02dcf16b1c3c31ec88c2389de652c6b176cb0918062b5f613799cdf38286ff199f486d0d3f6cf67ae4493d69b8435c06ad0f7f5e3f0eae99df9881d24d");
            result.Add("zh-CN", "350539a24f6100db84b4e660370b3151ea63037b53e2c550779fd81b6eadad0929a338f4d987e25789fb5a47c9160dd0a7c231003915fbbaeea165bf7f067ab3");
            result.Add("zh-TW", "024dcd19ea8f817f6776e05fc1b3247f3146d4c581ed2213c58282079f1804140d882089aa226c6fe593c60fbbac75fbcbf01ef37e2369bac72ab5870e804c9f");

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
            const string version = "68.3.0";
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
