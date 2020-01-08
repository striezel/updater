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
            // https://ftp.mozilla.org/pub/thunderbird/releases/68.3.1/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ar", "6d472184ef1e1d2b103059d05df88ff0bbb2e7c100115dc2f8ef199ecb41691f93c1b813fb0bfd72b1ac706100de930a8c2875a93b009f581056b9d3824d43f7");
            result.Add("ast", "2857e6fee98b446a281ed1e50f562bcdaaea48a4222d271b10c3f8febcc753ba7963cc2fa48b43d0c300dc255b28f6bf178e34e92f15ae64806dc306dd43a9d2");
            result.Add("be", "0b5a1a3fccc93af29f3ff693a501e1a344216775f90d4e8939910f844acb6d372cda0a48907742636f876e1dc7516bb254478218d512ed7d577724020cbfb615");
            result.Add("bg", "d50598dd919e98c68de4d65f0b5ac3c78b284fdd8b7c4d8740dd4a4c683e05748063533b8f7be8cbe21d866bb546c8da2186e714ab35f1b2cd3d9edd3e133272");
            result.Add("br", "e43258b7ff483bf74cdd8bb46421d044773041cc3a2ee1376bfc11c84747a9ac2d820d50443d8db25e882ebaaa2547a37baf33fdc20b7b7c1c637c01dd241494");
            result.Add("ca", "bb1898f2e4c5e47cca467dd9874ccba066bb1989b747335c0c01431f1993d01e7327c58e14333367eaeafb224b596f312d87ecba3c92887a8ef5dea118f8a54b");
            result.Add("cak", "676c25999ce3278a20a1167a8c1f2b3bcf57733e88a0a4299d08253dce5057bee019c246931df4497f7277f24547662d2dfb3500d7454f33604bd16a2168cf29");
            result.Add("cs", "f8ed353a08e58cd4288ac301d5809cd94eb4caedbb2d0025dc24271b87bbf921093b7c789218497f46e1ac8c16bf8bf16f22599b2886ac8b6175047ea9977fef");
            result.Add("cy", "7e7aa9a65a911d214c8e0b751093dd5c153d39710e5c2c108fb8c5f37e94df4bd37ae51e79bac13dc1e0f14d72db999df4c54562985167c112532f0a1b8a2c19");
            result.Add("da", "2ecbacadaf51fedd0b0d22d5bda94e6d5b3edd6ded688748558768a22f69944a2ba7be3298afe2f3c4bf7be4d860c5b9fc382d718193d38e8b9a8710afb364ab");
            result.Add("de", "1611800417a18da22f411644158ca667bc71a4b045ff6bcefe9f72c0f5ce02e4cf8c60e9f541cd6d8cff6074ec9c1f68f65b25ef07d6a3f0d269302e12b2d2fd");
            result.Add("dsb", "557476f813780829c4a10fae2526d71be002b6168bd561de9b91edc4c38d427c24bb6875283662a453f2b6b46463abb8fe51b5e6371115131df2ae86e91014d4");
            result.Add("el", "f18d2aa3f27675d969422b619013d54dfc1d03deb6280192677bef4d5816592de0ebc10654c52c0f7bbc687853556518afe533a416692ae7e8ae5194a8453c49");
            result.Add("en-GB", "780287fc7bdcb0fb7c525ea17e835873dbd659367cb55d68025fdd64d8cc7f4ab12ec919b84f3105a54fea69e504ae54461245a9fae58314c5647abcf9de19d7");
            result.Add("en-US", "4f53401f4ffca9630f35e9f8b71c3c51b8006bd740f4709cfd4a15d075aee92025e74a1fa7187e493a67623aa4f45b2c55559d036502c869a8cd2c31261b33fb");
            result.Add("es-AR", "55a383dd3c5d63bd2bdb118477e3821dc70e0fa11cb8a3c05a3625193a5688653f61d628183d019dbb5552c963c4e06677b6710ac9d228098f28fb7b59110282");
            result.Add("es-ES", "a888010b97ff26c457ea7cf0df82d1bc616ba50e99fb09df3d20c67706c32ff6780d1410ac4bf497d8ac4f986dcd118d53baed2dcac3f0261f916d0e9eec9530");
            result.Add("et", "854b2946af0da1d52004ce44474a036998a9f17ced4ea555a5c294fbb54fa42e50514474343c60fa4c9d61b02fe7d0a92658ede521d77d6ad761f1589008202d");
            result.Add("eu", "485738ffa14610830f43f9acd9def3e6dee677fa0d30ae7b19f8381e3ccca75b4330c1d713bb814eaf084804c11a927db9775aaae86d26d5be449c93664d0416");
            result.Add("fi", "40d21f61f1e68cb0936525a17f0f23c6e543a7a757547afba9d34995152f818c430a28cbac08f19333e4af9efa023d4620e9e71ea2ec2b4ceca3fb0dc5ae0ba0");
            result.Add("fr", "53cb12fd2492373a09a13304e6262f6b84b537d1ef4f0e7d683d0bbbe2f354c1b4d0aa7304015c6c0e07b02cb940f819d7cf72e345b3525bf234971cff9e1465");
            result.Add("fy-NL", "0108a979d7bd94f0e3df7ae844d26fdbdfa3df5abc510dcf58a76c1d8e7a61f4d996a2d564e838fff8833594cb48d23812cc2b0af1b65ab51dcf4cf946193f4a");
            result.Add("ga-IE", "f7458c991bbe294101611badbc1540bbb92cd7401874a90cfa280f80460b6f58c81a768023a3591bece96fedeab8fe10963122860a3923d60739a233fab33ca2");
            result.Add("gd", "2b1268642527fed8b3a403db32de1d3daf092007522c8d60c2cf3dc7be405492a6a8e9528bba27ab7aa9ce89074404782abb66d962909e8cc114503f4aa99a7c");
            result.Add("gl", "cefc44df57a9f706d8a4d219d7761d2a70b76dacb055bd4c1d4fc832141a02f42293afb16fb4f9380f141831a965f6d34524d522827c69967beff51270eb451c");
            result.Add("he", "b8275c01c6ee1bfe091352d24f4b7ecb7d82d791af4fbd73dba3e177c4c6deab7251c3c10a97fa484d68a60d7a10c4749d58d75d90de750cb957f7e550a41dc9");
            result.Add("hr", "60075bfa84702eee84c9345e0883ce4d4620fab0cf479b11c01839b29c3d98de5da47b967ca741ea945f2710d98e63a2b80bd4a89aa95746b08bf79b4f5cbf00");
            result.Add("hsb", "979580a977f24467b31f444ac446eae83b02a7fd04a5f87010c092a3542e848f52bda88d06c422f50ea1ba6b0955960779160963d5584de1f15250210db60704");
            result.Add("hu", "1d3ce5260b9b540923d877103f1077c06bbed9e52a52d501a6291dbadd9044974b8ed7b29d22de7f4b7696e70a209ee2844ffbdc753824d682fc6629517056a9");
            result.Add("hy-AM", "01509e9641b56dbe68a8ff6bae672bcd38678d8980ce9487a9c91f1781bcca5b0f9aebbe75ef61e17d77bb2b2f5da7cd2c42115d8ce0b7e50a5b938ffb952415");
            result.Add("id", "4f01a83555e3041a46a604713d6eddc2b78a607672f1a080e9641d6a98c52b6c1764fcf4df9ed4a67c80ae377039d96413fbc533a67efc96f34d74cb40a0926c");
            result.Add("is", "ad8f8e00ce0578f28e7efa0cd69f39ad51b080bbc34efa39513bc1a68e036bfe475a9fa4c908073f2b5d4846069d81b2e833ac8cd113fee253145704792b8ba9");
            result.Add("it", "b54e6c3dd4a472fc80560e868628d6c6ed0ff4da9fd9bcc450bc74a550c9b88634ca293033d746f334c95881715272be8dc4ddbe0d4e8e3414df15899db4a90a");
            result.Add("ja", "00401789d2d089c691f5fd3a54f959bb6e076fb3db25fa891671368ba4721d89aa4c13cfdc8c97cf571dc3269515578c7587e774730e8d994c2b3badc0aa5dff");
            result.Add("ka", "6af8baf787d04d04395d81dd4fc741c8b546adcd539a156155eb3cffc1e749b4687f3c2d197e94a7ba610845ca9aef2c704e0a69ab94b0643de788d9d3636247");
            result.Add("kab", "1fa179467dcdbaa9923172db39cade35b5d69bb1ca85c9d5a254fcde0341d40a71d5616c5db53280047501eafba1d46d3cac0554bda7306633be78f831633277");
            result.Add("kk", "c1823052a0aa4d32ba3a057a4139b68769d75be7c6bfe91fe47452ced015e5f109e225fc0d32cf4bad28a8bd100f6805aafa81d944d95729068e3cc832bb1db6");
            result.Add("ko", "674e38c2a29faaa489a6b7804e9d55c5a4ff1d3496e1683ab850563726759caa2a64276360ee68f8ff9e6754c5b6c92558c8a7cc0120c292b6232e0a27066826");
            result.Add("lt", "ec45a89c16756f07b823a4b0c036813e4c016eb5c3d320082325ed272fe2f3ec485c4d51ebfb282403b3bfb0f604a3322c98b8d49b68b03fe56eb13137beaea5");
            result.Add("ms", "5d540237b0494d3c776bf22d928cd064f7211b495c63a306806b99dc86984c96122efa0cb03c23cac558b7cd5b4a48dac51f25f1755bde346addba9ca934cdcd");
            result.Add("nb-NO", "96839a69bc76ff7c5fd7c2c5b6c0e5d7c8e5d02e3f2f2efd958e149459576c79167b423011cc519404d79f97707fb5d55e49c9e705449b63804e67fc5eb47612");
            result.Add("nl", "8f8e71eba9ddb49120c4d85e61c3c77cfd7cbd37648198aeb5b3e6fc41b5b6b70c8c0f20cf92d45d68ba4951e5508cdaff2277c359a332d95a4995252a0ba6e5");
            result.Add("nn-NO", "06f36a769de12a679ac7fd360b4c91f7e5e1471df71df4c3f1afae201f6428feca25b4fc813eea756fa77790832405521afe817fb2914bf1b76123eebcfbdb8f");
            result.Add("pl", "7f66c8ea473423c9d3d1215c604de54c7fa37fa69255a7ad3d95b9ae1b26fc4498cae910dba91abe18ba3db2c4a8b69c82f703d9a005d6f3f7ce365dd8a02eae");
            result.Add("pt-BR", "a666859298f075dda3a7dbe24bdb40fb370167809fa2646b7f9e7eda1ead0557df33f414fe0becf548824ec1c588f068dae994235f121153e5b09fef6781e1fe");
            result.Add("pt-PT", "7918694f379e46e41203233ab6c6920d900db990a07fc189b6575e96ca5b3631d8ff4e9936e301757636c30592dfffe38725adec2c78801023fda01681579d5c");
            result.Add("rm", "c98eee3ddbbbb3414d79cd5e0c10459bdb30e26602ace63fe20772743f9c8e94079fec6af7a1391869ee49d1bf82304c44ff2b27da977032a75ac2f870b42e09");
            result.Add("ro", "60c2100f21a5feaea8eeaa1248c02c3b2780d63d922e4679879e4f08f0604c2eb1e0185750eb7680696ff885a4b49fe62367d515ecd9633fee51fdd408a73cac");
            result.Add("ru", "854829aaa0f6d3cd4ae1a2c7d6974f0656e81f0f9b196ab7cd6b635e851044c23f720e171f37bcca986eb17028db151ccaafb3d2a45421d906ba02b376ee7c27");
            result.Add("si", "5bbcc2cc2e4cdcc00b720373cee170630e9b86d6a49f30ee45b1cbbc7f2eeb13ddc03c1beb5736fef5829a936eb6d4d6c351de4906d11dd9fd72de89de6c08d2");
            result.Add("sk", "1206488879793010117996b508d9017783813bfc81a417b5c76bdf969859304b6ccca72b060d17b6053ef3b3a6f642c552fb025ee73d09cca73a2550f8752c5a");
            result.Add("sl", "1364df5ce6aa2a1035689d00921dc6b3a4076cb83d51179dc952647c457cede9219dc8e9fc757f88532e7678c31d4b1ebda7ccde8376364047c72868a6237e81");
            result.Add("sq", "050cf81094a6166fd8c0dfb1d80a880b5d64dac10c1eb79e6ea612ce7dc12842435dd80af0234121b865da6a160a2d04f76bbcb527f0f72399bdd1d05c73f3b9");
            result.Add("sr", "e3905d34e69fe3753bb230c3918551f23fa3c73eb58c665fb326a0eacc9c83ea9539564d1215942ef523f2babed21e2c08476fb62da85a2b21c2dc90ab3c2e83");
            result.Add("sv-SE", "30649011bc058aa51675ca39c3a85dcc0b439509ce72982fbfb258979f9e52280a813e40b46fafcbda1a7cefc7a95256c3fb1077119a5d6deac02e11347f6752");
            result.Add("tr", "90816bdc4eae2f17d6394d3f73f85202db49e22d20f0909024033629a195a7ca6be76530ccc5460fbcac8e95088a229b4b033d202809d31cc6855134c1e47041");
            result.Add("uk", "528410d8c5149d018b7266ee1da308a7d5e9604b0a92d6e8e69ea313fe5a72c178b73530805b1865d2190209c9a1e171538df7d77ca895b0b682db896442875f");
            result.Add("uz", "b4e17ffa9f59e6b13d4325554dff95925e077ab8ac96b3161e89d307577904489fedcc1227ca55583f695acf06f238062fcaa719bc0cf24354330423c122be33");
            result.Add("vi", "4ff1fae0448b820c4957c8e48ef8bb104dcf1335dd04b40fb5e4bc2a58ee57687e57c68901481e233d95e3bfd15338945c61e758eb8e5d68c54c10c95dd7ef43");
            result.Add("zh-CN", "4aaba87ccd8559d25d392dffaae939e0c96ad49c3c965a2d75b6332758d368369d6fb68d8d6cd82336eb2370f6794adccc5e7435f3e798df46c225427dcdca3c");
            result.Add("zh-TW", "ff5bcfa300ad607c7a88bbce107deeb04ebcdb3de1b86dd7a7d922fbc1e9c63f65aa65659908e600b89421dd34838704a2b5e443e203f50ffaeca940aec0b2ed");

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
            const string version = "68.3.1";
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
