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
            // https://ftp.mozilla.org/pub/thunderbird/releases/52.2.0/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ar", "5e30653d0a6929c0a6ac583235feeebf0da3d4215eb617da79cb90ce8d694dec9687f975f9996628ad6128931ba05396cd6a2d9bdfeaa5554d843af1b91a974c");
            result.Add("ast", "7621c4dc0ca7484095f8627f1c83435930bf69b5aa970088868cbe703b61c43706350534dc2237a4ff93ddcf466c82816712e32be96978733cfcd4981f9b8f43");
            result.Add("be", "ec9d8f49103fe7055c90abd99fd19a28ae18f31c0d65a6d8e50b62febd5fb6935cf39e05c7ed91d8c55ed86ec5c3d06b6cdb24da8196eaa34797b93813514baa");
            result.Add("bg", "cd55b0795cb63db862490656ff87a2240c96460d29e7c032d1a67a65ab4a841272b3f14247e3adbea17867dd264476e61f8b838ae517dbef7542bad960cee574");
            result.Add("bn-BD", "b2d800299d863217ecfa5175095f786d69925ab22fff0d0d770a65ccc386e57c4f8a106e6223d3ac3921b9e878451c6456acdaa3659915e004d429c9a1ee194a");
            result.Add("br", "6f6454bb9319bdaae62e61408dcf2781bda3fb8589a9446ffb42a2db526c5457cb22522488da81e2e467c0114efae1d50629f6a67cd368e7bc3fe1bed428b63e");
            result.Add("ca", "1b1ad45ac71283e8bee5ba4bda5073ca4dd796eb5f47afce63874a672a550bbce7091fca59c13cea15718d074cec7bc2abfb79317d93c6b1b0b28d88c29642c9");
            result.Add("cs", "c9f965afaec95b0c12e987ccb00e4e8805d8647cda20d55e9727f6c876f1879cca42f17a3a3d40be6070509654e584657a179c1503cd3cbc6c64eec95d022cac");
            result.Add("cy", "edc47be70dab2aa60df5e5f43ddf66eabdaee77ad737a3b9fa16fafc3024ef9f3c90379a5c5ff6513d572d4b87cd5623e643296d62b57f37b39361344cf5762d");
            result.Add("da", "8ce180fde8ce8ffef116a67d78768702c41b3d695d970ac2619e29c29035ff7bf6fba08d711af831f269b0750057612a3ed3f23d9ed91c8c531a8a4400d29b92");
            result.Add("de", "a7180a1a457826e7253fba8aaefaac5e9959a064e93801e20c8082195c34873347bf5647a8242f9573ab2cff02491ead5ffea9b2c2ea929be82a558ec387907a");
            result.Add("dsb", "1a36d037e4571145a11d714f0d6bc16c0eca2dc168093e518936978b31e318952d55dd5ee89aa5e611eff575faadef2ddd558acc9de9732de39d8fdc1441299e");
            result.Add("el", "c894df9951e36b08eb3b07a3f64674ad21da4f94d94d0b996d6e13e9d0dc0a4ede23f78d7ff09c20ed82a05f52e8dd7a9312d0f7d5452aa81bbf8d812114ad12");
            result.Add("en-GB", "97bd053b5e34d98dbd533ab12e2b85569f66f6b6ed6d188c243c08189fa2508c03e935697de369705a29d10d970683a2425a973e80d1711694358758134c50fc");
            result.Add("en-US", "79b73bbf21c8e11932f570c65058842f3f530a6c7c7dc40ef0a0ecfc9dc44e23883095f0a61de596d9aaf630b3718d34b6a7b1005c12a2268c7f66562b58c5e2");
            result.Add("es-AR", "6268d830800f0be79cc3583c39ace12b9f8f6308604409256a80b708e6163f93e4e323ed4bb09b0a661cdc7e75fa2dade87cfbfc8dcdefa9e5090178b2b9b93b");
            result.Add("es-ES", "1413a525a240c843081e6039c73d571c6e73786172877c902fa7e842205267a7f43da4dcb8a3f11f5cfce0c9460a64ff70e5160a876d1fd73c4b2ea9aaa02209");
            result.Add("et", "09c2ece9e0f464572bf573dd8646f96bbb237f2861d2bb74b2ab2502ecf76a98566e30e3d492f7a7da841ae93bcb0be36d6dbc4195589fad6c74ca5990940139");
            result.Add("eu", "75b05012cc793d162975cdeedeed747bca56fdc620cf499cf87f53047d0ec55f30553cd32044017ff192179c1c6dab23297f7afd2a1234cd6599b451fc2abf03");
            result.Add("fi", "99ff8cfb2d811577b5e337e86af6ac1f032267884a819a231ed02c572a9ef01c39cb1512dbd51ee517187e6c7863477c7467f8da0fb32cac174cf2d7794b7ef4");
            result.Add("fr", "5ffc7d89b942e678034dce16a3f8733915104edf12a9a19a46cb03de79c0e7acca451f6c6a2e3d0ba7279d4ffa9043800dceb48d546909391bc53cc2064875d9");
            result.Add("fy-NL", "9f3d4da8a656f43cbc4e78ba3787f5fd5831ef2f5ae7844a4e6eb6a424cb75bd911eb9ffc2e404ce5ab3689fab5187479f046cee7bed2477b1b915703a75a6c2");
            result.Add("ga-IE", "5dbfc249a5321485c3b84b5fe424ab37c9bb031f7c750892f7b4e914d3cda54c6587b97ea36cbeed6e2cb701049531026ddd518846c4c8dea0a5b595175ee266");
            result.Add("gd", "9f6d993dc9533e32174840eb48feb4f4d1cbb8b2fc8517ca8b7f65661302ebbbbb316a90932ed4ba76ff3e468ef3d33192bfed47df67d6edeeaf19d61244fada");
            result.Add("gl", "68e757fce1af997cb5b32e1aa193992b19fda0c29f330c03bf68fc1e43de637d85123050e8f652ee64ed219c67efd3bd45b3d5e55c0509ff3bfb17977b3df286");
            result.Add("he", "5e0307ade54a41b290c46fa4c98521205ebbeb9bc0487d45d3d97f4fa5bf87ae414d154bbed802679fdaf61e8d5673ac72f332c8f6c9f4b9ab12ad869a56cfea");
            result.Add("hr", "c37e5e66cf757a07528cf4cc7c72d6be4743b5f3f41fde5357392b874bc1eb2b8bece8422a3f583095ab96218be9087624e7abb7703a4d188dc8853e52bb7d6d");
            result.Add("hsb", "7c3c4ba00828272177f0f5e74a316aadc540eb65f05ed06026e970a0f8862997d02133ae0a4c99306de5f1428a70e2808db6a6cc364ce160ee32213020938e3b");
            result.Add("hu", "2010e1b3a94ca5cd0e04357bc7f46810f993150990cd5614c01f71b639d491619282f42047e61212ecafb0be6a5e04446cd93159e38c1719aa804dcf8b97807c");
            result.Add("hy-AM", "878081d5517e2f2079fbc48ddd76414695cbf4a8d56f08480300d57b36375b9de6c0749ddb67f3c396e1606ab9b45fa23facd0aece0dc37b04751fb1baf50105");
            result.Add("id", "c2b7ef791e97ce2b317e10f11dcd17a98fd737b10ba4e4e00b6b782bcda98d9b87e3be53a1c8f9abd2d2fc0d5410a88525090be418481387d095b7a9c9668e4e");
            result.Add("is", "3f19356387e7886d2166fcd7e506175a36256d029fffff05f7be003dd309ee5c86ad1bb5291f73d42d354f592c7afc428b4d1139c2bfdd5f44490607874bddcd");
            result.Add("it", "4115dd0adb98a7b0e56f04ef220b6afd5e545cd4a7c60792fd404a269d3bc6593c922c5573ee1957db4a6b870d93aae87da3f8579ef0b801929bf6a18fbb55b2");
            result.Add("ja", "ba4600da8a1f174af8b3f6e68ef2695e69cf091ec81bfd0889d7a13481d1aa48c0b6eecaeba41edfe7dcb11937bda2b6ff25b8e256afa28f926cc5410c651b4c");
            result.Add("kab", "a9fbc8ff19dacf62371592d142e5c24e19e243a95fd73a227c933afe1a3bba922c31afeb9b4a4e037a75383273ce29719ccd0a394c768ec4b095f0aacefc5628");
            result.Add("ko", "3172c16ad90353ad781ee7059500bde4ee35ca4021ad2bbe7cc8a7b6ca6dd33dff9404f412fdb2e3efdfafa04eb78787c354f5c982a3e49949ddff695898cecd");
            result.Add("lt", "bc2e8612dc08773faddb5a098ddfc385189a97ac23d02272d1a79ee78697acf5b2a96de2f9b690b29c87630aa7042f222d41e52b04b701f79a3d8d02fb2f2b6d");
            result.Add("nb-NO", "22fe64b9ef1d03fcc7993a2583e6f1bc0883829ecb09b1d832e0dc4c3ed2ff2b0624e2eeb7e3719c443dc6b25619af402744f0a02d0bd36de25d0a9993912aa4");
            result.Add("nl", "48239f73cfb4ef4ac0e7beb3b07092fa30a1dabe67c35f8c8a4e9ed81cb1ac5c53c40574d9272b4eeb983fe03ff1f74757296368d62fa9201ac6d0cba3c681c2");
            result.Add("nn-NO", "c34f4877e04405d0bfb7774b0a2fad048e69777cd31d1d30c684983ec269220011858132f0562931c313957b21203eb4d3b82e64be5ec2098e6cf285e5b957e3");
            result.Add("pa-IN", "1f60ad5a1f47400b97b05090c75798b49b784d0ab2db86cbfa0b3c52b07dd13c846102aec67237523c52104ac43ce7a84b3d893faffbc6aa5df190dad9dd9a07");
            result.Add("pl", "f3e97896c0d88cc70585397aac4155553691bbed5fbaba32da459bd9b2b38318ac884a3ed6d0ae7d5586a6f0706d109cb8a01c5157838ecfc6584a2e9c189532");
            result.Add("pt-BR", "8dcd2e3cd32cd6e3b31531208189239c6c4b2f31d988c1fc990232a32048fd9db0904f49463b7d2a7e99548f0d97b0d068ff69a73f2842e564600bf31369437c");
            result.Add("pt-PT", "ab3a89ca820082c18380595e38bf36e2415e0c69ca29715cd4f1bab6e976a1313836253e5b4a9e1de2e68d5fb9b1a3e29c5f7eb122e561b3c99fe954ac194d64");
            result.Add("rm", "63dea21ada8218be8ee36dc9735a3c9ffaa1b94a0cfec74dc861a6690a6282c7a0f5cecd3365d62c90c1e2f1b9487cb759e10b007a6008a8d5ac413d205017d6");
            result.Add("ro", "2fc1afb7ab444ccbccdf4f7980e2ef1cd59881bf55901ec3785c3f5b43d53ffeda94d120b78233ff76b1ba00ea634d1793b8faad82293da85e8259098252c92a");
            result.Add("ru", "10a8880ba14c152592dc95bfa6cb05a50851ee1a2d61730aa22d9d9767d31be55938e2ec6fc6cbf085cd7cc94f6866b1a7e795456a8b3736e4f32c135e73cbac");
            result.Add("si", "edbcbaa8900fc958030d59477dbe8285902957c19a68feb0cc10a882425555e3972f4995f3f06fc3d5412eb2220ffea2de3ba93eba7a5b126c565d4186329573");
            result.Add("sk", "055fe7b621614003db6b35560a63f340ab0f8f6ab08c89f314b46610e7e5be9686c8c0fe34be69b947c88a4c17bca98214c8a19f16202158d91df15eacdf2633");
            result.Add("sl", "e1d74bf699e241dd2a40f987b59a5b4bcd2f76589c04fc76e2dcc875d875ab561fdb510d624620f4c6e1d24658d02c85bd37115135d0e48687b0869a13cecfb8");
            result.Add("sq", "7c3a0878c326e85df51afcf88affb6d6c1a674fe2d0655f8bcd9d8fbcee39ca6194b25fdf5431ec43f33e7a5e2907eb62356b17bfce50f04064e9ed057769c1e");
            result.Add("sr", "3621a4cde0ae1b70e2c3946670412f4fa7a4d2265d0a696ec0c4e420f6132b5e60162d2d170ec66b4ed22538c5cc8b6750ab56ca140b6a88a528346e4bea5773");
            result.Add("sv-SE", "0ddc5eb29d2a34870f09f2f92bca00f61cbe66b56fe743b91166191f75521790d79f9396228818c04f4015b90b46303d20b769ac804c6b7e80bbd28a3ed6f868");
            result.Add("ta-LK", "1fec25d92dbd8545eb23c1c000fb91f0261836b2125abba6a96b924e80ac993bf906b220d312ade67f62ada33ac53d99bb5049e97ed98c8a5144e07d52ae9f95");
            result.Add("tr", "5225c4ac2873d5e901da313cf0b761012d5a81876d830ee6f6c48c5e5be3a369dd1f0e8dae2b46cc7ebdcdc494d0ebf09ece05fa72cba0376d58e72a38c7929a");
            result.Add("uk", "b60044f960650fcb10494a4db78d13911a9c77f87fba9311c655392b646aedd48e1ac6541eae32d7c7db29e43b2ea3f4842f523c9978c2f8dd03770f81556fea");
            result.Add("vi", "38a4c79f8f91418c2571977a106354f9b80bbb7e47cfad3197e496821678a61bb8ab5d45608b01cbaded94c9b613b1e07232bc84f4b59239eedcd7be7b2fe025");
            result.Add("zh-CN", "2ba1978d3612e05a68a627cdb51b42f2bf70e1ab843db69f1a449098caf4677d05fa64099c8ef476d293315932aeee8b96a0ee33c1b6d70abfe2110b20c66bdf");
            result.Add("zh-TW", "8bed02740283aba836caeb9c7d7c4582de71eb373be71bbb620ec28a4e7a00ad0699823daac017df0a2a2a89ea78982596d0516be56b1e3eef4837b88e167f54");

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
                "52.2.0",
                "^Mozilla Thunderbird [0-9]{2}\\.[0-9]\\.[0-9] \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                null,
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/52.2.0/win32/" + languageCode + "/Thunderbird%20Setup%2052.2.0.exe",
                    HashAlgorithm.SHA512,
                    checksum,
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
