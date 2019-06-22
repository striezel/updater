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
            // https://ftp.mozilla.org/pub/thunderbird/releases/60.7.2/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ar", "e182527803459f6bac64ca13e321ffc82b545822036aa62f21fa122a35b3f158eb99778e8b0986110baf67a48546494bd3eae1a4b3c1c7b3b05b8d0a3d58b34c");
            result.Add("ast", "2ce725e827ae841770c879090b47efa285851e288ac4af3e72375533e06e730ea1b4e1380198f2cb07fd6b1d3bacd325405afdc830e033abd6e3589c89e7cc06");
            result.Add("be", "6c853ada07e6075c06a7bfd7569a7b3093c803c4dd55270daf9862a17f10ceed4d912a38e926a64124248a9e27e5c0a2803df45e571b78341dd4a74ed2caa3f7");
            result.Add("bg", "ad22768acaed1e82b61c5911f014e2b9e47cb92e4acfbf83d4874dd3eeaf1e275f4cda8670504381cef9f26ab13868dba7dc82433e33432f01b6e9de05d4f71e");
            result.Add("br", "9429201c91abd2939048a4a9eda4aeb3f512ca99c7d0fec9e16d05ea9002b0680fa38dcc8beaca8804b761c0d7d3cd999927be09228df957c3bfc9346c8e233d");
            result.Add("ca", "691d09d0377ce8f25dfe4e508b60f94db264c6cd02a505f6f33aa2b1666fe1d309e28a7cbed56de45943394714f17e1203501e5c628536637f7069b44d23ea3d");
            result.Add("cs", "a4f86ee4ab8591681dabdb6a618314a9798d0f3c70174b27c4ea2c222f37fa52adbd8816bd3c1736bd3749ae8a49be2d39d3991b64065ceb9570f2e585fdf483");
            result.Add("cy", "42ad06a02a3149c5b21533b39ca27ed606bbe42e0ea98e66dbeb111623f09bd1b1953d4ff8caa803553e1bb5e08569659f03ec262fe93bf0bfecee17990e1a64");
            result.Add("da", "fa74f7011365d0c05e1d731c92c6315e446d890bf35b817d497dc00bc32db3e05785ea1c1b8dcc626139b166f9d356b8f6ebe601bf15bb73586f9db7d682a782");
            result.Add("de", "aacd389d4b1a882ccbc2e2cc0c85b2866db3ccbcaea69ff7bda896b3ddcdea26fa8b8bc9c7f074e2c92fd009c941f747e0a09701fb5ba7a4c1293b07865997de");
            result.Add("dsb", "2712a3239213b2170bb38cee3650c50dd501296ca28e7a32953bc62286d31c845d766e2a420336a9d744ddb6ad3db786f00de7da71aa591156443cf5d0cd5519");
            result.Add("el", "40b8e5300a18999837a4cb2d521a01feee152d76b8aa4a305e308aa981d2e46869e776f0e29166e41a543ce04826fe830054daf2089c8c2c9cd704bcfde51093");
            result.Add("en-GB", "a00c8fb9c55fd70b76dfeef55dce92110f4e1ec8118765857f43ab3bd5a4f933f9de36fbbb6e2a9d2998ff50398446e9a8c70ae16314f6a9a23b42876c533d4b");
            result.Add("en-US", "3204edf72366a9f46c2eb0cbe456d940a11a49dadc5f728b525f82e1b2d20b4b83ba5f8ff764403b77f1095e072cc695d4996edc72d5b233626cfecc2edbd6ed");
            result.Add("es-AR", "b81ee34e5a344b754d90c62da7175ae0c0fcb8e106d9c875750366f97690694bde5301f77c21c90c531ee06b1b4f9184ebdcd7aa500bc3354a70affe1ba4572b");
            result.Add("es-ES", "bbc572a590e43f48bed275279047308d9e43e31554468a3159a1b494389e1cbe2d8d0f0f832978978c48379872cd24cb8b6b3da505ec2155753574fef5451f26");
            result.Add("et", "322ef2fb50563515e45c3a81996cc27f9653035379ec8f699d84ca95e45a2647e4b0e0c2da443485f67465199623458ae2b116397f7d2d81f70b24d6dda56977");
            result.Add("eu", "0b4881e2066e523077a878156e5bc4199b776a44b02cd24f1740c3c3eaf8d36e46b5e79f342bce4dcc9414dc25674531366ce6831046c11f4d9ff30df5dde5da");
            result.Add("fi", "ed7b7db83c9b6869f3d8c024bd9f20126fbf9ac85ddf5bb98445d690e92df71fe9e65302726267b49f85662d1b1e54caffb6f4d3f1782ed0192b3da448bdcbb6");
            result.Add("fr", "8cb8561dff7680dcc55630300d16c378f6bdc98731791cc66396ed1e687696b96b2a0ea8161f5646456b13d4e0033d9518811bc7b5efa8642c07f10cf312a5d4");
            result.Add("fy-NL", "c9322659ad5823602a76a3b98e9a2d9768adeb29c17d26cb3349415d348067f82bffe92a3645d191a9f3b261e81fcc2b22b9097c0dc18d4c060d7d43d752819b");
            result.Add("ga-IE", "ac29b6fb31a8a652ed014f7831c2fa98fa174b912a35d09d50af83142448e32a224aeef47302cb6a8ae892043b6eac0346b696878826613b153154c5b0cde7b2");
            result.Add("gd", "f94881ada14b739e2136df3a9aebe7abdfbf0dba76f511c3026f227a531ec1fd35f72b07cf6ee7b8a3a7ccd3b4d4fb23270fba0e063d27c63b1ae8b0ac7ae50e");
            result.Add("gl", "5e18e1915e1ad6187cf1e4e8c09f61f441e9e7beb22b98ace8a4af247721949a5abeeefcd2537be36cba1676f6fbc899e0d31d4736a40cb4e63976330fe1d6c5");
            result.Add("he", "bdfb977bd657576059d8f15c2252c8675d0f41c4012eb296caa3413c0ed873f3ea52d187aa256877e353bbd664c4d3ea1c1e341918b373e0e73e4034ecdb83a8");
            result.Add("hr", "425beacc242d7d875c25f3372ee19dc6e5d3317783a163021ec29e007ddb745b550f9eaa0166939ad2e122131c68452965e867a848a2452dade210e2215892c5");
            result.Add("hsb", "bb17767c0af6b725ee812864598251c72ffd8581c2206020c089195efa0b6996671a8f5581ad4f04e826156d334167acb56b80cd0ab1364b7579b5740a8ea142");
            result.Add("hu", "21ba04c807ad55feab27a349ea3c050c24ff6f90ac5c4277210eb52b4095aa490183f0489d59a2c52fb5dce92e9928fe014215b8617187df64223302bd14fac1");
            result.Add("hy-AM", "28be457683f6f3da1edc14d5758ddf9e1c3311d8f8eff2ce3e5278bc2bac4a00fffcdc78775151782bb2a1b404bb5dd21194507d0c2abbfb8cab10ee97bcac8f");
            result.Add("id", "f7e442c8af8b6a4ced60af672855d431928419d75addd269ecd299475c46bc9daa73c25173a3a26515813c8d10b150e45ab597a76f96b610396460200c5f1fc9");
            result.Add("is", "7a2c87f27cc6b1998b366a01210ac694df4258089e014a5255b0edd588808344793bf3aa385a22fbbc7917da7fba876c7911fe6ff284ce9d8e9281e17324218f");
            result.Add("it", "44462da8898b0aed47e9ddf3653cc1fadf7e941b782bf4e700f1b3a37f7d78346084a5ffb410b601bae29fd902a7a4131182618693a3a679e4ecdaace534f03a");
            result.Add("ja", "db7a05b0dc8888427f7f6f5122887b6637c53acb0ba0bc144c9b3fe030fc4a318de147504e65a1e3e99917be22d2012de73f3f4d8d336b95cd3bb4ee475fa519");
            result.Add("kab", "b944e9e3ff71cc94220ee69894144d4884150a3ff1e0f4ceae027a2e6d5409d054d9c6fd6183a1306e463205b1182c5892172877c6f875a3c83c2f16e4c866c6");
            result.Add("kk", "3e513203c422e9a3474e2570b1aaf588c31d81d28081838155e0aa989d2e3a91bca86efadf62869e51d2c5041e6ad6227882dcbd1a16378db75a19c404b80f3d");
            result.Add("ko", "b3a5c8520bbb5a43eb216d1aa31e5bb5296a030347b43b43c22776f9cff0e065a7d4c3b4d6ad2f2bc3fc2cf52c0942483cb668c7d9a5de81d53cb6be8ab65660");
            result.Add("lt", "317eb489ef7085a60f5573b52653e1dc4fb75c7df9fc1aa904c7a405c112fc6011b7c884c40e7994149660d3b6e8732e89846c28c18ab849d6518af6307f49ae");
            result.Add("ms", "86491fe629729ced8be34f3566ae2f352e70b59024c67e979cc595413380a2fa6c01cb462811d6bd8af19c20d11152f3bfcc2a738131d11ac778178a50bc40de");
            result.Add("nb-NO", "c25bf7a8e0c5eba88ebf16ddc5b49bd58c5f03bebf1d9d0933a0f3f5c21bb64943f5c0d4fba0a99487e7c60363d49e4fadff7977725c859fda1d64ce7cf5e0ef");
            result.Add("nl", "50b207fad7d90348f542076960a7a9c77eee31604ce9a1bcc522375276b07a64bc445b3f25788fcc3e182553a8715a7c07027f46e02a78bf661b67ed22f56a52");
            result.Add("nn-NO", "1b29ef200ceee982ca645d1366be1ffdcb6a8bcb4baee6ad2f8526cd34e6ba9aceb92bde2738e60314da8948cb4787e7542bcb1c55b3fbb2fb9c6404ba6c1d79");
            result.Add("pl", "ec70c8ebb759f145499e81b2e37a40520cbcd014925c4593476816cc72ca2ba6f68787dd892d12576015734b6802fe5bb1bf0306979407f07b019585368e1045");
            result.Add("pt-BR", "24d3683b9635b38674f9bf0342799f79b5135c2d1738b34c24061666a3bb76f9baa603e74979cb72f1a62f97d626aa12f439a975ea4323d3c386198b5dd89fe9");
            result.Add("pt-PT", "3adee7de2b3fdae919e8690135b8e05cce176223cd7cd4116deaf8aa411fa38c2c4e08cf9add8d929184aa526c20d60ffb10d9cd6a0270ce947647a8d49bec91");
            result.Add("rm", "1fe8929d860b897524f823901a60ea41014295a2b360965a9d213d770bb2957e10acb9377b1d9bf1093bbc5f88da9f53f9c04233ed5d6e76ffadf5b65636393e");
            result.Add("ro", "b6010407080fa9b72c59fdf96926459789c38b7707daee406dc81278fef267da58f362e5d46fee7a0f723694f160b2c04145d5f5bc714e1811b4d2ed331636bd");
            result.Add("ru", "6f17b009311cd9f8465dd0f79ad5f51b1ad85b698cf3a9404621c6bb1bad1021a010937064dcac38c67562ab999df642579602f9cde353d51be168f0b5a680f4");
            result.Add("si", "69fea71b0be5ffd0127dc328d3e9581b06e5c967c82c3da8760058f8c0a31d3ec639519528f000af539bb69a1817104d1c2651a33df7b9823ebf2ab4b0c04cec");
            result.Add("sk", "5acbc73cae8b0bb62b4410fb90c63c44e3e403a18da354cd5349eae88ccf070360659a91dd391c24a8b64cc7f54cb528917e9729e12143da4dbe22f833466a4a");
            result.Add("sl", "e31f66cab4146d08dcb384f81ef8b9dd3b2c02d30340a728b1510c839d5489c6bdaba49aefef8d5335ef2c577cf764c0baf345fed894ed1fe8b6ac74323e25c3");
            result.Add("sq", "7addc1be7ddb0b9e777521f4456dd5e80e17c728f88cc2cd878a18a52d851173979349b0c8bdb25f2ed5d8ee69d1a1d1d639b2e0c56e3fba1241b97fa2787085");
            result.Add("sr", "089e6dbd5965234b09c4c6cab00756c1c08e071ce655dda3916b1efe231524e1bfe4b9170558f803d0f687ba95d52d80f604dd6861c1814e2ee188981778b679");
            result.Add("sv-SE", "37f0840dbe1989335008ba4b3143b236069e439eb3c61fbbd8341fe5d4bc207665498ae0c6703d117bfd981494e21465afc04db48f8dd0b3c6172bc2e543e043");
            result.Add("tr", "06583abed54627e13f2042b87e1f42e27e74d6f13a0da38f8e4dce874274048d8d7115b40c41ab81f83eea63f0e83ea3898accc312370782a0d9b0dfea68522b");
            result.Add("uk", "c73d365dfb07575182d42ef51bdd4542c35edaba0209b20c913481c5f4804593004e2962a344fbc3886a6aa2c5ca95cf2c7e0f6d3d7dfbea2f0f54069d8c09ed");
            result.Add("vi", "08771fab27a9793b93060035ca813a12f04cf59964512889576b252ba9a8f4c220dc63f792d055efcc8a6ff7153e743fbf251a1bc89c336d58d5d965a1afba07");
            result.Add("zh-CN", "40855e8c8ec03eee29a284cd74df51d5ab14a69f042319363983fdbd8f5123ae13cf8f8037e3f6079b094422c3edb599f08d8dd0cfd555b2a5521d517fa4e2da");
            result.Add("zh-TW", "deefb73d24eca07b4313d9aa2566c74db69a7afcd5b694d5b57c31eee0d0da2d3b0dfb0c1f6e889cf6b9b6c7c4149a5107765e71bd15899e4fb9b79cff967f6c");

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
            const string version = "60.7.2";
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
