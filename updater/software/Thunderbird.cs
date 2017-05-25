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
            // https://ftp.mozilla.org/pub/thunderbird/releases/52.1.1/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ar", "f3704230642ae93632e4f007c516484bc06c0511eab27b28f1cb1db95fd1ed3d6c945d99c26beece5fb6ca95056677a3ecc159e023bff0cc84660877dc4b846f");
            result.Add("ast", "d94619f1ff9fac4678cc8aca2614da8b02ca4b23651d323f68a15332c0c739ee43db12b23d11813ed905f24edbe80ec71518e6070cb0034c8868ff6a7287d4a1");
            result.Add("be", "40b70355f7266e5733cddb8c1c896305ef48dbf6ff5cc382fc51af67d711e7c9c40e7a504519ae4c833d003f8433343e06eeded3e48188850ca49550b1721f5e");
            result.Add("bg", "e25674e178d5dc4bbf9e16ee3388a2bc128b911b1da037d0443bccf5c98332a964424f7d3ffb51f9a706060a3a2ee2d308be5ce1b86c8dc24881707d75449616");
            result.Add("bn-BD", "767a03bd8fb3afeab7e3a87b673b0d8bbc83508484b96732e12325e50fdd0cc3d584d1da163882558e0f3953a5e954ca9a4d59fba06d88009bb09a4104c60b8b");
            result.Add("br", "2d0e122f6d6e993448a713d8e9c38f1acc86e2dcc419e0532ef30dc91d2507cfb443d061065908c4ddf12c3c210125bf7ba895ae084d49fbfaa5cff4e6bf8f5f");
            result.Add("ca", "d92db08c36bbc61ea919c5470b18431b88d5ecc27d0fe3acaeb64a8d02ac3ac9bc1766ccb582f6c48dede38bfde324a72d1cb670ee55b31471bf1046c31dfcb5");
            result.Add("cs", "899df1082826f16209b0a10c78f4eb6f9edee9688cf2d5c55b4fa3db96d8c63f89be60c49a510e34d79c9bad073264262fd5f0a2239c0e4002d0729786ac24c9");
            result.Add("cy", "f77832fdc549e15492eecdeecc4b5736dc3bd0ee14f80766b1ce6b15438134905ef695b971596b38da8689b32b4d0cdd1fbe83918823f3987f0d30e8976c9d53");
            result.Add("da", "f0855698cce69a6c1b10b7b6d997c9808c112f92133b82638669e895c3c94485a88fb07ac182c2b83ebd604b97b89b3c57454370a40cff730a43cf17b270e7bb");
            result.Add("de", "acb3ea9a6a753e9e8b9ae3386620083a795dfb272e73f97d2da20755efea599e8a872854e343040b2e9ae5e151209fa74fb16c89d9a924220207a9bfd9979c0c");
            result.Add("dsb", "4b5b4b4abed75fdc512ed7ae1599a0bff9776f4be299336eeaa297dd20fa26874b1e36f8002ab34137bf89f01bac77a439704ea7d19bded6ff598d9d16db8134");
            result.Add("el", "c9423e0c1fc7f5c9cec2bd27bc6cc1321266025ffb787b0d0395bcaa13759cea93a5d3da4280c34f8689e893a8aa4d9676fff36347b13007cbc7dccd285b7a2e");
            result.Add("en-GB", "869f4d2dbcdb6d5fe5391e81b8ce2472279db138419f08214c568d04093134a9a361c9f4b8e3b9320c27d6da81693d957ff52fdfe6aa9624c7f7f3b8388f5d92");
            result.Add("en-US", "3d555cd925671d13f656296dc9157c5fe303b89cb2fc6a1b12839256633a10c5dc4ee56066441f42b7ec6e77cfbead713f7ec45622fc4301bc5435ddfa359c1b");
            result.Add("es-AR", "d3cd988c6cb6995e81256eb38458310446816b9e97814819fbdd6c477dbbbc4ef801e4b816d1ceadb9ce3b3175e8a85a8849c160af582279333378297e8349fb");
            result.Add("es-ES", "65dfcc36b364a59f8600ff16e9946de1cf3f0e558168232a40e9f1dc412eaace422d82e2ea6d50fa7b3b8101a36acfd53c85a058550be2637cf64e9065930067");
            result.Add("et", "2f84ebaebe0e38e2af1f49b6dae65b5683d14e019ebc95abdbdd4c1922d3a4c2adbfbc4d69d768ee1764ecacb42340a21134dfd123696a39655a2446f90518c7");
            result.Add("eu", "fdd2f77710840212448dc9d82f0b4f25b133e0aeece30c5688265842da3ab4476a744f418004caacebf9fff5e38d0400f76926fb5872fe2b3f50fa0cf98e5dea");
            result.Add("fi", "67e3f0669e6f8d560add4d637beb2a118d7f4b7639a0ead246ff321c3e9f5f97ea74138da88978d4e389ea5ba39c676ba1f73263025466b3f6c91277b59ea119");
            result.Add("fr", "059e78e6ece567da75999ad83e979292b40344ba77a670c3ad854916efdfdfac68ea67720b688f5808d5121b774bb541aea8e53d5c0a28668d25e3949186477b");
            result.Add("fy-NL", "0346c9602b2da748479988432fb8a3859e7b7ce87e88255e60b563da72360bea28cd8b9aae7a7e75f0b64c4dea65a5fb98b0a97212d53b750faf8433b97d4210");
            result.Add("ga-IE", "846503e264fc7c0516b967a64a1f824672cd984d3b9625ae30329277e151521e73e09cf4676f1af4e98d6b7481bea149c5f6d23bc566e92f66b6c1ca3372bcfe");
            result.Add("gd", "e4ab640c00724a57459aa6ceb7c4d7853f2aef62cded80ee94584f9847fe643d89f421498837fd574ae9ee606e10ff492b4d2fc6503ab8bf6871aedc9618c419");
            result.Add("gl", "2601ca19afe0dc935bb42af58dfa0554ff8c01305c7731d1d9152933167de75e9a2b8205e783ee108d770dde5491dda4b4754aa1ca1c78bafce891bdb4147208");
            result.Add("he", "2aa3008a618fa4c1ac374802fac1d853e28c4cd88b16b8dc5c2902cf7a388a1ec2c340e78694116bcb079f3236f8156048c228a618f325b8cb677230d86880af");
            result.Add("hr", "8be14008a9e099379277838ae5494ca9a61dd330751dfbff4fc9d129d63110f6886b35b587e63f09b708996f3a5c0312f202576441bf2954cf496401660bbf27");
            result.Add("hsb", "89a0c720307a0420c2d092d7ddf93c54c1f16077ae2eaa725de408aaf046dff83a26f20900c9c0c3352ab6d4ae5a598cabd435f8bf1947e38e0b6cdc44237d94");
            result.Add("hu", "9a5e81563e87c24db8b732dfba7a57db31cf5f60b2f914c1f44fdcf3113d0c252a262e555748f92a2efe3418f78ba6725fd1240fa8ecebfc2ad5488cf6f78c86");
            result.Add("hy-AM", "cb751e76ab2389b22199229161777e4e0d901263762b5d435e92587cb231067501c414576a07ab2e588c8e8075b60b5abd28f4e3534b255ca1778f1634a27ba6");
            result.Add("id", "54d5b2ff4e9596b361115d6a73e96e66492b15023f44b459f2cdc5a2291f4272f05ca9d2286b0f75c395afe0d1097ed941c27a05cd6e27eb479916b6175ad91f");
            result.Add("is", "8c6c61af86735b382b63bbb9af21a298cff92e09f7c43b06f98ab6a5304446ebb67d7ac2f773b0340d06301c1fe48227eec467dc54104e886fd7d3ad182bb626");
            result.Add("it", "439fad65c0e9de7d95fd2de0996f167efd39e43f635e03d45ddf4e6953c058800eedd799dea5292f4f2e09bf34e496fa615fbb4e892313e31850346131ecc778");
            result.Add("ja", "8c669762b26807469a059c333501ee9349c542bdde6634f384fa231b80fbdb806f1f92117fb92414e1eac3752f2e5cc31f4f9b53d97b0f936d6ddd848f7cde08");
            result.Add("kab", "8fa36af1099e514c9f7e0bc5c68c4a05eeb7a37d8bbc5e633667c6085e8a3ce7a4dd7ae7108344b3e495881472327e0b580c8cb3519fb6337381938923995aee");
            result.Add("ko", "ddb30e6c0956a1c82aefdee94beb84ef1f19309dffff7a19bf9078514880389c5dc415ec2509542b7287f0d554afae09863d261e7e61bed5574f132cde9de6e0");
            result.Add("lt", "aa72722a3c5c31da3611297735db6afe9d50acae71a4c12e66d524ed4213d0ba81b1a47c3de9687e7b35fd19bd356d821f83f2753e6f0855160934f50f207e1e");
            result.Add("nb-NO", "e4d5c1d07117114e9b28423aaf4cef89c3d312c470b2356ebf12235bef18ae8ca5e1d4c242f8764b28706eb4e9cb3ad0a8bb0e970d62def4d9e3c356f23062be");
            result.Add("nl", "bc767d1f4eb29a20df7fbc7810cf8a4ffbe03cf007eece543786cd7830204463a357fe4f5e0ab181f99da515d5fa766fce4404d55a370a4b74cd7394034e0dea");
            result.Add("nn-NO", "97ebd14889549fc6cc6721be1a46fdc5adddf598775c2cac083f1d570fe06f26f5767117100aa8741fa5c237991424d33cb7cb69085e7078db2b032d8d71d23e");
            result.Add("pa-IN", "f19307fb98ca2adfddab6287858f83deba6b13e348d28b23dd9cfe476234e367978eee150da8ab84629413ba670a4b8ffa1d3954a09cf6fbb49c15bd356a565c");
            result.Add("pl", "3bf7ab9af62b201852e5285088475a8a37080bc62835da149ef00e05aff03162846632651acf02aaed500ba75e801481eac418bb0c6bf9b34cb0163f1c9fd40c");
            result.Add("pt-BR", "bde3a675f765abab73a03a2612446d623a540b491e3ca152ca44841675787f59c41928deca92f6827eb4329db45808930a47c6203b68b4fa2e4a04ff1e1c29cf");
            result.Add("pt-PT", "7d31b0f93b7aafb81a69d3e5b607c144a4b6476467ed2b6107a1e773150e80a913593eb3089dd7ed5a88f6ad628f7da41d070ef76d09b6368ad5bee1b661c191");
            result.Add("rm", "170966b38edd634188fbd975410062b5af843f426f60cde336f82fca36834202660422f45bab4486ef57095b8fd7ca25dab7508239856b8950d878dbfbc55e9d");
            result.Add("ro", "660029bc0b3965233c69d4939e4c44f30173ce6e877740b91421fa64d78b9f2607e1d342251763c0c4deb5b76fb7d5c7bdac6623d0d505ed16472ad16425b7b7");
            result.Add("ru", "2f5afacef43043c80e2680816337c74d74dd069e7a1121901ee61a80c4675008511d68d346e3bf37dac3d922cb71ff202a6fca3e120b2c5e61047179f04a44e5");
            result.Add("si", "8c4db47912279031c93f101a335bab586cc14991fc8a40c6889d46ae6361a2019ddb7eb54807c37b879838688815a1bf98704cf9523426e14befff759e3de26d");
            result.Add("sk", "f824106fff88a27cf6b14007939fc86d8b7d71ebfb9f71cd31057251b7f88715fcb284da514cee9027ccb0f0344ac63722363c561b592bd0f63ba88ce3d8d6d4");
            result.Add("sl", "b3c5f1a4db1540b7d6bac6d5c4fcc05e53f248aca1659655329c3c44c7a494e13803ab0ec982ce657c2627bab83b68f28203ae1aed9041a50f59b792b740e5da");
            result.Add("sq", "8d2553ee30d1ede9b8331c0fe31618694f7839c23e4451e239630033cc02ce080edc898deaf95f5a6f6e87fd30a850c27df8740e44b62e3a1a325e3286c4d558");
            result.Add("sr", "01228f82a18de0e7ce019af920ff267c9f187c28abc7740ece8c95073f3c8ff188ed1c88858d91addb5a158c346e0b02b7ae001db8f02c19acafe95afb76fbf0");
            result.Add("sv-SE", "e899c5630136ec13f36efee4221f914dc2c26341a686d1b2728537f67fea655f7219a08f75cec6eba7dc42fd60458782ca00f1483ef802aaaa40fc758bca5b0d");
            result.Add("ta-LK", "90df1ae23e7e211a74281a7cb706555bb8e73a9b6732dbd4c247ebaa4f6891324ae7a20f3db6a160c813d2f30d2417ab587c0660a2b2b5b48dd6b1822d4be498");
            result.Add("tr", "197654fdcad121ee218455e39a488f8027fb5e7026c4f998396b3eca8b4ce1a5ce3849b692af6e3e6497f0a09ac207935214e3520ce0566362e3792bbebf5c88");
            result.Add("uk", "113e09424c950a1bdefc58fcff13e68c795fab1c5ce9472c01e9c686c56b81c67da01a11c7dcef64a0c67a7d897008a58354d6cc54d5cd2049d984b3be0fcba3");
            result.Add("vi", "ef83c5cd3d6cbb12e8ef06ade196fded3b68bd88439fc4d1c0f243ad13115b42be525555e34d58d4ba33b0c2f144ce2aaea228e739aab2f50bb6241c7b1f02dc");
            result.Add("zh-CN", "c42e552f8486814bc1f98a54f059ace4e7a7e335516b2faccb06824dc27423f863f1934183769e1e34b2971ea2cee67ca0b7205415a268d154e92882cb555104");
            result.Add("zh-TW", "5f75ed72b7ba66cf1af123402c41a8af94c85c1469ff50e2671e20ff69786bdfe76a24fc1291bdf74c38184025753af6698c920427bf2ad60eafcfb4592cddc1");

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
                "52.1.1",
                "^Mozilla Thunderbird [0-9]{2}\\.[0-9]\\.[0-9] \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                null,
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/52.1.1/win32/" + languageCode + "/Thunderbird%20Setup%2052.1.1.exe",
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
