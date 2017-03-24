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
using System.Net;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    public class Thunderbird : NoPreUpdateProcessSoftware
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
            // https://ftp.mozilla.org/pub/thunderbird/releases/45.8.0/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ar", "1bd97fa8e91f0ec3204f767ef3eb6f8bea1b3a6d4ff190654f6708748b8e65b472a970c32cb7ab218ec2a781f7aa279b9609b2ea76882868d88cc2a88ef36cda");
            result.Add("ast", "501a785989557911b3993c4e63a2e1ca6cdad80b8039a98b0e2ccafb82f09ef6b8a82f92ff445b6c19639f862d45c09ab046e94aaedec96209981ec4d16c03ef");
            result.Add("be", "3a025136b9a9501974646bd99d8fe9c2ffcf740c46d6207921e4c56c583f7c447b60bcdc1ee6af7f697b6cc0bb909f38aebe055b8ee18a77b3a6a64f44fc7c43");
            result.Add("bg", "b4796ad5253d07011ede34968dfba7cfd066ec690a690758837d08a1ec4ae2818ec980a3e8b1ea9cc969e6f2ea88e3278295c5231e9dee20b386514f1cb82273");
            result.Add("bn-BD", "4edcb0fd5cd6e108bb66970933108d439e1bdc1ea54a8d91be0ddbea226952ef885a0ed37d45d36dfc3d78f6dbed6ad83e0dee03c6e9241d14f7d5f1382498c5");
            result.Add("br", "086874d47f8345d78781922c3a40e47759c88272e94be6e3967562bdcfac38f40ceaf29a32fa5cf926d0c9bc8084c4fe1b4ef2d5443ce306fee28275ff60343e");
            result.Add("ca", "1046a4e26f44c30c556399be1b0e608ff40781b9dcd02d948e67db72af13411bb311764d8362502d2c46f3c605cc94709340394b78e188aa497d070d0ea13045");
            result.Add("cs", "5777b7660f2b16dc093da22ecfc002d1a8a483a2cae9817ff0dbbdbf39eb353b62b178a6cd929fa73344e916f471604385bddb1b818448feb8e8ceae74917fdd");
            result.Add("cy", "f6ae86897b1f3f724a57cd49fcbd229ec71fd0dee520940b4648acef05f4786c89b04232e5f19f7ec6baa5b9bf943387afac6d742f989873082d6c25ededca8e");
            result.Add("da", "f73434aa62c2900623b5ce19c395e8bf206e970c83c11c1bda4281cc514ddc62863936ffbae7a071073e4ee703413d8ceafa954f03dab5425e407730803ffeff");
            result.Add("de", "cfa6081784bc34d2cc64197dd624cc80880fd8fe5f59e3e9192679ae488a47124f18d1114a63edad0a6036644a1faa0a458aaeaa496a5aeaf284d26094357fc5");
            result.Add("dsb", "14ce094f165b92012a68bd2138cb4af8d6a3547c1f25e8e6281b89d7dc1bdeb877c9106c30eca4032340776c062699b9b00edd94947ff42064c6620160bcc63e");
            result.Add("el", "fc58608e6a8137ac00afa4764d53d0feaabc02b5a129c3d343284270707d2a8c0a0d48cbc12fea6ffdbc3b7db07548d0d44996e5137d97b12e3a3975c46ed08a");
            result.Add("en-GB", "c7aa388522f726efb57a2da190e49b22d9c6984cb7d72114734598c897179aec60262945c813d781b1a8dd00f501bed1070de151f04b697825fb70bb2e31589e");
            result.Add("en-US", "958a303bb7e9d543111ceef7d1c47ea225ea89ad6cccfc9955fefe08bbdd3ad629ee14f30ff2a3c06d7b1732c1769b028d096339039e0c26dbab71bfa5331b05");
            result.Add("es-AR", "737236097e1b2b4ad1ecf475338c39cba5b07933d43f3e361bd8d13c38970eed838949a6326f0b7bff5c8120f74171ea187614f53a7599278dfe9714021e4d17");
            result.Add("es-ES", "f9c906e8510e644441b1e6901436698c8e0dbd855c202b7c68754537c90faa0768c44be26b3d67c391afa35a33a1d14a40b95080f8b305a08afde90d51e6400b");
            result.Add("et", "80c1a4f2d69afa3f6a671ad371b27b1a230fd0c21dfff45acf9c614d2ad10f08a1762b9ac3344e703a1a29c7e49828c3e258f09ec75525821f5a93c9de5feee1");
            result.Add("eu", "da8b64d4e22b466e9c9b9307dd69beb6a4b2f486371d8841bad253a0a6d720ef9835c22453b68dea6091898b91239780b3bbef474fef995c502eea985bb1aad3");
            result.Add("fi", "460fd20b1231e221a3d81dd5cd90c0f42ee71749530ff8cba1052ad2f4ef9eae7c9597f3f0a32b24826b695c2b818555197fbcd4783f7518385bacbc3bce6c4b");
            result.Add("fr", "7d1be61753ee89746bb7ad7cd17480b5abe014193d447440b8a5e4dfcff991a0a16013b9b0a6d16b27b5804d678e3d1aa8621b7d622103483183be382a21c14b");
            result.Add("fy-NL", "2c8dd1ae023dd0d9da695dd2a6daa40d5d5108adac2dbad66df8a30a7a26baecd3b95acb0206971e4305ae7b75f45b7e591645f1ca71005cc37fb9a4c057b454");
            result.Add("ga-IE", "ffddd3bc8e50e317b15e7620d747522b9c04ef47945c86f77fb7f2204d7ec789d8b20d6b427d66ca9205a8734a3438410f60b7144273508640c3e97c97352a96");
            result.Add("gd", "4bf322353f6d4e8431133264a5e846070525b8aea37c35f613a56e7937c37cddd0c39059f32f13665f75daa0c3e38f2f3532a793eab08870fb78e47a0a98b688");
            result.Add("gl", "05b903dd3b7a53c107bd43452af6a4c4faa70a50e915c292ec08fd7f06d0104ae48864d600fa02020efbde19f6632cbddfb9e0edb6f7be893040e99f3fd052b0");
            result.Add("he", "d7e214864b61d587fb941c796e837bdf69aadc6d11a2a0fdd484bd53283d83cbcf590173d5703dc8918391a275145946f9d14aeab828135445e0cda4845f2a15");
            result.Add("hr", "db785071a86333d8f8644fc75564e84291fd3e9b1e0c47c93a1d2537d7360f1e0fd71088890c9262379e47c5c72c3f09600428de3fbaf5ae5314dedd25f37de8");
            result.Add("hsb", "ff090ba80b8da99491b60d2bf7c3bada27529e48d385053a3d857d4e9be2971a6ffe7ea99651b4027dcb313f7432d9a33bb4ef4059c99afa83b91f4699eb3940");
            result.Add("hu", "eda979efb5453b21d87e863a46ea0cd28e105cd18ece5daf4219e9d977b44b6ad9c0f3950f76b60726a43d9331e3dad90501b443a222a4622c71b20a68b6e527");
            result.Add("hy-AM", "98986a1fb646ed70d2a8d055ddb910a29657d0c22010bbb0fbbead5a31519b507db46c90f90047fba5e00e57078b5457bb373c53e56f80655b22784790ade3b7");
            result.Add("id", "730fc448630ff06be55e1fb26598b941846f2c619b749e63bceffd3cde280eb7af0009c9fd323c8c9913ac763f53ba922a7f84983f01325fdc29813b15db0861");
            result.Add("is", "8b1aeaefa408d9ac92fc939f23d11f85a49202d5e1f3dfc04ffaa90674567ddeac2a802c767e848a39482103846206e2956d919614d5b11da0df79c3fb2060e7");
            result.Add("it", "3c76ba719e82456d4c2f008fe94d7193f0b06294526190f069e79529914567d9a9c7b67dd4d194b8913921020239f74e922ade85012a1c329cff220beb8835f9");
            result.Add("ja", "4ee7bbf06ed1147bd7a105aa80b3e58bb263a7706f88efc9a710e6341c85e3f1c269e03f46d7b406f55c5b9a00c80f656a7395a3b1b613f5cd395d3c9390e901");
            result.Add("ko", "efe2fb11a87110192e0a9cc7da4367c81340a95aeb23092c1305a70d9fd5b1e19d5c6186bcb095b48aad2dd7a2d0ace34305b8a1304c18dd503463a041f8bf7f");
            result.Add("lt", "a6978d2cd0c0adc1269ffac2115c601ad6db055b471a066442d2828d09592fcd6e59e975e99e51952b6331d12ab9c80202c9bced89c598b46a5f5fb00b34e100");
            result.Add("nb-NO", "37eb128a4184a712e8ee92c0c93050e8be5461a1ea016ef4876b78644f3fdb0a639288fe5581fa54ec60526afd7deb511572244fa719973ed42fb07cb45de351");
            result.Add("nl", "0e321b5959b2349df6a42ffd2b37b58b56471ec9f611c64c0ac00935d8a4b55342e6e159a4325973c54802921cc5f454ee2751f4731026582705a28f3d8bdcce");
            result.Add("nn-NO", "d62a32ce9c807943d4eb2f88c9d03cb381ffc901e8efc820bd967471ff35dadaa62d44b5c0bf19485d55a55081e2c58a954386aa66882fad3c8ae7f5f64d8992");
            result.Add("pa-IN", "0ca96aec5bea77d94fc527a66ef13d5aa806bec957ae17e6ec11b77b45542bcbe3e915a57591e8263ba0244e498d1b1bf22f9d865074282491c413800bbf77c2");
            result.Add("pl", "dc43e0f9358e23334e2a4b84057377ab2082372dea93b8450c7c46041c103b3f38c69ec7c37e98a89bc14a2b9d3121adc140307a866ec1f9ce5974a0604f9e72");
            result.Add("pt-BR", "962dfb811ab1aa0799c7eaecb4084b08e3d64b59ae8b8b6863b7a4c9147e151d5997da6491daf0920b7c0c21a2930436f3d9e1cf4b8cfc30e54c160cf9fbb10e");
            result.Add("pt-PT", "ba20c4b797993c627528e09cc0283afc3ffe78787b4591871ecc3c7eeacf9ff99f20b0dd95f2840c75c3bae45ab1a45f7fc4b38c231f3d34320bb33866e5c857");
            result.Add("rm", "276ecd8bea3483ae24541f938b89d90acedae9d92085d8468f9a4a25133e193b679565f04fa3853f9e498afa5f329ed8329ee5ec6a37764d36e20d795de78eba");
            result.Add("ro", "c6c50e075c18bb7f2304cc4cab31cd2458852eb4ed6215c8146c7904fffc196df46520d095a5147bced61bbf80fa3d245c6d08c53b665c1c61003de8bb4d0e66");
            result.Add("ru", "b7932c1c09102694003d931252586edc76af5e0d2d12d1ac00b2ac21a00d2c7dece523f2e7be598fee5787e0a72673a4971e922479a72fb9778a9f3f76c57546");
            result.Add("si", "ad1fb72e7f878bbc7d77c33331ed49f409625aa2951c15f85a78550904ad84d14ed9c63f921fa35e081e20208b1ea127b92cf885c2ca86b3b925020d7d8e287e");
            result.Add("sk", "09f9af979645640df24beab0bf540363646228c059cc3eccea9ac41b2a7ab98ccf99a3b7170ae2806b0a45e976ca71193cd92997a9e51d41c8157c5a743c5aa6");
            result.Add("sl", "bca896c339da93d31c7f901098f0529c267acca130a45039607bd4a8d579c3cbdd930c29fbef50a84cd06448c222fb54b986d7b69d6b4798171b621aecdffe6d");
            result.Add("sq", "0fb738eb854f53d24c637ce735b5b66943d225e4a4adcb9b84d6a3cdd3fbfee9c08b647fa743b72b79c23e1872f3bd97af33c986bab3cca1370368629306f7bd");
            result.Add("sr", "85cfddba00fd7839eaeb3733a8ec0e63312c0e98502ff476ef0e9d0c76775e3961d81ac880d3eaef994a5fb10f553d4333b97cae114e709b40f5bf4743743cc0");
            result.Add("sv-SE", "99af623b0ab7017e57711b7c04977f41512b3df1387880135fa3e636ce9f3cc846695f49ca03d289ce8cd26bc15b67c392affad343cee77f41c3e51509533946");
            result.Add("ta-LK", "5ae1eafa9fba1729528358d8e516db3c1e733b1edc0df6eb67ab9c5c24cdd21156f182f1cdaf22065959dfe57875ba0bb800ab27eafe4a438227686ae6eeeb86");
            result.Add("tr", "e40ab34b84dc6f2b907d1f614fa5475eefac4df9a3947d74f7ea75e64bb555b2ca3745fc05b52ca342763290fa7431c6b162c41539a2a7f0712628bb45cfbbdd");
            result.Add("uk", "3acbe4506da3d06d9bd25eedc35b573fa7d77a69aae0482e9e09e2ccfaf1d17cdafac2c4ce4893d2b2fe7d21e2ef70bedb6c2383898e9e897768f6acca80cdaf");
            result.Add("vi", "4a1cbe6719fb2b627696255749bcb7b170b88e7b5574d5bb0eea9ad358866c5357a7404c0e331c3ce44f3ed60a58b1858b686b6e29b6aae86b016833fd6a43ba");
            result.Add("zh-CN", "f4fae20978a33fbf67485a8386958a2b3276c6762e64b810ef40550144ec9a74b7642005dc52fd2686912e1ac064ccf3611b20b3f0edfb60c7e109c86055efc4");
            result.Add("zh-TW", "fbeed67af02ace73c547440ee079c2c7535945be750a04d462983467bc4be6a10b63c4d1e29ca070b0cb6493152cfef266eaa3dd562bcdc2caa67829a3d8327a");

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
                "45.8.0",
                "^Mozilla Thunderbird [0-9]{2}\\.[0-9]\\.[0-9] \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                null,
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/45.8.0/win32/" + languageCode + "/Thunderbird%20Setup%2045.8.0.exe",
                    HashAlgorithm.SHA512,
                    checksum,
                    "-ms -ma",
                    "C:\\Program Files\\Mozilla Thunderbird",
                    "C:\\Program Files (x86)\\Mozilla Thunderbird"),
                //There is no 64 bit installer yet.
                null);
        }


        /// <summary>
        /// list iof IDs to identify the software
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "thunderbird", "thunderbird-" + languageCode.ToLower() };
        }


        /// <summary>
        /// tries to find the newest version number of Thunderbird
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        private string determineNewestVersion()
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
            var currentInfo = knownInfo();
            if (string.IsNullOrWhiteSpace(newerVersion) || (newerVersion == currentInfo.newestVersion))
                // fallback to known information
                return currentInfo;
            string newerChecksum = determineNewestChecksum(newerVersion);
            if (string.IsNullOrWhiteSpace(newerChecksum))
                // fallback to known information
                return currentInfo;
            //replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksum;
            return currentInfo;
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
