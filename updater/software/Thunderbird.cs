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
            // https://ftp.mozilla.org/pub/thunderbird/releases/78.2.0/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("af", "8b21fe5d6b62ea89db5cacfc7e05a4d7b9800f5842901334506029175b628dae62c9492998831dc17924dbceeb10c61dcb00912fbf3a477e2d18218680c13506");
            result.Add("ar", "3f2020a10477abcdf7a7a679c5139d7efd03a5bcb571bfb96dd15d24246fb7986dc08d81249ce92ccea8c2a2bc79f07af441d075ad247d8dc34bf555023798d3");
            result.Add("ast", "60eb6e3c3eb7be941a26d53f3ce96b6349f0eb70b07713b83536bdff630598f760d49119398dbeae1ec31b4d131975a12eb668c9987e7d4a08bd4992cde57800");
            result.Add("be", "0db237aa5ab83524f459e7817861b87b16b0ca41bd4d0c4ef8b9c39dbe8b65d7d4687d562451eee2533160205ae73daeb0e42e8c781acda37db0a59cc0585b08");
            result.Add("bg", "7056d3654d6b57d0aad1fa91475ee9b1278fde9f64c4eac9ac6cc92435983a059ed59074dbd7cddd6537f05085acdd79e3176d6f4173d4451fec7554c9720b6c");
            result.Add("br", "9e03bd5b4ca0ea77716a00f56f494f6b609c638222931406add2ec939f605758f2c959154ca572f053de11138ac17acb61691cb245fbf96b7d770a743b9591a6");
            result.Add("ca", "9907bcdcc08660a8774e6ede561d5c5abff6655473f8aba996c16d8b5966acb127065c7d1319b7e6ddb67b2d10ad36167c88fc6868baf8db405ac5e5e37e832d");
            result.Add("cak", "4c4b0d84db2d12a395f5d54822e5efaa9cfe426adc7fea93e310f7327790b417ea24ff788394aed8196bb133f2cbe1e6f858f52533961753437823e6e427264e");
            result.Add("cs", "bae67b2f19e3320df7a23f6a8f6b7678c9e59e8289f200f1f00bb7baff19c66f07228d11a1ad3ac191c738164b7a93182933639419d2eb4e727e7ba07ed33b9c");
            result.Add("cy", "c4e95c077370af3aaa1f9c5cebcb53a6ff21267dd13d576bafce4c90d6c46f19d3da2002daf6e99e8470c9d6a36b08f87cf9710827b007494391676e5f92b1d4");
            result.Add("da", "733d9ae6647cef47f161223a428a86723d071a042bac3f1ea84480e52c20abb7b2951291bb6e8b28e4ded787c8294d3505ca9e5bea79753f35739ae03285f011");
            result.Add("de", "fe7744369af1c3a8ee8085d128328bf4db796907e02bf1ac11a5252a8926074600cbab3dacae8b2903303d7b5da693307e9f60217d9c33b24c25a5e4d2719af0");
            result.Add("dsb", "0071d2c03290f96dad6cea97dc9da5c23b58a30c816a3231bd2c508d92df3ae982e4199dd9afb6158ecc2eb3f315f8285521f51697ced82646f6ce3d49caa117");
            result.Add("el", "37ffb0c5a30437a5fa78965f205ec249083cf491eb87481020a75d944cd1c58c6d63e58bc7c6d9f578ce4b2329577802b0a7e6ddfc3dd35a14337e9891ae4826");
            result.Add("en-CA", "515045c0e4c122d73a1747ce334a2d3606736275f07962937a161ecdd7c6e2469b7046dfdd8adfb53a96df6870a983a32f941b0d5d26122652b7f34a0ca5528a");
            result.Add("en-GB", "93b98b6eaa4b504999785ab1d93c549c3f105397d7b525219300ae37d8ccf65a69358325d408ff6355203c93bf6f76e391db78e11197a929571eb1f83bfb6d3e");
            result.Add("en-US", "e98c40bcf0e576d31d5aeac1b1ab59a82a7b132381c1212eb4db426df62c31543cec25d3066eebf9f422387cf02556f97815b0aff09e745e0e2c0fa1c5e81e8c");
            result.Add("es-AR", "b1597f31a017dd04ff709c2a9c733da6f8fbbfeff25713d928c21565fd1f7406ced63e103c72d338b9dae71c620b56d2090ad04b7294568f26d0e70c877d2e73");
            result.Add("es-ES", "4e31cc71c6d49a9f804ef5fdcc915a3ae2e0dd27a784512632866ced4c141822b860ce6961818d2c4efd0183e0686cf6019e0016e2572708b4e0f5e43da80e0a");
            result.Add("et", "f22a9324203b9999d07e500ea4fb0bb6d4871d50fa79901c7c106d00d790a6100bc117dccd16795a4f3d4130b568859f57da71959e07fe06f799ffd67a465fae");
            result.Add("eu", "04f88253c49a3537b27e67abbc65d33605e53a8b4a190fdf9dcfd09c9a4d575af175a355208b0059bc6987d3bb089baaeb67c87c4a8fc853e03d8e5016e2c993");
            result.Add("fa", "a6a61ed150a36e1695b711e067d25bfda8fc7da9d7fc02ccfee2a5b108ecf21b89ffc1a0c646168a882745b0e2ab9024ab9c06ed9bb1eb9f4fd217513a0aefb5");
            result.Add("fi", "e541583c9329a0b9c0274f9bc2a528fc6760a95e672e5e21dcb76f486bb05e237ecb88dceb0d7c3661fa08451c6ed9878e1d4e4aa6a00028a205c062044a74ff");
            result.Add("fr", "16a7dac899736a1143b8c7eb337ee4f18ef70f611340bf2f8e8980d394b68c3267abd085f584f6f2df79f77003f9ac86a5edffdd473930c212ce57901d870c02");
            result.Add("fy-NL", "4fad7bae6d692b1e6f159b6aa3ff9d4260f6b9c94ddae7be8d4602990db564dfc1a42616730bb8103e80afef8edb4b42992927d0938ee856e744fcf521ac525e");
            result.Add("ga-IE", "5661edc68958889f40e94c0b3351700a953eeccd856668f735fa6f9e844e857174eabf13ef567bd05aea1446a22f20014160b98befc60f31ff08e3df5d645095");
            result.Add("gd", "c3b57e18aec080040977ee854fbd5910af6858da16dbed693b61e82c4483c182186ce052f69ba169388fcac3af68e391ba944909defcacbb05f289c4498478dc");
            result.Add("gl", "a0475dbfbded1d64e20b0090e65eb446202c25f5b62a2fe6b9c7942a94e9d7d7ac58031b9f78eed528d2774dacd25bd3594e190cac4499e1389d786dbc7c048a");
            result.Add("he", "06bb0b7dcc73e681b55440cf7fbf5576104e7366c8e81ab1b2898a7d884b68cfaf468fcdb0641e5b71b8cf754dfa59ba05288dbfde711342819fb458dbd31f8d");
            result.Add("hr", "798c11c35c8d329837c9475e80358e1ddf01f95dce5c6c348206a470368ae60cf1beb9f0d2bc74197dd7841b5db4eab62aabe1f7d0372981e3f0d4d9e15a22c1");
            result.Add("hsb", "a0de8548a7c450db7f5ad016b7ce7992150b8072fcd42c4f4cf4d5746e2be4d0da1df39c5a6baadff909a209d2df994b962212789bca6aa8839a73d7f6c2caf0");
            result.Add("hu", "c56bff394b6bdc214f2fd7b0b561823145b411b1425999e78438c7db970ebc9328596f38c4939743246aaba62d54e3281be091793f9591aa7a84b9d2c44e72c3");
            result.Add("hy-AM", "7f8c7e1ddfd6730c8feb295011842f4c5631fc54d1faeb1927576ca7aef61c79f6dc24a0fd452b6132389a45ae3b7ef032b27f553bcaadf1d9a760429a35f7d3");
            result.Add("id", "fa3b0ad0a3aecd60561dc96c7da17236de9f4f24d99473a1130e4ff5577d1b0f049fce2f1df66b369af7ce82b75c0c4e330cbba6e22484273e65618d9e428c8e");
            result.Add("is", "18143ad51232cb20357173317445290679f518bc1f26f8bcd76ae7fd60674153761b1e1e0174a00a9dc0280fadc1aed63fb20f7b8271565236162ded6b2daaa9");
            result.Add("it", "376b8118d22ed4ec9bb2727e3bd3379d96ab7f84b3bcec704ca3dc196bc8900d5e883d95b8d564d7eaaa2b53d52a124001a60753072b2629369aedd5c4197405");
            result.Add("ja", "0e1b5748a141875c8341c69af4d3a18edfb81b12532c72b862ae6490c0b2f7a0085637132de091b2ec70f18b3154281d21ca53501a944d5c0bfea4bc02ad37ae");
            result.Add("ka", "6c39ce674fbae532ed7a0c66158aa719f74a2fb6ec1e46f85816759c9653c9f61514ccceda2afa2a6e12bacd60d0386bf7a1532db4debc5dc3e2822deb502d65");
            result.Add("kab", "2ff83d2c384e5e426d7ae61a3a6b54f30736f7a0f6a8a473445ad66d10ec62997981d3056fde0c15d5cf0656a9f4f110db4aa5e2dd73eb7c60ba0041d35003da");
            result.Add("kk", "7d77255cf349d3f1390dfa8362c4db6d3cc7dc7984f60be15a1efe03eb01c8d495b7eb1b079e780666b877cea07990c7ab1f7b63b62d6eaf917aac57610caa0f");
            result.Add("ko", "7fb0cabc83cc119f72cbaed984f84308145e7efaaec25979b030ddd86d686b574c879658027978904bdb957d6608b9e7453b3785509d652037390e8ebc58494a");
            result.Add("lt", "9edfb6233ee0182a2290850ccb19124c4a2007f85ff2c44700c4ef05bee635451530ff6cdcca1a3f38b7e9201b42a59396bfc318cb303684d4dfdd5a006eae17");
            result.Add("ms", "0a93f72adf3ea6434b81252ebf55314b58c62a63ee648dc344d046295f5f899dfd94bfab1a5ca7c8dafd2b62501746644c030b10b42f31c6256dec2867abd4e9");
            result.Add("nb-NO", "e10a95b0919f7c389133418fd2b3bd0a1d14b83c836a8d02ab2fd389466590e57a5c7c2024b3c6ccb8aaf2aeeac71a80908f4d63b9b682d99b0451e0e588c249");
            result.Add("nl", "ef934d92c46e1793e081a00ad6b4267b92e6e50ab7809341c0184142a8208f87fafecfd2fd2d65e8df9e8abe03a37f4fb9a364a94034f1131b9af1312427d22f");
            result.Add("nn-NO", "436d803e0a01b5906d696045f45be1ddd4f140be0ba83788bc2b9971e1b270a763bbdb3909c2cb35a8db4343f946543fbacf7c7f379d76188957006c812df5bf");
            result.Add("pa-IN", "436c9b29eb59a5e79f8363525e7267061f1de5a6c3b5be2418922b361a28452d053a950e8b7a6f20b09d2858f8be626d57e99e442ac7672b1cfd08c79ac72952");
            result.Add("pl", "7753aa441b919210b80d66117a91ec081d0609374067c4cb86afc6e30814cc6b84e126451dc6f0de12bc606ef3229ac2c9f3a31804500d9601ff26ba4f1bc20b");
            result.Add("pt-BR", "f34ae85523de5fb2f9a1e96f6f3dc2a714bfa308767c9185eaaa2be761c352d3d808f59702d35d1b8451d6b9b08962cc2976291681eff01ce8ee81e6e7b8925b");
            result.Add("pt-PT", "6dc5107eb1487ae689847d157e402e80c16ba7d0967cdbcfb127f2841ffd692c6fa9d77832f9ef05149035f51feb38adb2863e9f99949b4e12708df819148bc0");
            result.Add("rm", "a00fcfdb0627d741c13c09f2e5093e481e6dfdfe0061c5446fdd6f29ea085cf7640d2b36c87b4d779bc09f7006a706f74f0dc159e5ea14ba92caaf33936759bd");
            result.Add("ro", "beb13fbadf7ca774c25bd3d533f0c8f4ad2f1b0e207e9cc4ffb73f42dbdd9837580d635b21c1ac5646d3e37f7a619a7f0250072284b4af6889b3771502aa9e37");
            result.Add("ru", "96c57457312d71da8f7d7a5e4f5e9aed8ea4ae86911a00886e134287f2292cc6c0870ec565cd730f6fac03702640d16783ba90d73e92c9ae03a71030987f5b1d");
            result.Add("si", "90f88bbffee3929d7b6f1c694e7e1d28731f5a2b5c69313db7dec9e238ddc6c7ec993b691f8b4624c0a2aaa805ffc3cf9eff942f298c87440ca40c3eb6339c02");
            result.Add("sk", "e635b0d39b7ca9a341c3f1542fe4eb7264f84334bc64734f075c80e14d93db069f816eaba517a09d8a7ab0a547517a8276c4bc79d2e6ee9a6279cd0828245f3e");
            result.Add("sl", "33efd064f4e020681d6e80024504de6ff2e316a7e3665dcc26fcc4992e9a1e00f9a9b798adf0004ddcd83985e3a1406162a167a149239b4ba6711ee056c085f5");
            result.Add("sq", "21e1b8e8a1be3878856020b815606398951a4b0c304ac95e644b63b28115d92ecd2390e180f661ff870adce6ba8d083810f5d449f71c5fe8d995020adb8c6d45");
            result.Add("sr", "230e21e1d0204a67047c18a4c69d4c712f130faa64144f23c44da89d5620a1b901e5480dab2f0cb52c3a3151f1926166831052b97876f28565abddf1f826de50");
            result.Add("sv-SE", "9e4794f70478d8801ea6798be6ea8ac8ddeae6713b58a6adbe01eaad3d875f879a09c02c75b6bb301331e0614e896c45ac3cbcc9947fdc7442e844a67624a0c9");
            result.Add("th", "b7a01b001bae0d55208e46f2bdae5c3f4b48aa9f388868f7a919ac3f6f250d7e2502fb99327da7ead9aad09063b15c32011feaf206440172e4a2d00d8d99de83");
            result.Add("tr", "0a5f37ffbec7ded74cc42e14f1350f5f5c923792b44ce7113d6c2f8cc4c365c1ae0915b4f80c19cb723c94dc091e9ebee93d69857c4a2d865da31668a4e42d76");
            result.Add("uk", "2a108dc55fdd7c17928668051c93cd0b2bbe10eb67dab4cfb97fedbd55bd8e7b7d83e985c022bccaadc8a93b362460142fef8916ca14315aeb9de73c396ddd1e");
            result.Add("uz", "c6198f679b75b47b0c234ec0fb03140a80893b695a58359e6a475c1e72207e4575b4a616595a82fcc32ae3d33f15c0d1834e428c8fc03355448def18d3a61467");
            result.Add("vi", "1e9c705212077745b422c5d9df05f991e4ff383e1b95871dae00945c3c71efe2aace1102cb8b2fcb6271441d6d67843add56ab67729ee705754cce20d5caf073");
            result.Add("zh-CN", "6a32d82ba1972662e816e98b51754d865432a4d1c49d9748c1217a488f196f4f61ba9ff7b1fa16f062176ffe3da0c8ca24cb1030b6db6de1f4dce948128fedb7");
            result.Add("zh-TW", "9ba582eaac2c5956dd79a450157cf61225899c41c6fdccb160b7120804f57c026dd19b7ace1c4a3a100db4bccf65e27fa4a8df68dcff4fa96227e12d9e64ef60");

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
            const string version = "78.2.0";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird [0-9]+\\.[0-9]+(\\.[0-9]+)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                null,
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum,
                    "E=\"release+certificates@mozilla.com\", CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US",
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
                Regex reVersion = new Regex("[0-9]+\\.[0-9](\\.[0-9])?");
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
