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
            // https://ftp.mozilla.org/pub/thunderbird/releases/52.2.1/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ar", "543b5359bd53a64ad8937e76670466e72efa1a7a1ce69ba562fc71c56d1d358f0e92d002f05b34a3b4eadd7f5eca92804c379bd67ad481cba158881998e62de1");
            result.Add("ast", "a8276f5aad03e8e41c6cbcd275032de4f4c9d994096005f4253f541087f3f395ef0efcf46101dbe05081778533f9d647f328a64ed058b776d9632d678c81ed2d");
            result.Add("be", "3e4b15c2ebd3b82f5e6f066a4da74f08652366c5e1b8144de3c88eaa4a4c00e370828b481611ff1d25fa1a1016220f5cac054de653d115e1523a9bdaaf954935");
            result.Add("bg", "10c951867c608951aa807d4c6ec60f011f06c91ef4d841760595648ab716291b2190708cb7e106449bb734b1d21a2864b5f7d94aead10bea84c1f4e90c30a292");
            result.Add("bn-BD", "63804de65d0f868668e1b738ab094c5d1d36a466a7a3770c6af44e38e765d3daa0ed7802de32545ec87acb1331f7024a2d725fe3062806bb13f6e61bd0883ab8");
            result.Add("br", "fa146086a0f5c2735c41755e25d3b859f04965a16b1d95ef75dca8b92a485dafacc5866ca4c9a2060879d13276ed02934c9ee72e87f581d86a987fb77cab6e83");
            result.Add("ca", "ca62f6cdade11927b569fa969aa29d8e0429d5c58e8a449e09e70ad8f8d0d9cd2411c120d1f7798cf995e78363e5cfbab6942ab2527f69bb305e6dddf6ed28fa");
            result.Add("cs", "386478005e56f96265daa9d91e67b9cfd6faeda9ae2c31adcf9b97291b7ce4d349b48c16c64c7c397002a82818fe5aca4bc5f2533a28a76e39a7d6746b1c48da");
            result.Add("cy", "9b97dee9e5e80235ba39c521060b5f3700ecc7c651c711518c943a1ad4e103fe5d672b43420b2b3edb332739acd49da0381701590b4207974023c1334a32e1be");
            result.Add("da", "f2c35ff2ef395ebf524bb8e21979e42eadf29652d263e371a6a7609437658d70ebaae130c991cea5562d122e992697100453143068996b566d3c6bed5b3065a8");
            result.Add("de", "ad2d6d0b99f2cbc231536769bc89ef99748a5eb6524661301f47c81827190853d4ab85970b1fd420449de22a9cd9dc35454c2587cffb12d04fac3ba465427c57");
            result.Add("dsb", "9b4fe378db1f76e19437b104eddf4859cbced3fb9372d367964d88218052686f41810494329183d8127df3ce3769ff547fe1d09ac8e9b621ac0227bb4f0343aa");
            result.Add("el", "61c8fa775669106dc4ba688153779f5e5f1479ad3158445574d32ca762698ab2f285ea1d7cc0576598d5abe3e5d69db7bb3da7d4228a25a7da417df1a2336cc3");
            result.Add("en-GB", "08a37331aa68c2fa64db4d956c08f32ce312f84f96b51fef461af3ff86c6c0f5a015161f06c636697a6a4c8d28afaba271d950515515ffeae246e148f4436558");
            result.Add("en-US", "a9ad5845ea7e7c7d5cfb1ff845cee20d6ee53e342810c53cc5877b0df193698556bb13c1c53452fd9e91a515fa3f65bb6c279279868db86ba1f218390416d9d2");
            result.Add("es-AR", "880297a9ece948eb11d5536d40cb840c9714c8822e78253aa4bf5b5660020834d3267fd73c54ad9bc860b6c0f5e07750868eb87f913583c6b23bb409ef051f01");
            result.Add("es-ES", "746666d8c7e40c20f83a9f57ffddfc7aab84b3496ebe6f4fff74b5d7d55ec6734f7cd870557985623edcdbe92b351ce2651df44c00ad1cf99d4b015e8aab0b8a");
            result.Add("et", "285250728c44710b63c9be09b5372904866537c1788d855b1979cea938008d128a31fe2bace4fa0f6b6c1da9259dbd0c2b4be58f23c2f184327bd8f5e37b4558");
            result.Add("eu", "e37ef9810d78ac01dce9c70b315893c368eefbe0e4f982e2e546fc902af14e4461463299df1f2e4d1894d5966b5eb12ad2ac12e5c75bceacd4a5ac777ece21a2");
            result.Add("fi", "7253fa416fedf74d445bab80b5160df1b2f8ac227fb5c0c8c6878dfd65952a190cff9aa4f0ff28b29818f39613e6907bea09f37ad62e23a98785aa49ff770826");
            result.Add("fr", "88e31dac650484452f1a05b6821992ff18869a64282744a5a3a299acce71bd167ba727971393fbf4603d4127aa9cc9d306e36026d706c90ef41887faf5ec9d6c");
            result.Add("fy-NL", "8539ff5edd348567a030c92d40258a9ab2ddd395da554d9900fc1aaa1b171b51ba492bac24db0e0c5f261b91c57caf867e735f01736920439f4c1242bf8c3808");
            result.Add("ga-IE", "e549dcd070c751d3e2f21563fcc747c5b18a915ac8e4ce26ff7b4890445d4227f3d5042c4d9fc1378ca59ceebfb034c3e677c46c4fbe333f3c303aeef52cb416");
            result.Add("gd", "80510151abbc27eda7cf2f5a7ac15bde0cbec1fdcaa2640c062a5f2cdc1e3b1dc902b7d598d240b4de08dd6019f46c26a4a8899026cd50301295b57887631ee8");
            result.Add("gl", "1ff91cbaef2909d35821942265946326269eb8e0654bddd8c26897f8f1b88b56b51de1abf78edf2e63fdde0bdedc2d6a4dc2b0d506ba518d71eb139352507ce2");
            result.Add("he", "d8edca0574e5dde0952ccc246040f1c1ff3a07cd0fe63563010fe84bcf84e9c426f07ac147b8cea39e64b1868a05c5d46721f27e619acadc7191f2969a3deda1");
            result.Add("hr", "61cf71385a01b3b38ec26581163919ef09db25c85b8e316dd24260ecbe8fc7c12ebb0bbd2ef17ec93c382e1f8986d9c2e82277961fa08bd03fa1763404de42dc");
            result.Add("hsb", "3773312e226f3b5141b1eef6db37336580e653b1996f30eead7b7a30605c653594152c53cf76e34d03cebd194087a56c6790aabcb8dae7cc8645118d2cfbd712");
            result.Add("hu", "bdf55be1b90716554df5e9bb773b4bf06e3062a09cd2f3c6fb92b3fb7133ae3633beacf1ea0aa958731cfe13c15875c5cae6eb4963ef5f25e08a0717211985c7");
            result.Add("hy-AM", "6ab464c26b91a10c276decdc45fb486ba244294129d43b39dae2e071d5a993e56bc370128623c24b19229d9221301223146cf81922719f0048d66c90a7b1070f");
            result.Add("id", "2e6b3de2a090a3c0654fa6c93e8ef19f281756001268adce47241e7afaf2a2efbefbdde87644755db10f3bd0a594ec925d60e6cc9f132978dfd5dba1c01b9651");
            result.Add("is", "5bcf43d272290b0dd4c9d7bfcb67334680a819f1644721f65d89a429186aa925e6f858bc98842bc21da5809fe75c6c535d2dcbad99f757f52b79ade6f9afccae");
            result.Add("it", "0adbd99ed1a023f84c310728acdea9decd542a861ecbffa2abc6b1ac1c5e68c9a557975998bcdb698a418d4ba9f4f1ad6623dcef4a80c9182ed0e51551e4e441");
            result.Add("ja", "e95f013af12cdd0c40dbbe8c55994e220be6faa2d610524b4b54703985e5f587856e25fdbbc602c396a62627ae60e1fdbf90d6dbe118db034365411c46da4ab0");
            result.Add("kab", "95dbe67b25b3362d089f3899fff832c10d462e02b0230f2e9e1414c76cd642d1559f2c5bc0f125c871e460b40b06645e2cccd215179e7b6e42cea123417769f1");
            result.Add("ko", "863a59cfae83e1b40cc4767f7d11c67c338931eadab55192fd4037d6916acb99e6b59de1dcf899c1166d7090fdb407f8d9300ebb2219dd051973dac8db9872ac");
            result.Add("lt", "bb280a4d1a146634e61a9498f0f85a247089b61155581dde5c91ad182779bc0489a98054423df83441ce90f438ad080ff7bf34d338940b299d3074a9179c3d45");
            result.Add("nb-NO", "2b4881b24c19ba5b69be38c427f5592fabe638effe821bedb2d3b52c3b4b8946a137777b141c48efc6003b19df45e37a965f772ca432567447daef0c7383af7c");
            result.Add("nl", "b4c91c59b5fbf08674809de22319d869d99cb5c30ae13b1b806c7995c6f405886e7ffc5afa9b1daf664acd01d0f84f4f9270a398e3511a9b865d6e0dd214980d");
            result.Add("nn-NO", "559d72ce91292cf93cffc1ae785f98ea35a134f7b4c26ef74d01f1f3ab2aed2039ed6796b8e06b9d552de4e2689754ee5da6dd8fd7f6bbd4ad205a7a7f38bfac");
            result.Add("pa-IN", "9a4e9a7a0dfb74c648b94e2416858f30b64c0f45396e27b74fde1d2a5d0a9f939e3a12f1917ed0046efcb057f6a99581fd3f9d54da251a4a33af848d030a67e1");
            result.Add("pl", "00f321b9057a6a992586c69116f6ea3a7f1c29d8fd35106b2326fd78a06ceb8b63029efd5fd39373bbf9114ff0bbc7fcd3c3b0be5a856c4ff6c35c04c606375a");
            result.Add("pt-BR", "1d9431ce8813c988fd32904a140f18bc4806b586ec6bbc6b2d5199eaf663f3fc6d1be2635cedabe5c8bf87d1314ef956b48cd8ddf706ada8fd3075e9db5da26f");
            result.Add("pt-PT", "dbbdc4e07e4e9de484cd42dc9795f733e02811183b94a086cc0fe8b1230ef57718320e96cc7d41ab9c211091948a85fb23239c0c85ed3b179edfdd56b0483982");
            result.Add("rm", "f8f4c114a0aca112a6dc38aeaeda070511a5f094477153a813a808fcd536d2ee1e9adef7014bca313780dbc43889670176b37ded4a5a04cfd63c65cb3a25db1c");
            result.Add("ro", "72e495bed485f2dbafbb36cd3b89aebb1aca465e40db01671ae1d3d3364754733f5a05708361f908bb2a274c0e51027530544d48abd13ff90e2987a2b43e3e0b");
            result.Add("ru", "f34a8680099b73344646bd55c2fd691bef48a8cbad96cb4ffb94ef9a6d50a779fbf66e5b8bb1b10aa1c2077357a16cf74e71bb3be69d42a005277f5dc5f24995");
            result.Add("si", "e7731fc0c9a39e42a6c671f3cf411f6c72415166877ac37b50912803cec8732f999443f6716f021627654b3da38af3d0bb322c4d4a6edc88ab31ce5f1b9f28ae");
            result.Add("sk", "d1b48c83c1c63530f92d48cc250bd15bee8b4b1c96df1e127a56c8d29bec122fda90f48eb46960029b14a4dac437aaaac7b4ad1afeea1bcdc4be267063a4301e");
            result.Add("sl", "24279d49e82198d3c258f919060854114dfee00294012d962fff14f9f920a6da806694960e241e1108e8c920993629719b7426792f63bf58bb555b897936fa1d");
            result.Add("sq", "7bc485374fa6f718bd6fd2b697e0776e60e328dcf32bcdf6172359c3da54ef39702d577672e8d392f36928bc08300348187117abb29ea121e7276c73bce51750");
            result.Add("sr", "e82fbef6b2e7cd7ef0321886d3eb9792c1f80c9c481b038c5e579f802a656a4e79bad09f22f8213a7525913fef2940a626b2b872a6db3bb9179c936f0131bd29");
            result.Add("sv-SE", "2bc9f3ad6d61c00e9ffd398f47ca09899fb3943b5e9eebbb7089d70ae7a59c86a637bcfe128cd0fa40a9c06e0f5dd79d26ca636a77dd23b3fa055e0b9239a36d");
            result.Add("ta-LK", "3d32af172f474c3742bf820338f1a14f05852e64f6196f5fde965154728935f5fd5c77a8bbf698a11eacec11a030b4bd4150b51c1bd179ca525c0a23aeeec871");
            result.Add("tr", "8defece887585c18d6084184b23fe879bf88678990f565a121157f3f8340301713323bfdb0756621ab9e2464129e086de2a9a4f7881205195f54baa35c852373");
            result.Add("uk", "ee0bb5f6af3cd80b8853ffed240eebe58568f3853e687d4ae777bf1156401c2f7af836caf083268cd07fac91912fe7ac5110a7cf7393f9af1faa611b0dd3faa6");
            result.Add("vi", "ad96fbc017e4ab830b89084fb53be1f9451bfb1c2fab71c8ab22bdf75900f07958603376c0b2497025229ffac186cecf8a19ab763c41038bb3500087adf0cd31");
            result.Add("zh-CN", "13997af39243c854c5496660c56ea1f7ca4fd168036efba0fd6fe00897e9a0221fd4949478bc93c7b58f849e92267e4c7365c5c812a2b25162656afa9a6c45a5");
            result.Add("zh-TW", "4009966699deedea3428804c149552e6584b29f8c9a230e1ac139b3553e346e515e89224d0eb5b646e738b4dd7aac1d61c81ec6ead54311c2bc8a88239dfefa4");
            
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
                "52.2.1",
                "^Mozilla Thunderbird [0-9]{2}\\.[0-9]\\.[0-9] \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                null,
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/52.2.1/win32/" + languageCode + "/Thunderbird%20Setup%2052.2.1.exe",
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
