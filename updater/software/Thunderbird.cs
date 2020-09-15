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
    /// <summary>
    /// Manages updates for Thunderbird.
    /// </summary>
    public class Thunderbird : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Thunderbird class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Thunderbird).FullName);


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/78.2.2/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("af", "8a71d38e427fd0ef69887898b0b40439de5d4eba8995afe39551c05cde56e4580f8ae1e1f245f8d78030b474404424e4b076c7f89ad110036b7ad2cfde0cb5ee");
            result.Add("ar", "164c41dfba2fd10b6e201927330cd99f65aa97e08ad8cc948e12bbe2f240cd47474b7fe22034cace856842655940419480b264ca7d2b3bec1e261531543b49ab");
            result.Add("ast", "45d8f1ebcee3cfe452036dd8d092a797804cb448b40f9abbc6abb35ac77701b9492b19af747ad24b740261c289d94321682c981bdd0e35e8f2365da05813758d");
            result.Add("be", "44a50823000df4a0544819a01daecd5eed156085073e644b26244fa3afb5c5c7270d0adba1c2063e3efb5132b4379e78e90757d47e1c0e3960ed90e435d03e8b");
            result.Add("bg", "0d9f0a30a807bc690fb0affbe4db7db4efc1ac0bf7955a17e640816d8ba76f039559a248fd87d581ea0eeb303e37a19e7b3356179673aa2bef7a62b4e11fd5b4");
            result.Add("br", "216912d18574dfa915e3a962afe1b5126c0bcc4f758f02cdbfe82273b76c402b5bcb4e589ff5fd2fa17fe0300d8deb62fb2f0d3ed7531c0226e05a6ce71af0df");
            result.Add("ca", "fa295270267dd9926e7a2d4c52c33986c510209356f08ad7268a3dcc64c2ae78e03c7a3664c6beec8d0d381cbecfeb9f3e0cb7a83d5449839b98211ad9c49387");
            result.Add("cak", "2d7084687a36aedb1c132b5a7eb51f2620101966eb3dfd006325337c3e25662eab97e2345171e2e25e9eb0b3d5aec933b8b560ffc9e4f4a3873bfb67f44b6f09");
            result.Add("cs", "783e4639842f0a78da5a2d7d22a8cccca27bc2fcf876e49c7db5a22000f290d47bdca370d458ffb071cd49aaea17e133e48dfe41b0d28d3c0cdaa3e15b940df3");
            result.Add("cy", "25edc9f53a5a30ffaaf5103a08e17662f9a80cf43175bd0b4d03a3e96951b3416f6cea82152df04f3a21e6d3afcb789de6f1c1f12941ddc918befbf42e9ec2a4");
            result.Add("da", "912c0312a922d0f579fb006f477a27929a869c64d4344ddd9e50370e92cd4061f1de10721aa17f19fe80342f080777755cb3c414e3bf2147ff6a1df9f3ad2f44");
            result.Add("de", "9bcd3b993f5c53e2eed900b0b1fabf8c42fb491198c9c03884a7c83f0d233453d5146fee4e05c80d0ad81cea07602b85dd2c45b556d0d92ad0787f291c4c082d");
            result.Add("dsb", "b24e87786a343c8fffef520b800e7c9985e97bc08da35a0f6b39f42d36efce21de9abbc5c6a1c2d0373e1cef8d5ffd14bf733be0a86a6cb203624449625c424f");
            result.Add("el", "fcc917d4008aa3951ab4da96992394a1f1815b04bd6fadb60bf6b2b4d3ac0e5038ffd7789772d68ec7ee37072b47de8be107b6a142b582ea42f16df81ee4d2e2");
            result.Add("en-CA", "f91ddd5d48dba30b04bc99407a784633ad2304b462ca3b42ab7e5f2c021b06a6c051cf09faa15fb1573893493266ce3824f6fd878f91f1aefec49479f4a46176");
            result.Add("en-GB", "f12662b2b9c0c6aae2dbbcbfa58d45833c4eb9ecab19573b42632b7392323dd6689c2949cc8694825d54aa95ac720a8f04e7276166f37aaf4eb8cccef7912101");
            result.Add("en-US", "8e80b4317ea80886f1290c17ee1c1f1a04147e9bda797e4fda03ee9415d2a8880d5a37db69343a672f6919fa16f27b110d3ac070ae25db7432edeb22bc9bfcf0");
            result.Add("es-AR", "4bbeeaffb7bff2d044afafe8b9d9844fd3a798746461b185eddda8d06610039fc5ddfc116f440a284466843a89b032987b61032fe0f93ff887b83efa647b468e");
            result.Add("es-ES", "606e466cd68391ce4c212f66d0f68f3b6a7cf2552253ac5901885d0818ec39c28d2a124978ee160435fe84275692b8c5780a54d1e58a9b84696e6e9c7d5e4c08");
            result.Add("et", "6db085d8bca53988858fc5b8e594f2afe9b8af26ca0137f440d893adc5986baa1180db8138ce2ca8f9e660207ca33974214bbe1c62463a2f1cdc54f298928454");
            result.Add("eu", "64296a23cf24b63c13e2fc902af6d1d8dd17ea6598a71222141b25919a9fefd478917a196941d48e17b16bb5b169a2747b6d36c1b601c7e440982c3faf064018");
            result.Add("fa", "224638082058ca24f08fcba1413358b379d037e7fecf0d340e56b457d3f038a522351d2ff3921eee4cfc7511fd2624a7873c30ae6e86dc7e29a23b334ce4cc9e");
            result.Add("fi", "af61edd452c5923bdc4bb5e96bd6a1cbaddb6cd0e01816fdec8e5bdf062ccd6b15854be75505f13188419b47b079c994279f998c9a8f6563eef38b727adcba5f");
            result.Add("fr", "0d43b22e8408d635bfaaed227baf189d27f53a65d21fe20fbfae38c891fc98df5b6b0e27d3acf2ca9b85540f0134267f0d3396b914e962c80c46a8df9ac3d20e");
            result.Add("fy-NL", "bbf84b9227f93b6e533eb7251a06df07af69e2e3a94581604eff36d9dae597ea238ab238e8655b6cf3ab3f8a19b74b6f636cbfb8e05d305a9530fd9bce5ad5e2");
            result.Add("ga-IE", "60f64e0a56e9114d704e465fb971e3ec72aac4dade9d342248cdef40157a4a6364ddba4958997dfdb2d5a6f0411c358bcc74f8554a776ebad789953409ed693f");
            result.Add("gd", "bf95072c2e1568a49997c7cf1ba97cd233671b358231880a9dbe3f26570400181bfa8ee8044f49bd0e28529ba83139ac3dc23bbc1a397878fe507367e02179d2");
            result.Add("gl", "b3b847d155837bfc3037a68c65796a2b627a962a8d5387b0533c51ec2e174c5c397fb646e8d2341af3c194a5c49a2ab4eb534885c9be2839df77b6daaaee6e33");
            result.Add("he", "5a0694a29c6bd1dbc69fe487a884c7e3caa55a0dbca2d822c61bddec6bd40db9f5bb84c7f9d89d36f1fb364fb9ac1ad6208e9eaea5f8301c95bf11a9b53dfabc");
            result.Add("hr", "eb515b92f2d4b8f2d4fd085c3c506e58a6b8fa71b6467ac5ba030a275ffe6197252aba3679fc86a53cfae3da1efe0237781a6a4235668712e83b83d0ae0f93dd");
            result.Add("hsb", "6c17dc2b1ae60998f4b16234e5e3d719bacd13d2aaea7f1036c9c59d8b9ea04339282983acd61e8d4ca99fc9be4aa5a6b72fb1472d358a04ccae8348189bc070");
            result.Add("hu", "9979999019fa163c6d63b3e1c8d1a125af77887ed893a13304bd8715f6c5545cff54616fa9fde05a6203771c0a15b745d68bfc54290771217c0a88f3bb9f5666");
            result.Add("hy-AM", "230557cb180c4b7b128bbd0920179ba9e8877bf2d148e8f54577563514aec55119a8ba1aa87b9847b1ca10815b545da57286b31c24e283e9f7193cce7b3b6be4");
            result.Add("id", "316defc61f138407e4ba0e860712821874d65c0c43da015b0f9906e86e2dfe2fa2081691bfab264f01289cc8f19c0c5d5cf41d155126ffc88eafd23184f0a59a");
            result.Add("is", "1222c2633a93cb521016fe2517cd7cac838389825bef2c65de74eb72602f4522b4f247382d966626cc46d433d1130c6176724aec03d7a5352113f2246eebfb58");
            result.Add("it", "e37cf75f264c283d2b27015a170c51a6efaac3026794247cccadb41c7bc29a2494a81a614cd04025e8c1b4175c5608e447a9d622d8e521e55a30875a1a534864");
            result.Add("ja", "821ad3275f2b614061e1725593c1a95e6c5033adde97670c697f396d8839e4215c5482b1780514fa40c5cf3af1d6ae358cd9f0a1947a1cef4d094033b73a991d");
            result.Add("ka", "8033a2f906d735852c2bcf06b06cac2d9f2ff7d4746ea0b7c7c9521f73d64f8f5fa5f626a702fce0653d9368b2c89bfcfd25c654657ea15f71d20a39341e347b");
            result.Add("kab", "c5158969f11bbee687c43a761d1bf7a9c4f30568a0ab9d83639e6bbd64d8a3b6a3237b5a94a3ad94d98fc494a270f839e8cc2a96f5b4e781eb4e8b0d077a46e4");
            result.Add("kk", "3ba6ef06fefffbebcff19359a4ee5140948ae6b492672332b25b9c48c59404c8fb07ce330f46f24f638220f32231ac9cdeeda71b4b9b873dc391f524c4f3e878");
            result.Add("ko", "7b07233d6b20dc8142c4739ea7a3338fea90265637af183de05771860ae9c740438137b36c71cd6a1420c12e19a43f50c8bfa1fc8e7d1b5b25eba1de345b41aa");
            result.Add("lt", "dd7d39f6c65f1a9e13994e37961862c2c4f3cd7113246e28c8b43935af57343c5ec2d61bd801a98b28f5128ad6bed10d022dbf3c00057d361c5d49fc456969f6");
            result.Add("ms", "c5a79fc49909459a6dd6bfcada7f74ef89b6620ee47a85179cf06348fb476f19f490583e46bee1a546b925d2db022396acbf184ccbcbf0a1b7d92e3586c83cf4");
            result.Add("nb-NO", "4060d9105e140e623841016ab4d46fb51541c616c843197948a02829cf2abce800ec02ae6432726c01d1aaf523143bc93c64b85f2507746c2a1ffda227987b14");
            result.Add("nl", "4e440c2621ccf0cc71a983e7051d4919c97bfaa05daf6e4ae7d86d91f0c085fa403afc4401887ac13a32b6033fd22646da7b2fc4fd6d1a46c2ba881e6074f929");
            result.Add("nn-NO", "9e3ee592f3ca8a34119283cef94868ede1fd6a75accecb5b844045db6153eb6de639810dcf31724fe50143fec71ae19d4e01baae0f86c8c3d7aca96d0e4138d8");
            result.Add("pa-IN", "a982110fb5e9307670bbdeaa9c328325ac314ef5cd5d0185bdbde559eb7c3c4d4a7b7fa6089f43692ae1a5c7ea3abfb9605769e4ecff6d23b9ca151447a8df58");
            result.Add("pl", "2b002b4cf51b4ad4bfbaaa36ca87eaaab5cb367a3e49d5f07c448c5f19f74c8ddb27165f0beeaf29683e43ef947e88b98770996577e42bbac3bdc77519df6639");
            result.Add("pt-BR", "486bc7afad2ec9a1d161ff565892e2e8216f70f9664797883baaaf20870852104eb6a821c79e3621c440ef19cab777a7fc275f0c5c70de98016b22948c5c39e3");
            result.Add("pt-PT", "681888d0cc0085008053b82b35ae8387d5203a38cf410ea836924e655786ec4092bdd5fd1034f388ed110cb8d0695a140cd81cf993432eb397a01b5a0871c948");
            result.Add("rm", "b97eacbac193ffa4e25acaa88d99f0b28871b100478b18a4cbdccc19b32d09ead7566d25a6dc2f8f07ccdda5f5d1ee4e69327537b34a27a01fe141196f6d331a");
            result.Add("ro", "38c139a8ea84f51193fe70b7b913f40749a2461f3ccd12b7a80d8fc45dd5e9d28f7adbda9ea591dc6213ecc3e792e3bec363f5a5880752581b5e13187e254624");
            result.Add("ru", "2d48c16c91eab0e0bd423b9299fe31546b2879e4ef1554399bca41f786a4e01be0fd6196a64b5fc06b1eb5eba40e9d6b0af7f7fee6edd5e51b5e4f7820ae47f1");
            result.Add("si", "e7cbfd33afd0c3fbe21318eb9fe560ce1607db52b8236da4ac06e1644fdf3718d85a754e713a2e99a111b62f40cfa213c581a4dccfc7492147ced9806b531725");
            result.Add("sk", "20a65d0c53c68ae0b6dd4a943794cd3229cb5f7b5a3bdcf978efca17225652b914fca6788d8d89536fed065ba50805bca8b8478308430564cac3c94ae54de39a");
            result.Add("sl", "f7c9d1a54329a5b4f5dafa815bfe50b08a8dac4406dfe076fa51b866adfd3d45305dc843603ce5eefd63c454f17b231246073ad0deac9bec1745719f4ad67238");
            result.Add("sq", "bf616b9614d51ee1a503fcb05107ebc5c0abd2c27342e83c6ac122958df3b679e81666e6a7353638e6cfa16b8d6e87258419fa921c51e8e09c97c730ef19636a");
            result.Add("sr", "08081c64bfd5d5b79d2555235b4bf056f8c38c436d8b895b14a0f13312eb706fecc71a317169a1a03a16537882f2144493320cb9ae93d8263f810840e927eaa1");
            result.Add("sv-SE", "7178ba95a2d1be757c6d32e49cf760013e49a781038a99e44e739d8e0f84debf50c5901b28ef368348a7c8e7f8141fd272504aee652ddaf5aa61b1c573c238e5");
            result.Add("th", "15763ffa61728f35e8db1471de8e2b1e5d86813d37daff0aaa32be31b2c8eb596b9b75e902675da094ba620020e0930ff4abd0314a12b885b226d0c40129005e");
            result.Add("tr", "886365e0f99f0321846c0938a67698957609bf29f842f2ac5a21b1479cdd28c74ac9dfa337818de3701fdd73d2d3f436dbf701b89230119eb6c791a11f2674ba");
            result.Add("uk", "35519b07177c20434ec645d3e82e37d4d09a292326b55922855e7feb2caa6b4c71802427f4983f065331803e9641ef6a82082a8dc63ee3770321573471cf868c");
            result.Add("uz", "9c8457699c08eb50d1a29115438432899b332f09469ab714145a6b5170f34bea628ead119f974423f5c56fd2c958cbb0af1c870c61ac00a97a9abc99a0786516");
            result.Add("vi", "490d0d97bf77242e9cc5acf35999928b1fcd7a2fdbf9b719faa27390fdf6aff32db332c2c6153610f3fd359576a696279ecbfe7f7e1dc5f7431fa8c992ad54fa");
            result.Add("zh-CN", "61bbb7cabdc0cc18bb61c92045a455528d19262029207dd145630428167ec435960f31e094f890b03a8bf438629cb00319cfb1caebba950f4a7e3e5068732b91");
            result.Add("zh-TW", "6bebf216ef6cb35ea2369cb508ef5312b7deb12764cac92dd00a49fbbf5ccf9f957946bbef420da778dbe0ba507d0edf9aa9d50daec19ba418e3f258ef9e0f6a");

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
            const string version = "78.2.2";
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
                Regex reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
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
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
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
        /// the application cannot be updated while it is running.
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
