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
using updater_cli.data;

namespace updater_cli.software
{
    /// <summary>
    /// Firefox Extended Support Release
    /// </summary>
    public class FirefoxESR : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxESR class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// gets a dictionary with the known checksums for the installers (key: language, value: checksum)
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/52.0.1esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "718dda2eef3eec5cf1a84fdb79e64229d1f05b9e0031484776ca55ddbba120c40859373d82589b34cade3ebe683906cbf7f2cb7b310458b0e483d1df477f496d");
            result.Add("af", "de3b9186a1181cfb2ba017cd1e6bc69212391e8bf114cac05d62165967626db47f86a6e4f9cb410e772ea56162d80f01010644191ae72cd3ff5af519640d6fa4");
            result.Add("an", "699180813750966d61b63c18ea6de7ca679b5f922005aa2365d51558528a59bd432e6f420de541be797e40017c9c295b340862b54a17c053dbfdb3aa5e8fead9");
            result.Add("ar", "02c82a81bc04839206b681ae0589874f5b75f1bf6072b94a0c8a3f258c5f9202f4993bcbd8b773b074eb90f329200ffdb46d73883226c775b6e2c3abd41499bb");
            result.Add("as", "d4ee7378df5dd10b054df8bc2fce7bc9b600aa8c08584765dd826313d461a7b2e425d1370dc4eb868d6c4cc4c09748b4d5535265949078dffc8da6c257a9d313");
            result.Add("ast", "71621282f9d58227be0ca47f9d6ea4ca454af91a14ce0446e1050cc697f5094b7b4cd1f4b8cf1a5993f7ddc3a78aba7685d33a99ae6d322d8261dce6173ca3bf");
            result.Add("az", "4a370fff363ac9e48d5c719f438884a361d68790584642635bd6b98e0012cecc2e2151d0a89139c714eb7d0c3d47d14469af00ee5abe0643fc867991a94324e6");
            result.Add("bg", "3187cd208cbcb85f7404a79266a502f240add38f3ceb232a15e496c39668434b29ebd5a48e2e2b90c80690424ce44418c8ff58c875b8954699a72f25b2041e4d");
            result.Add("bn-BD", "fa419fe4900148c9c91871584e28cddc9d626eaf87109bdac031df45a5ea94bf8d67dad613fbfd46ab8e004cb240ddd3804fb9aa4c56a871133f81c95d776fce");
            result.Add("bn-IN", "482112654563fc45f79b9d3eef48f4c37b51f114ddfa6b84da51c43cf20445285e96506274951476e13bbde9e0bd5a5af68ca5938e23dc27c93d1351befa890f");
            result.Add("br", "5329d72a1c64f7380871e2e9e8726b50ebed4193611bbe3dc7d7bd4bc15a2ee126e736ad439cd4c959761e0cdd733686d2bd8726ca06a7c2616630b0b3a44f4a");
            result.Add("bs", "7c4394da1a9abbf7dacbc72f14a877e673dcaf6d9d94ca806b706f40b2bcab0f8e3a1f556ed5d2a1bbf74f8f7609b0691de45d138260d4e86b6f0fffa8a7739b");
            result.Add("ca", "192b895ffd11e14e56187f53bf8ee943dd337b6b580054b3f7a2ca4e04e626b4385a85d14e9d43ded7a374ba22ba3c663c80532014c99ce972d3c2d5e9f55b56");
            result.Add("cak", "00a2a64375273103f6250e4e503c5e025b07335b5f034563d9e757b3e5e098bfe7bb318069dc43626d7da1d6543f6ebed05c9c89399a8227502712abbcf71e0c");
            result.Add("cs", "489508ffec91a2e30c45c4ba7ce8d1236aa1e1325a0d6f8fa6afb99dcfd4f6ea38dc6f8a655ac1d331dbdb2d387b4217b3b6851f7eaa362db381ae4f3eac9d41");
            result.Add("cy", "bb4f646562076b8ddf17346386485b542c13691cd59ad49b835ccdabffc0782f382774e3e69686e3a8ea26896bc2ff2f9e737e471c5b8712942ae7f64d61b12f");
            result.Add("da", "73094f24fb6fe78f448921145e06438941775163cfa8189f6f2682dc0d033f23e01ca19290b48a4ca72104d3b42ab898330e28d03167c51eef40ba24c19d3b01");
            result.Add("de", "bd938e74ba221315bc18eadd974e049f33a26b0bc4f3a017f82e1926ef8219a5f114976d6e8b6255a77356909e0ff2e54b6e9bcdb808f6be14707eff8f004fdb");
            result.Add("dsb", "5482a27f2ee6991c6d6815fc2a23856a029236fcb02ec5619707e3e2b43005c551bb0d29c598855c3b81c7e132e4803e38917410cbef9f492ee41d5b54d4d863");
            result.Add("el", "b06e220f43a0f7c626263e102c2419f2f51a60c8c05b4d6c9642df66f8c26b0612b6b93ee56ddb27f70bccdd3c68571f5cc10c6eaaa3a511adb38cfcf0272806");
            result.Add("en-GB", "5bb573055f2021b01f79819eafb019460c6fe9ce397943bf1c25e16c5ace4949e606236e773248418f87dbf114d46525494a2dabb7f820322322d5e199e98eca");
            result.Add("en-US", "8fa3bc7dae932311b0c0668742b59710c55113658498862bf32ae36f1067b7d309919095a0f1dca5c5761be3f2a4e25a708a4867f4c4402da798b5ecd250b3ca");
            result.Add("en-ZA", "e1e834df64c1c531a19bc38947f653be5f64765b6a3ee709738baca672387c98eddcea757251fa969b324552a7f79270b48947652180719c2ff85b67bdabe1a8");
            result.Add("eo", "d3264acac47f1942022303534eb6adbebd3f0d6fc9c8c8b433e6bdea73ed15b6f0a128a61c737699741aa73ad4976a45d740c248df74dd16db4fe7aa114297ca");
            result.Add("es-AR", "e2ef4b4b42fb5ee60bab6efb4c8e05754f0ea999719d3d12d6c0ca10189b7a57b036bd523007f3e546a12bbfde83656f44422d375b00dab0526843db929f60c8");
            result.Add("es-CL", "636c74af13e2f51b04611c7b7bbafab082eb77b601641ac5a3310f2ff0ab017e0f75f74a319224d08a6164c40d47427f270cc964ae5924ecd9720753ab2676ef");
            result.Add("es-ES", "73995b16a7e6a39bfd8ff604575cc79fad3dbf8152243a1cb965fa9a44b55176799b07752d9c4dfa0efa2e4205f6a79bedba0f077f0fb2aff677ce58d58c6709");
            result.Add("es-MX", "71712333188a1d9a2c27cec0f4ff97427d8b249a47fd51c72ecb933c0d88a0718b0abaf456de1cae23db1bb6496062fec83c56a31516a747bc0126e81a85612e");
            result.Add("et", "b4ce395347fcd6f1fbe7aab339a2921ae8a8a4cf102c5464c1cd90935c21db1f4f6293ae9e9893a1aa82f5bbac3405dc6dc14639e4692ac963f6195a097ee43c");
            result.Add("eu", "e584877bcabf1c8f7a4d6b6ead855afa4b34a19ea3b8c85e65daafa24ae83c4e44ec29d7336755cda00e646b52f967f2795debed0676764f9bc2c3690d7c8c05");
            result.Add("fa", "262228ddea5c5dc56fd2f1472ff1f2a9bfcf0ff36d6adadcac1b462038776aa0cb000a1916ca328f95e80e5792ae6a4dab0e059513dbfa2eb8cec19f882bd7e6");
            result.Add("ff", "077011dc95da129b82c614f945b3eb73090c035862260f0f2eeb6b8130626912832778606083a461445965039dba7dcb6b12e5c4c052ddc050d3fa5cd1cfa198");
            result.Add("fi", "b40e81f21fb1288296bfcacff4ce569415a418530175fc13f8dc99d76a297f98d516a25f6d8e698795a786deba752c1792d5b8e6a9f9cd62d714dc7eee6f22a8");
            result.Add("fr", "45e2d55dd033ec40e3ab290ce1086860a6dab72ac9ab613c72e1304740f3d64f59f2f53d5ea07247964da8ad08cab948418677ad406cfd31e8e54d05708ba7ce");
            result.Add("fy-NL", "d576d5f8147db18d06e5c1bbb2bc596a63602ad4e56d236c897b62b2284b98ca4237eb2ec917715b14331c28b94fbbb473f95a6cc3b205fd4401348693c05bb2");
            result.Add("ga-IE", "d61ed5ea7cce86463825354b799c33f2a800fb1455f6d7bbc5da04a726b273c790c32a8b4db2cbf536e89a86039c2a9387e4a756d173f84105e09ce12eea6e87");
            result.Add("gd", "5bbaeb378a62bc8aac3edb8f5c9360e6f9b06b2fc6a91dc3310c674fc896051c94ffbe8d6579a9760be1326a09c79a0fc35577c95f8174c6453fc2307108cd75");
            result.Add("gl", "1de957bc015939367191994e7ffba7795b57882f23e21578ba679bc2d6039c3d9bc58242cdb85d827f301ee0871adbacbf26fe5322eed1e334322b1ea6163e77");
            result.Add("gn", "6c4e48870de7d221c04fcc787ad523ee87ac84f65008377dafc8701300bdc3f337574e11a8b997b5645866a774770c9ecaac4ade44d1852434a804f6dd286eeb");
            result.Add("gu-IN", "f12381187ea8d2ffbe8bb48066609783b67a98d50d198be9f05a0383b9fc83d7630dc2372af08cfeeb91d033c35c5b4693ad1afe5699da8889328d97204046b8");
            result.Add("he", "919b01e88c7f7a63dfbbf0bed9897fe4fc54600f1ccea56c742ae891d05462d7b0790b391a962f2fb772d904cdbb46f83ffa5ee20c22090d8bd840f8fc0d5bd4");
            result.Add("hi-IN", "0b322ed01814241b9b5e79d144fe3854a335b2c1a10a987833a2eb305a68198699b598ac6c2455ef35523baecc41ff6f2b272fdc235988ac66003557620068e4");
            result.Add("hr", "53224f500d92690fecc8b371e5cda90e04eb169b202478c39d81ad2d916859b8cadef2c9b88892da44d4c27d4bb3a301b8c62398b9da0f3b406467e48e59f1a7");
            result.Add("hsb", "47b994f8f6b0bbf5bfff7233a4658f190e7003eaa4bac5effa1151571cb87aac8886ca965034d405cfe4d4fde09e918258dcd53fd5a8dfed09d186e0af5229d6");
            result.Add("hu", "0414ac99bc259e5b5d30af551e9d1faade36dd9e99651791cc3730889765f2a2d6f2a295a268eb78a9e115707ac6204b088323c9f466cb1213ddb22f0a857ed8");
            result.Add("hy-AM", "3e57a027a0b503e91802e1d8f558805784393a4e91cd8c6b1a89de9a1ada10dc7ffd79e917bb0139d2819961083b28985378a56993c01c9ec8aeac60aaf34d0f");
            result.Add("id", "42b747d684212cac801b219dbfbcc094c273542120892fccdccb915ac9ca9d4755a65dfa7320292e126277797d62c60303b80201af7957ebf3e7c9f69f44abc9");
            result.Add("is", "8707b7146af72a846cba870acb3627da90df22b1ef3d7af70ab1fdc5b98731416c9d5da216f0ebde70fabd153777408b372e1d178250b27d2d65ab99164700ca");
            result.Add("it", "739e7c53158c35e9183030e582bf5ac20b1ccf610bbeb94a87e8758b80fdbe6eb5b80ec90257e59e5a316d74c24a88d2248397585645ffb612b06a6bf30eb342");
            result.Add("ja", "51c178c7336ae555aaa175cbd512303e74c99c67511824c2857d12e3c30d1a52f9d3fe7dfc6d6202559422393f52f5169174fdf7b52e4cab5feba5727ac749e6");
            result.Add("ka", "6d1ab36ab0f6eca2633aef295f6286a032f9ce2ca658227c7192eb171f07aa0e72367ac22dfa00f5d5ef8ebc2165071fbb724a4d3799d46a9551c7751424b693");
            result.Add("kab", "f72e7782ba7c4b00c11495cb1d1bbcfc67a960f4ca81be1c9795ef982ab670bdabaecbc7e2103b86b3d8e9df9831b3ba7fd634d16d1bb209f3315e22af131d99");
            result.Add("kk", "623f62149358851bd8ac755422cac38b4a5bfd6ac961f760e4690c3dd38a570946ad994466c8a3c603bbe013e035e29a243f600861102eb9f177fb123ca289f9");
            result.Add("km", "fb0ef6556822d730e66fec4840c733710c5bcbd07e414313103d2cb01fa8f74f25a580e9f2636e082fc492448f8d284c8fe74b325536ab38fb422570cdc414a1");
            result.Add("kn", "be40e4d7e0dfa7ce3e4543a83f1cc6078c632f20d306cad20e928ecd6a7732b890dc54105a98a59cedf37ddec7c9c92a03196af055cb4e3639bb913b9d826728");
            result.Add("ko", "1d5f64240f4125957b1a98f79ddd82310ab638e4ab1f85055a7197a6beb58a00b600da02bf49fcc72a0880c0c2859bdf68fdb0ce370f7cd460d1c8465186203d");
            result.Add("lij", "6607fa96dc4e84d4478811002c6ebb4f0e1ff53424556a554099e89f5e21199cf1255d5db058869bca156eff311916523bec9b7155f86ab8e90dae110546bf62");
            result.Add("lt", "7cc105adbada9f704652a50e156907e0724a5a3311171fde593407cba17e7e385743e9168bba6b9cb28bff085fae3d2064888b5a0a819c96cedec47fbf2f3452");
            result.Add("lv", "d084c5b7a3a89b0231029db70fb16073b966baeeaf4b803acd50c48e572f25283e3f73023b2d7caa5475087c830779aedf38f74099e91d91d4aa57386c23a616");
            result.Add("mai", "d7d581361fcebd0ca3ec7a8c1f4518d3049bc76d8d200b4b5a223279b40126e99a9285a58a532f4b0fc7b6a74bf3c5679e62f7b9c81c5c771d43cd3d1d633c0f");
            result.Add("mk", "1214cafd78a1ffc448805f7a4a5253af696ab062626032c750f76fac1e7d68a027bbc2e8355cda50c4ec35c9c32ed54922ac0399ef6a670adee9167b92d5ec64");
            result.Add("ml", "0ccd45069dfda3023f7ab51b46c2cd73a148f923833874a33db1e763c211622a0c5174be2e2a0e7f75fc350ce0b98398e1bc19a66d51a7af6351557c24123cb6");
            result.Add("mr", "6f2e65f8f4505eeff21847a112252c5171dfdb132dbf10ec4ed4ff44f32e0642b853c11fef9da88979adec41dbe073be2559f433ef1c7142b2a31a7e33dc3a34");
            result.Add("ms", "594b491ad851b1eb1a89349738f05c2409887d2972cee97d779d2809fbaf9f2fb907d35d3d08aae4cd98a66e6c54a39e4cda966a0ddcc831b3a17c4b2d0bfd9f");
            result.Add("nb-NO", "7ea66f72e013f74cf9ebd5ed3f3f02780ab4e4df0ee1bd9395e359059740e297f3230155a51770ae5a41b66eea660a76923e1ff613381e534a919016dd165b05");
            result.Add("nl", "86247f02b884014da003954d59fe347974b5e85e19e7e62353e03bbfd59e74755913f5bf2c19d6a5945a4dc0ca6aff7655a15b7b740dec98183596eecc2fdaf3");
            result.Add("nn-NO", "8ec3de922a3aa65a2c544fe56bf793399cc6bd0639da97702e4ff18c528a83276298e74b1c37fab04ae6cd67a07dc64f93c7448743b210614030442b8383b34f");
            result.Add("or", "e0f8ed91ae69a8b849254c23ea676939a8364f457b8374e5c473e903c379d802e0ca23a55073f598f7fdf5683df58bb8847fe6854745ccd109313d052bffc624");
            result.Add("pa-IN", "8d0ea9c0e61ac1811b37bcef17d1bf1f865845f22d1c5751e65db4645fd70926387b0e65efdd42be4c062c46f8030969df0423aa22ccab063f47ab6c30b073f0");
            result.Add("pl", "be538a6dcbb07fdfcf4b30ea1635392c052d5ebc53b248161d4fa1d5b212c94ba756bc8fc839b57d61936828511e8813ebf5a62e4a9b0836ae9989ea34d49a7f");
            result.Add("pt-BR", "b933e9451dcc8a78aff211ca5630426fdf248842b8a45eb14e6a1761b4fccf6654266bdfe68421bc449d34fecfba07ce983de3c380a50b4cb19728815296b852");
            result.Add("pt-PT", "db0b2d21dbefe7fe4aff3fe4b6717e756ba70355d9368412e51f864c3b0b304c083f388b279aa8468a6b86b646842b455dc8b2d9d6caf65aa6530de352d2e6a5");
            result.Add("rm", "aba87561cbcac5205163dc8b1d52eff86703911c72ff3f2c072db230b7d1f54fd1b4a8267b714952c0f9a2f1902e2ba7ab92f9c37c19343185c7a1ae4e1fa7f6");
            result.Add("ro", "7c611f67be1722b1c09f67365e430264fe17ade0377030700c262800d72417a8371c7d1210172b967afaab10b66b5d8823098fa013d904232ceb5b66b5c779b6");
            result.Add("ru", "d93380c23d99e2fcb2df63d27a9b34137e55f30db1278e45e4d196cab0749a365d83682d13e2398db4cc8f21d5b9cd40640fec3cb013a33334fa177aed21202b");
            result.Add("si", "c55811a536d450290bc931c2041f76c7b918048ce3b4e1e7ebe269be618f8d3b594c6bd2be6d9361245787666ae1256cbb9abfdd08d6684fcf20805fe0ea7275");
            result.Add("sk", "49794db5af75710ae478d74d1c6b6f6ed4bb8c1855b6f87774475b7e4361a7c53be17e3bc22363a60fa753a9a2fca242702a6a6e78b7e052ad4fc1155a1e73f5");
            result.Add("sl", "a57c98aed4e76f4cd10f81a6acdbb0e95034e4fe496a230e964aea4e7ddac26951bf5b48defa012fc74b103f3929ee43901e1aea892005de328a6dfa4b900d0f");
            result.Add("son", "f241f2ac8fa4fe8f4bc6add869698a50066162980dc57934859ca65f0a503c6a595e025e49a7acfe261ca3a1b4ce33dbe41cd1e2aa21014161fa59029ad77ec3");
            result.Add("sq", "72a004cc6647e16610731525c58cbd21021c16842791eba08155f49639340dcaa0ba433e7207ba7a1dc10b6683a8d3089e3cea07475da74cd621bfda90992f6e");
            result.Add("sr", "83ca8872be5400c3def61c10f57e5e30009b6ff664bbd240f16b9e3ab14d43ee835bde6162150db428c8859e931b6aa47eb2160532a0c8dfd680018d113b7fde");
            result.Add("sv-SE", "7c5ab8d021a4b5730a998c16a42deed91f6ca7c566d65c1e1a4296d5c317a75223df194d7156ee6f1e3a2b9dbcceadda7e4743ffdf51d39c6da6a18eb28f65ed");
            result.Add("ta", "2325199701dc46d277552838de384e51d02f91670de1c497579805d70fff446c83c0ade3bef266d907e625bbe5ab736f16cbfdd2400866c6c08ddfbca0558909");
            result.Add("te", "159ad3d877304663fd735cf7c6da182de76baa8807a0747380b8012443527b5bdf2180f093ef2aaf1119c81b2b770d9e419e7d8ffe9ea58a5de23d48630ca0e9");
            result.Add("th", "903d2440a650aafd4ee82046c3a257b96c96dac975187e8c24f2bed2b9aa59d9bbcae2c6a8a7df08eb7c9387b51de1a97c438f4ef21ca07ed7ce7092de25f6c6");
            result.Add("tr", "a3e9bb10e18192e190ba26e2c51b20d45ded2a01ca0c31d47cedfd64e9d2c8883e8909321538c01af019719ebedb19d9113474cc52e35bd727a5a7b316b5587f");
            result.Add("uk", "5e712cc7d67d4a37011d4e4f6154d4f3ac299e274038c8588c49cfa6b5f27afa9fa04a6256e0213f2834fd87bf7bba0c38cef078ab5df090f1b00854bf5cb17f");
            result.Add("uz", "82ef522acb39b35fa7642fc853daab20a9e9776a7cf4e27fe0f22544f8e27feba4d2a606131646a1b8007b945c980bae5635003d410fd6f6587811c5263a584f");
            result.Add("vi", "bc4a7fa4c15e88dcfc14bc91646a6a3235ca0220311b16487e772da5f5287e253c58c673a4b336882b24032f7c1568b7e3f512e91973c5de6ffa507f5cdf756a");
            result.Add("xh", "71009f25045009a746dc98fa518c360d577f7cb0dac228cb1512b34c7867e1c0f753abc3d26159e2ffcb9e2c072ef9170f9c4f60b198c82c1453d172b3fdbfd3");
            result.Add("zh-CN", "4fbf25495d17f771a29871df37d36a6e693ee734ccc67bbd2044e49aa7e6d9985056bdba275a1041414f21c1b78a65ad33ad2963e6389b3f99d9ad2377892cd5");
            result.Add("zh-TW", "da39bb7b84090524bcd097ce939fd70c3d426f88e64c56c325db337f6e6c3d1c332897dd0b3a8dc5b9e862d1a03bf39ea5153e568202e878fb01b5dab4e75499");

            return result;
        }


        /// <summary>
        /// gets a dictionary with the known checksums for the installers (key: language, value: checksum)
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/52.0.1esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "73dc247b7623d6b66e79b9ee11d3520650b1e3b18e3c6057930b09bdb87cbda44d1634f5493c02a87dfee659533d9c1e3d49c12eaf31c9e309e682080bcd4bca");
            result.Add("af", "270777e5c6c3f69acecd4656256f9ee9b45025c21ae3fecead74abd95b9651e310d9823779c4e255c5299f76706fb517fb3f8dd2cc8606b848d30571c4db5f0c");
            result.Add("an", "72242ea9077d607e4976bdfe5cb911c6393363c7b47397fac96c470bc58b8ae211cc661ea82384d740d861f5dc304992fd99a4ff2fbab48f41560ba52bdc0761");
            result.Add("ar", "f92387fba149c755aed76072053ebdbf80ac4b27623127ee85ac95c3a6ceb82f23f5da22ff3fde1cbea8b4c563937d1909bb28c4a999faa24650d454532b3a61");
            result.Add("as", "2fb7538b99b7b3b593d76eb4a25fd8733e90d57e3af820d3621657dff0f80af5101615c2421eea4c147b6c1179d080b9181f0e9aab6cb297dcc6bc24a957ef63");
            result.Add("ast", "717fcce66544770a8907a733179ead0c6c5291e747437893e1689ebc17a8034cb7b199f20f52697deda7e72c32b56d8df0c41f53b7c92a96295e9c7ea067cfd8");
            result.Add("az", "b9b515d2f356c537f9fb162978757e625c4408fe9c072cefc542f21225826411439458028dfbc2cd1b19fbc597de9254aad118feb8b4bc0c09c89ee6a6e65887");
            result.Add("bg", "d447bdc8bbd3647dc5241607d02a8a2d824850096fb076d532491954c9c6e3642e5a0ae20cbdbf9fab73911e0beae0496173811df6abc21075bd85d1648fc517");
            result.Add("bn-BD", "0cfec994aa497e4a6db07453511e436ea3ddf3edcb3218b16bbb44f045fcc1b0170d974f05620cbab2a49369456462b292143e15eb5397a9eb67ca0b060f14a6");
            result.Add("bn-IN", "54a97bde1a721850ae32399d2cc5c290a46f82dcc8fc3e86a004cc7b3897e16cb02d089b6b221df737824cb3c08fc903b69f25375ab860fd476275175202b7e5");
            result.Add("br", "658396d89643b0d9006476fa992622165f2c3c2971c0741d223693aacd6637d5513ccfa6be7f17d95b09e5933f2a448d6436e341ffe2e5f3632c50a4042090d4");
            result.Add("bs", "3820499c2266b1d1429f709680eae399cf1c9746778b990bdfaf45ce2d564241231c1ac7c8f746a95dddae2816c72bd2dab96229974a83afb65e5d26cf847aa8");
            result.Add("ca", "225f6120add597e9647a247351aa718f0b958d267c40e27eb5baf39c606cf94bbcec58e49cd1199527c21227b8a2af7c873ed5c6166a252e7470ecfc2be26341");
            result.Add("cak", "03203aa9d4c088ddcaab15388ff26b23ac7df9dd84cb77a5206a75d3c61eca34e280a4ee5fbddfbaafd2665991eca74f87a0014eba8dda8f13511f4aa7b58ba4");
            result.Add("cs", "043583b1d51bc583a3bffc72e36834d491040214f98a8ac3f8436360ebbc5e5a2459a50582ccf11b0a835030051e90c1095756dba491d1124e6cb4967acca0c1");
            result.Add("cy", "a0ba3ad8b584fb6066ee6d0064e2c1df88cf3c5976e57f0a42725ff14a82a0d4d1819646e39e21134cfefc1a8b54e319cb8364ebaecd7a5d0c392a8f0dd98b03");
            result.Add("da", "66c048eb9bc7f45ae04b5973fa468b3a5af0c8affad187098e7644ba4f6e066f086e61242c412aee7c25bb1465920d0c389b36b07780d9b89a8faaff775f20e0");
            result.Add("de", "44001eff0ad6d79117e28fab243adcf00cad319a782f11d6b7e62ec5ac31b2b5aabe33010f62e080a010e851d27b1e875baf6f2cc6509e5c99a4adf015a97098");
            result.Add("dsb", "cfd5132ff5b4dc4bfb8a5402ca9071b29e6896be111e583977f9a47e344a6e2250e7c0e59e28b0def5cdb454b2deb543cab588926e16dbec847723f2169f44c4");
            result.Add("el", "e4cb9215dde7d70411cc4e4a6aa108f2833bdc2235517d8d1fe89a3c199f2ede73620d75d32beb826a4c71b240214ccffb691aeaf73b865dd5535373e3057579");
            result.Add("en-GB", "21ddc8470e65f476f85f76cfce63171b0b87ac5edcea0d31b96f029d596af79b23f5b22e50fcee36907472cc2d97c496bb065a34d27852a3af38b88cb751c599");
            result.Add("en-US", "d67ac010abe69b03eba46cafb36b70fd7e35da1e2db5134486c88adc3296e7522042f8a2794160e482c09a587f7a77163d546874b4ec3098bb7dc169a666718c");
            result.Add("en-ZA", "1e5a7b2b8f4046233031b99f1f0a72937eaec96c85dbdfe6f096793ab60911f58c07c1278db39544b9dc425efd5bb7223036e9963df6fcbbf4c02845525e1117");
            result.Add("eo", "be183657cbc94dc89d0c1772a90d24c3ee553be5b1b564f4d354b9ca8f1ab6b663bf5fa56270f3775fc072374b986dfc0f95c082fa6697f99b10ca1f3715a9dd");
            result.Add("es-AR", "a740e768525ab3557ef1e452131f19612952cae90d558e5138e33b0f9a98dfa663031bb306bb4f5ac9c0aefd0ea9f47bf8f10b322c1f3c34dc13d8aac6d1221b");
            result.Add("es-CL", "fd8af3b3b997d7b01b3cfac242660dce2f4be8fabf36359cdcdb9aea5341ba71fdfe3bbd228578036566cffccf91fe066a7ed96e37fe626ba1fb7cca820f7330");
            result.Add("es-ES", "2a371762f95d9ecef990fd21c1b35fbac3171f73038a96dfbc28512d6856d2873d27bbe8fd61bbde44efb70fca1e7f3eb44cd231de141ea4e30adfcdd4be13a8");
            result.Add("es-MX", "ffc0f8931475be2086c907c7fa844818328a0de0fc7e25fadf85f69fd728237d057e6a09cdb9d44856425ad26c2b5d88d9dcf5e511e43e406e2e75d499fbb872");
            result.Add("et", "687bcbf5cd4464fce387e20ebfea7b8fb8f96175b6216ac459a99aae714e363654ad15bd80691f1db55ab5610f745ed4bfdf5f3c01348efb6af155dde7788ffc");
            result.Add("eu", "4056b9f49b1bd07020666559d5922f36bfe11fcf5c3f53d414e88306a3c283ecf9925e8bc86c6b3cea2f871cc20f25dc4e5e26c94cb90ce867f697c44bd70eb2");
            result.Add("fa", "37d771b38b9380a90e14c05d4a990f905ee56b8f8653bbb16801225a9b917f643b6d4200dac091f7a5f294e326424af1bd5df8736b07f016f73a6eefc79a4b1d");
            result.Add("ff", "0fde06781afffb4bfdd969d0bf117fd8ae8ac70485dcf11153fd2643db2ce7d2e4c09668991ad96986e821ca29db5d52e369a24ff607e31aee403bfa4362278a");
            result.Add("fi", "1dae862957ef92b5828c4cf95f324b5f044f8872c500ec9aa063ce96894dde2f9f84866b71729afd0c039c718d37c616ed39bfafb039072447b7cc6143679cb3");
            result.Add("fr", "8957103571a202c80edd7da90f303f09c5410fa90fe83fe9fbdebae486da7511ebb7d8377c7d321eea6f2b133e30d84412212f07982c351f28a86be343ac5a08");
            result.Add("fy-NL", "f8d256f9deffcc23da94702591c21692d81b4dba1d2cf7890ac8512f1a22577f636875e3cd8171825b00707e8795d9879745f5bfbea61a13e9b5a7263e511209");
            result.Add("ga-IE", "4d98d18800091f455df77189b28cf084f7e9670921cc915362fd88cef2ad23c6ab7357df047babb246c17b5d119c48b6cd16fe85e948be1b273d01104494ab35");
            result.Add("gd", "a20485c06c14b67331aa9855328c897acc4535d7fdcbb8708551a86015e30e27e0bcb79b107c2a269f4756cbf5d2ac474fb12c499b739a510b71fe27e47f039d");
            result.Add("gl", "c3804d0570c856fa72d41129c22f75d3e23513609777dfde672f66335c880bd8321ba84b0bd42a9e25da3ada362fd27dba98478561d0f68c8f73f5d0a82793fb");
            result.Add("gn", "f15e5b7b514ac39a5d19474bcf9c58632e4e4b599ead5297a72c67ad6e9090d6f13ec4e2a58d27151e18ec3df9bffb91753bea9ea1ae7956b5b1bc3edecd01c0");
            result.Add("gu-IN", "8438c79a4fb828081a34cf603619c5a27ce8df5a0820fa13d14102817b8df5fe2267d84c0043458e264d3d974f0a21f5277284ac757b90cf49e660688f8e4b17");
            result.Add("he", "f7f89cf5c2d3544aa8d04a422f7b30e2b9b750bb6820a808d949c21b0bb8a36e770e1e052b782be38efae328ff0a5e8c6696ed6a78adf2b4a39bba545f9f411e");
            result.Add("hi-IN", "a9e3980734ff0125fbc457bc593bbb09255e02187dcb43056e5dc69bda16fcaf97da70052ece87584f1674fe185fbae042608b36b4e24ef1b9300486a0bd0b3c");
            result.Add("hr", "1903dfeec3973b66384ae42feffbdd2266435b5ad8d48e7546a600ec57394286483cf3123d287700dc1b4837cae5546990c1123d5b555b14c53f0aaf35ad8072");
            result.Add("hsb", "9ec99c3d0cf4089bf40c79dd38cab0156689355297ace7a2255cfe2074bf180513aa92d593ff33a97fcb1cf618640a87c2797bc8f0b1c1076146b6e7ba5b98d5");
            result.Add("hu", "cc4717f6ba39a74a5834f0db56be2988d2134790bf0030a56b5628f9b20beddaaf6407fdcb2b27b560c081a19a0c6bbff5d39f4877d616749748fbce0f8baecd");
            result.Add("hy-AM", "31776d8c293063cec584982317d89b88192164031f1c1753f2102ca8b8f127faa494196afb4006eb309fb08bb1e4f7798471bd859a964e89507c04582a5def97");
            result.Add("id", "6bf48c98bc6ca83d09e32f6c35e2a2701af6681dd41b990f2bfd23cc0447e8e74826ec82c3c7f6f37d292d614d5047e61b3042396e8e6256269f0fbfe5a188b3");
            result.Add("is", "e0ae5f3a469dd5691847948af5475a289052c0199a8c8b246feb3e9a325034bdc2c784ff73ba2246e5f74b5f24e0b862f07a188af4921cf811ffd9bf7a2e0d4e");
            result.Add("it", "d609197cb8c8de305e5fc63697544cbfa3c7306d74887267a6bde2e49753e14d838c300b822f9c3ce8572ee93786c6f94e8ed7f89959331b0c191f81687a9bc8");
            result.Add("ja", "d2d5a5057a303db629724e1751a9fda02d6fc0855cc8b821f3ffa36b664084767026b577bbc951c6d86b4ab1742123b5b3d9ba11128178d02ab527aa6f0f82e2");
            result.Add("ka", "10f6ed8a094242d051ebfc38400ec35688bf86b6442aa419b247dd6f9f5b4ddd9d1cedebd37c559babee9c200b57ca979c7265dbef9caa9c6a3115d86ac104ef");
            result.Add("kab", "4ab9dc92f1a6478102dcb7f9cca27b14ab7d9d68f271251ef6018d734709a24bd094666ac4db08bc2980d6b7cb7fefacba403d260432dcc68767c987a71b1dbb");
            result.Add("kk", "2569c376f2ba74ca446819d24f890a40cf3ccf988fd971a2f8093b0dca73f7c930b7b5f5c7b01992679d0318283d05ccb7ae8d1a34792344466a99ca02b1cd2c");
            result.Add("km", "f9879e55d6f2054936a96854d0c2311f796e1f73ac39e5b9e1d40f86713d4abcf7249e49abb89ce08cfac7956bf4ad427df3c68f86c343860e97337134486e51");
            result.Add("kn", "9ac8b9a5adb862684c69e6b05689da46bc6e4847192c57c9273869e733f88cb6cc61853a3e820f0b4eb1a0c10841dd27c9671cfdb9c27a3093ad242d934b3271");
            result.Add("ko", "51c89bc2526b429064a4950962e29ef30316ba2ea675e9fd92653908ed2c1e095cdcf1548f451038602a40c18fac634402f22227a4d90f18a6cac5f1540811ba");
            result.Add("lij", "d5ea4f7a9fe9392519ebca5dec53e9ddce44afbfb478c0289be1f43007f4a9ff66b28503c4229f8068944e1544949c0e70c02f283c3dde97b4f52700f2e578a6");
            result.Add("lt", "910dcc24ee713dcbd9b25bd759207793fa9014a402861ea0f6a54f0ac567b2f28cc8ecfe8a0f97f2861172bca86fad9bccca644726d5f9e553848c6aecdfbcdc");
            result.Add("lv", "159834980a244da4aef4f86b8c524f970a0f11dabe0e1fd2347b6aed94db725f42970219691ac4f52bfa20b6cf7962e4197b0e05e8d6625d61a31ad0d87187df");
            result.Add("mai", "cee9a02267f190f9c314e137607674b315a9e9e3a8b5522bc5fa957f9f99c02baf5098dac066f6281a9e0ca59b48d12573295d6c0d74e44239f8f2269c6b9952");
            result.Add("mk", "12c4b25787e3fd5353c50133ab2b2d58cd8aaa0e3c3a1ef432352e914ac6faa35cccc55fdedf84e7951324cad3d6ffc0e5332d98b2dfa10bff38d323c3f215aa");
            result.Add("ml", "71a0a565f422671f57bbb18bd1c9f5601f2af4a6a845a9b25f5514a409a914129880bc5ceb203b567ed96aafbdb12bf2fcde182b6ba4a07d15f9821796c22bf7");
            result.Add("mr", "388a2012d02cc76563a23dc423e804722ac835a9929f29b4aecffdea93bd379f8f3ca8e0a2fc1589f8af3c2c64e6ea638564395d40521079862f6401c93e0564");
            result.Add("ms", "faca9544e92d3d1d8c1bdfc6894207e18ec3d8572df7ad95cd4e194e48a782eccc011962431e6778cdc516b7c0134ad1128a1f9b107873bf3a9d39838b1fc540");
            result.Add("nb-NO", "c3528a746181417700248d2a3535ed3be8a129e00e9d718f7e6671f2a4458a328a7ed31e33d29aa61c06250bfd6cdb6139f535543dd61265d8ac5667c12b4dd2");
            result.Add("nl", "ca203b0ee1e07d811f2819885cdb9d069cdf19c65fa1a8babca606f3be3467b0bdf72b1a71009e32610f30ba686962e10ec1122ab1fb8a263c47ab371397e138");
            result.Add("nn-NO", "7d316c0da734253ae9b797f56024722a964a2f610e6e595661e1abd4d58b0418c6fdf2d98bb94883b1f2a231753293303aeb9a59c56c661dd67cc19f6e3f6fa3");
            result.Add("or", "f70a84998ee386c09c7be83b755a2f1b4eae6c1493b7f3741f107af1ff676c30419ebd2105a1a803590aa01612a886661adb88fc4d6f8d40487b42a5e22385df");
            result.Add("pa-IN", "afc2fd21ee45f3870b457878fe7da25d36c8c53ecc7cd761145d49b63023360925bb3dc6b73378fc7ff040f00210ac1c46c574c7b4b902d5ae0d4928f7b4047b");
            result.Add("pl", "e3bf0667439bd138134752b4ccaad9c2925c8cf1c8615eef13eb5d43fe47a499c5a1ec7abd5b74a0a56bc3f5bf07cfad8df754b400d02cf0398dbb0ee8df0452");
            result.Add("pt-BR", "4f850125eb636793ec29aa4d1ca088426df0caded613036ddb67b33a1eaf0cca4e30885528e679c7d8600ea4fc7de12bd6cf676d5de90f17950987ef212d6da7");
            result.Add("pt-PT", "402b4ed444b25c617b36268f986e9bdd0af194ce48973ca38008d5943a2b39c0ab78b2797ef4309087e0212cd66ca25ae969a493005453709f6a866366824f88");
            result.Add("rm", "1537ef312e653bc9552325e4f28589b959ea62f5e8025f0d549585cc60b2b1b924458c943013fb440bf7b4251b69a23c3af78fe9fa91d7317c14b262c8acf7da");
            result.Add("ro", "19c0b66b0e7fb9ae64fce79444f4594c44c974ae5f11d2ae31489616b0382d3ba05f56f936fdc5373954885b06c3c7a500da98bbf81e710cd22776dc0cfcf06c");
            result.Add("ru", "b76d68c364a3f033a3a455b268231d4784f4d0a808ecadabe403b575e5aceb6e83057d71dd458640b907526c2ca587d8e84460ee5b0007d9e1b1b39341e0a7c1");
            result.Add("si", "7820544eaa76e543bc948ded221a0c3786af3111897987f5ba17b2ec950fea7f95f279fe80e8c88b05ddfb402eb6b934e3fdcd91f251217de66b5dfebd4ef733");
            result.Add("sk", "53e9cfaef52c1e9d139a3def9b69dc39719ed72c304a40dea15b43cff53c973bc7f8c14e4776972cf979ebca389d2f7b1a35b3df900aac27d92438585362db26");
            result.Add("sl", "c7703f3f8fcf73afdfe76b4b255509a0cd27f9e11ce6b4a2d995a9e5ff1d5f71c21be121365cbb66675d2f1c6439a394218c6fe13522ebb8f8b91c710508af60");
            result.Add("son", "154925f0634293a82b676b02a2590c2472d447f7cc2f19accdfadc058cac780cd7ba827dc364f227a34281d12e8194a720abb8394fbacbe9b1ab007537db7138");
            result.Add("sq", "f8eaf79f44eb34a0fd4b8291a01e3866b0b2819c16c7b9aa5c698bbf4761391e4174bbd164e99f833a93030987e53213b26cc44ebec2a4214d3d0b73921a34bb");
            result.Add("sr", "75b156435b2f1890f065e3de70289a436858a6f6813cac723a09122177412b1f029bd353c9e5215ae11d583aed0d272fc8f712147f0d2538114e0b5d13919925");
            result.Add("sv-SE", "ed6ff76d50c41843dc7711d62d4d23aa65afa0a5770c90eb06c645655f30a54546ebec6bb0f07d7cf5b78b4eea4628aea6fefbb69ebf0b6781057404381f6047");
            result.Add("ta", "244440f7888c49c552d5b33cff7d7812c1488ad22ec328b0a76963a45bb51b51d79090b17be4cedc3b0575ce7d5dfbf481c4555687658a1f35137fa3febf051d");
            result.Add("te", "23dfe677cf3a71036f8fb2f6367c722c08d7cfbd3ae6862401061d8e30d9de7652a68008b1d18a50d892cebd3fb2e9fae813a80299a50ad509174e94976d742a");
            result.Add("th", "0f147f2c25198e25b79b0d4dd8dfff006cec66019a7b40e86d5249033651f45f5d751954d1e2d43a64f3ca13df69aec7cd7ac658fde848c1b1a5e465a1f210cf");
            result.Add("tr", "079cb8023f4b985066afa86d97e71c268be7cc7aecc941ab0a5524a5fe5b07c8a714c2055eba16cd96699e2c5d411de11427be15c82e109e7f19537a2f6042d3");
            result.Add("uk", "22b976a5d2832c5bd4150c7d1c0b935419efe013010f567279cd04fd5830fc9114238fb7fcf6d8229065f5e9181d2e7faee231ca0c76c0665c6fd12ef514d330");
            result.Add("uz", "f1e0ebef26e28f1a3b81f715d749bc1366a7372c2d4ea8d1b446032a0067dafb25ed99f1102afea0c644cd768c52a08ba55061f903ba18b51d7fc50495ea61cf");
            result.Add("vi", "aa903f35d0962be407ee26107fa1ff076e8bc21d979080ce647a40d1726e44593d6210612bf3115c52f0572320a0f31fc83a47fe501a9d9a6aad2f27868891c6");
            result.Add("xh", "4894cff933d90421ae14910b16773c7b57e006d24b3556850101d97e5c18b7d49e419b7b1146e93c7e96781fbc8403d49625bda5d70a4befba41a764864e3817");
            result.Add("zh-CN", "a3f315ac0083b0f761085ab0643588eafe2357bd3e5f764a05cd8d75be2c1693dcc6f9bc5005303578252af777246af2db344c806dde1d230a012ddaa9c34d89");
            result.Add("zh-TW", "361aa564123da63ccf24659911028b946bd739cbac0bb494d3b34217a24d8d905601dc64c5f012921a886477087db8bcc01a9d19045b4c67d8348f3f162f0f0c");

            return result;
        }


        /// <summary>
        /// gets an enumerable collection of valid language codes
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums32Bit();
            return d.Keys;
        }


        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            const string knownVersion = "52.0.1";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                //32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    "-ms -ma",
                    "C:\\Program Files\\Mozilla Firefox",
                    "C:\\Program Files (x86)\\Mozilla Firefox"),
                //64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    "-ms -ma",
                    "C:\\Program Files\\Mozilla Firefox",
                    "C:\\Program Files (x86)\\Mozilla Firefox")
                    );
        }


        /// <summary>
        /// tries to find the newest version number of Firefox ESR
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        private string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
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
                logger.Warn("Error while looking for newer Firefox ESR version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// tries to get the checksums of the newer version
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit an 64 bit (in that order), if successfull.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/firefox/releases/45.7.0esr/SHA512SUMS
             * Common lines look like
             * "a59849ff...6761  win32/en-GB/Firefox Setup 45.7.0esr.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "esr/SHA512SUMS";
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using
            //look for line with the correct language code and version for 32 bit
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            //look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return new string[] { matchChecksum32Bit.Value.Substring(0, 128), matchChecksum64Bit.Value.Substring(0, 128) };
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
            logger.Debug("Searching for newer version of Firefox ESR (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            //If versions match, we can return the current information.
            var currentInfo = knownInfo();
            if (newerVersion == currentInfo.newestVersion)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if ((null == newerChecksums) || (newerChecksums.Length != 2)
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                // fallback to known information
                return null;
            //replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksums[0];
            currentInfo.install64Bit.downloadUrl = currentInfo.install64Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install64Bit.checksum = newerChecksums[1];
            return currentInfo;
        }


        /// <summary>
        /// language code for the Firefox ESR version
        /// </summary>
        private string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private string checksum64Bit;
    } //class
} //namespace
