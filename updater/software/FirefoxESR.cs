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
using System.Net;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
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
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "E=\"release+certificates@mozilla.com\", CN=Mozilla Corporation, OU=Release Engineering, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param
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
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/60.8.0esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "86afb21b893d768a589d7d4db5408f238e5bd65e9382dd9d8b4890ace917e102a699636310ab60c9228d5cd8c7756083007b28feb4cdc7de507c734969bcef8c");
            result.Add("af", "173cd7f8ac3cfc570d78c9aec3595adbe21ab456853c71a587059c7335d5f3f1bd58f7fc4a10948123d2d369027a377733fb2a8889fa07adf7963aeca62b7618");
            result.Add("an", "32b88be96c2d25b0e343147da8a7702ca01f022ab6664d32af55aa25781c6a101d971cd0b34c28e6483b69d3bb904c06517366bda9c4679f1fe2d4994b2b9fbd");
            result.Add("ar", "adb54ed782db5ee1e0bae91a663c4a48cb9e3cf9868539620cee4a3c7207a964ff8ec6650855f746b31fe48b8500f18a8bfac5d633749e4b9c9cf85592b04140");
            result.Add("as", "71ea3932ef6b61caa9513e502ff6ddf53d13388debfa3d48b11cc343472a22876a5860cb01b4d44e47cfe81466c69b71c3957bc1d7f92f88834365ff8ff0ecb7");
            result.Add("ast", "614a5296329ddce0c54e3f3dd62003e0329ca2718683b8653442492dc2f78ffec5dad7d59f86f0ecc10f2c077d3ffe1a99753e3f7d11aa44a7208cce07c37ff7");
            result.Add("az", "80c6bcd1894b273cda1cf31a19b89e55feaa3812e03e70a4471aa8fafeeb0b8fe129ff0c95504044afcb5a37d206aab7214e18717a917c4c05932c1c1ff7ec33");
            result.Add("be", "a48d402c8dd6d4fe94103b7a38c4ae98dbd9fd07b67c068a07983ad37e5f619eb66b7c58d96d565999c210483f7dd7c95f0e319f7fb5ef1d5022965a424ea9af");
            result.Add("bg", "4b4f9fb5341538c2cefbb32004154668d0bf0e935f63019587214ccad566d5acfe89bb883c24189b822089674d251c0334e413c849b4c4bde13050d823789f8c");
            result.Add("bn-BD", "62173a9ba148986ca8cbcbfef37af7cc8b8a885e6e7f677051fe26c90460a8cc6b00be233e78a88e35de87a324a6d07cfb1568bbc26c9fbc9f3e3539544fc56e");
            result.Add("bn-IN", "ca8ed3fb7dc9e318b40dfb918c557bf437cb01961ce9b4a88fe9618d2b202974c50bad4db39f064f9ded732e0ab072b2c34b2b625a62c37bda25e613e3b4c699");
            result.Add("br", "0e6147eb4283a72955f53036a6544ca6714b410a0c175988ba291471d365578d5f1d7f1f0422656dc23cab11c8886f597b4e142419bc680b59e8fde44647ca18");
            result.Add("bs", "94f2c2245d259c97482324a37d84d544313af0b0b39c5b80e4b260ba3c7979fc12cc2aebcf3ecd1f6d4bc525feef3f82a7a41ab1338588e2f97bcd861b394865");
            result.Add("ca", "7c1bd8a5bf072b8765170cebf03b3f019ee3f7c4828c8b9adfff6694df1bd624732f991d5329ad2c95f029d91517fda2253953bc449c625ebef6a72eb16be763");
            result.Add("cak", "8c224d28baf4c533e8db2b3e6d7013237a600a4047933c7f514ca720eaee26cf77bbb0518a7a3e464c518fcfe5c76ba92f6c69315784347770193fa4c5470ef3");
            result.Add("cs", "51868d274d5586fc80bf2493516b3850cd7813241e00946973fa4283d1649c9d08542c302cea1c0534559d0759eb66650b7e9585bb4cc52a69cb6a9d378891fc");
            result.Add("cy", "450c1f79de321a05488daffedd535546472cdfe1c20e765d14bc7df4d00969ce1f03f61ae80b3d7235cfea809069a9536d9db8d65d73fe4dcbb346120fbacea7");
            result.Add("da", "02574809a954e7856970abe5d95b9efdb6e1e0a3b7e46ad86e5bc572001c65947f4cc6b84374f07ac33620d7450eefd4ed4ce70cd70a9f6176ae368048caebf8");
            result.Add("de", "8d9be7f6b77682654c396b397b39847210158c973cbe6e62771e1b541e115657adcba306674000fadc1772b0fc9320b61039d10272dbd8d958c010903e558a3a");
            result.Add("dsb", "e164421b0a8b7675da9f5083f0fc8e2e888eb6d1e5d9c8dd4bef7c7328ac1ba8f47e22887e6351237bc169c1514b68c87a2c0a31df1450fa061a2a57f5dbe946");
            result.Add("el", "acf75b763e589841f95060ebd38470b86a60381620766143e26c15cc0cc54003e9b7e40ddceb74d7a6345f3b169e15d6bef016f75ebbb2a7b12858897bae5197");
            result.Add("en-GB", "543610925c5e8da5acbf3e876ae8891ca02da94a4906e559ee65327a5a606cd4a367299f29d2e07dd6c1611eebaf015b1e03eca6a4eab87eae76b56f9ece7fe8");
            result.Add("en-US", "aa3a52a64b3302976a835a68b1ebe03e2c12618e02a9614f1cdf500c4c6c27889b487bb77ab89c65aebfeee1eca51558e9a42ba84b7a8b6abf4c98d6da8daa06");
            result.Add("en-ZA", "e2610ca6275d414ce70afb59ad73066334d27adb724af01cf19ba185212f4341ee0779ec14ce6d623929ea1533fd05d53ff03875cf2db2bd1e1537f33be046e1");
            result.Add("eo", "4f38bce7f51bf5f6710471354519d8463b2b386bca351bd4649bd6e6d457a3e769727c4743ebae536d7d7d7bf3b67d094cd44a079b94ee06c54f1b56270fcca6");
            result.Add("es-AR", "f4333f1b028fce19fa5e76a564ac8e27e7274175a10a8b8e18f4fa2aaab039fb37a1e060f1d6ff2a68d2c6110a385b7e38c011c13e2b91d351dd1f4048455f02");
            result.Add("es-CL", "8798d3dea34f326a66d48da063cebdbb0d6ddb3eb2162b187e27c3e7b10ea685c9df98539c2120072f4a23f750c8dd3ab3bd1abb1f181c148041cc9da977bf2f");
            result.Add("es-ES", "617635441ecdaabc37422400b5af742bfebc5c76a2b2200379559eaaaaf8b9a90abb894d113a521298cdbe2f3de808352d9270e84f1ffa5a92fc1d4cbd6dae28");
            result.Add("es-MX", "159f015d239f7fd0592780ade9ccdfec4dc573f8546b22066cf6b45ee71794e7cc4241b57344949c136f9c1ceb9569f637673b6e2bd5bf2881618b87a747684b");
            result.Add("et", "7fdb8b9a4e8ca4b69a18f17286aedd77a9d2414180b73720ae6481adf6c6562a063492c309cb86c9b5319062c07f750f2b7de3d6a57b8b3fe2ca89dfc9bb9a51");
            result.Add("eu", "49a42b7522531db83047f395747893a427ee31798e82671f1af882d18512e6aa0e2b36940249836f0ae0ef64e9917c13979bb9ec8cb0fa21a8ad52114504531b");
            result.Add("fa", "0b891a42e2cbb0aa9fa4410f7e5fb3ecf410a06c6374ee271e8aab0974d5673a001a8c3ea62de8aa4810ea764400cd2830d6d622ad566e8b74332d26dacc3b17");
            result.Add("ff", "c842d49f4b55f66448f1d7542155ecd0645172713961a6350a2688acd04282873b9201132afca33d038099b4d36da8b5a6c5f025de8af904d3920f3fd653cb48");
            result.Add("fi", "18e46ed1b5525d49f99a76739ddc27307db259cd51f06028849346fc8e8a39c2aa6031b854e8b91da362e02b7ae08ea7e357fd82d6e418c85660dd3051aa9d1d");
            result.Add("fr", "e7470bc0177a86731d45d08035bc9c8d51a31abe1a69da32f482e5d6a1de15056f7648b5655825cde2234d1e36493d5aa6755850df9f8e6a1b5ed3fa681f35eb");
            result.Add("fy-NL", "82a3a069d21630b56b1d96873bde376ce45155bc7196375e451775455e4ea91ef52dae7bb43b942ed7f9a3f391236b8507e9016abe854bde7d6883f8eb6c6fbe");
            result.Add("ga-IE", "3dd3f9d125e3f7407453e94f0097344bce5ccf69de19e2c36f385d59873298950538ca538c5511541e77c80c8bc8d3320123c5b121d6c86df95df7a6b55cb918");
            result.Add("gd", "7d5d4e89eb9dde0bf6c2fa94b96dd0c48978487bffa1221dd814cff8f8040a37b446118e6d1d37383f92a05d888ec7497499f997fbdcdabca5c1a29cb676898a");
            result.Add("gl", "fdc8912099c45cc5271547d037ef350811777fa373dd82b7008f397b477b98a4b47876c02dd6d48bc0e392a04eaec5b75f2d3bae76a5ec55fcdce2b7faed0a17");
            result.Add("gn", "b1735fcbb772667dbea2673f74c4ada6c2005b1278084c0c2dfab6a0c88e36b9fda9c709c799ed50dac588dc2fbf53612ee37b2f12b17b3a73fc7bb3751886a0");
            result.Add("gu-IN", "097f62ab8d98ff57f591685723e3957f774c2e443f184e056e9bab9d6ccf8e88bc6dddb15f37ff75f6ac794aedc922e007f9679b8f25816aae4e912865464aa9");
            result.Add("he", "f1654c312731b4f32e0b442b6106b7cbb8543ed6b1d79f092e2db9e643145bfe01e6af28e4296074a9ac0373b573ec2de9f8bb11ac208ab55a06a78a5e272348");
            result.Add("hi-IN", "95cf062562a114a9ecfb9bf23cf1ebb7d4a25dbab6ecc97140696568ed1130653b742e622c674f7def789481c9965cc6412227add1f47c2d0ad34f8fa8d74b5c");
            result.Add("hr", "d93959584c167317bc7b1f8e3d9a6369dc63a7c6d1cefc2141e06fee52e56449bd579b33e3e00af11c929f734f15d58e8b914cf55eb2036bb36d692dd5f681e7");
            result.Add("hsb", "e62e8ae3390b1fceb15f39b09591933c5a418649920826f22ffe13ad4e3fafbf423c147907d2e09130f69cc72cd7ef6500d807124389519ba6bcdebe10a43f9d");
            result.Add("hu", "705da7c27d0e83ecbf0638055aaa6594bc7362293fdb2069793bd12ed9fa8ec782bf519338e4490bbbb0ebb500ea68ac0f2953e6eed2576f13451cc2d07349cb");
            result.Add("hy-AM", "0388b0332ca4c98e6417fdae34ff75268604bd7f3e0521c05b219ef854943417f69fa863a427ad9b068460348d86317479da3d531013d5decdfb3f48f1f72cdc");
            result.Add("ia", "700fc3f07117dcbd9dd057e12f2467f84f8010e445d846bb1e412c0507f5b6b5c4667f1ef3e92757fbc305413ae9d8225bcc95a51152e0958eb682f9644353f7");
            result.Add("id", "7b814300fc3688ff4da43fd3e02a8be5d5f2f4e626d8dd1954ac8ea4bdddbf3fc0afc71a691837d6079214f48e3e8f5aaf95ae2ac5757ff5df2e855feef657b0");
            result.Add("is", "cd49c08f607df858c374cf62d5fef0933d4e07612c3fffdcf93d8eca4c4f5d87c3abdbb59de03ff6d83e33ff788e51bf1468c86f009ee74769894c6fe57b9b2a");
            result.Add("it", "6b2603e1a9fa9e407336be4acf6ed89c90c58fa2239c7e5d7d7d2b2b19867d333f8b0f7ffde9d5ae6ca30d28d83ea8889c2320d581e2bec5f4937fb90b7142d2");
            result.Add("ja", "24b463b4bb1d2a23b7538630e0200cdcc4caed1b5589c45a52508b5e12c2da3ccb243235dcadc3ad08893060f5c15cbb13e973f687d4651413a06bfb26f34355");
            result.Add("ka", "5c6c0a76bbefa0c0282b36d69352625f99ce6ed019253718cd9d1228b2387a85c5d44e0475861d067c0c6736653179d93454f8ef018cd246efb21657dc04a0ed");
            result.Add("kab", "0d9f328ddf276376958cf949f38f8e3a015974acaecb130b8c40c330daaad7151c0efb21ab050fa9ad46489f9374fd87f4c843a9dc264b51d08350fcf2b9f0ba");
            result.Add("kk", "7babb65779b58b71ea588caca1e62e531ca461be21dfd6ff67f13f379e876d42d72a25c7619d08aa45b924246472dbda442d57f8bdc5f7670c6d5c2cea5276b2");
            result.Add("km", "6375c4383d088cd5748b355a102a8952c0aa847d6e1212fdb7a520036e26ba2a6a85f2d162ecb056e556f6badfcdd50a2e2fa0a0c200aa704c643089dda5b891");
            result.Add("kn", "a6e5eb8f99b96d3fdec6c312087249b0be7babbea512737b3355f3bbb136e0ab6f8be2293eb9664bcb611905a7fc2086b7ddd9047f724930525da1d8c79784ee");
            result.Add("ko", "67df5d871f6584b62432d6e1408a73261a137c52f6039d7d9cb948da7feb8f0ac0b66c49a78e41ae09e903c20b19301f1beb92ba589716d6bcef175cd75bcdf2");
            result.Add("lij", "f87e62bb3325d063570e7d084fa8860f6a264dbfbc2f1c30b5d0defdffe4c7fb7084ded6300c167cfad1e927c220e8cc147b8dde1e8cd60323893485d272008f");
            result.Add("lt", "129b9e222da56b162a916529fa14c7f991990cf3de025c22d098a6f6713035bcc28a78b927ee5be45323644205206583f7848d824fe8ba767d0edb94ae4f640e");
            result.Add("lv", "748eed9532a975a3ff341f10470c31ab9270dc2eed4c6f5cd10403900e7c5e3900dcf5320c61e96bda8a7aa19fabc5753e3a20c1a719da6960f44b68d32e93a5");
            result.Add("mai", "5423877f524af4f4c059d081b29105722388ef10e6f8f93adf3aacb8d58565059f4cedf7e943680e2de3755618f5d22a28249985e6947fac5df5fc7fd853af97");
            result.Add("mk", "8e9921a4eb10a965fa7ce3f72191b6beb0bd75ab80b7782fd0c53447465243dae77a4110c5470f2f1907d6c62672d5bf5c29b68f18e66af3361c87e2f5d597c9");
            result.Add("ml", "72b7953cbb11bd2c67ca0a821deaf428afcb77035a8b8f747b068e67049b25283a4fde5cbe4c90eef60df18c9dad08b1f6ece443080f430f75f68cce47628f7f");
            result.Add("mr", "eca81fad6b02883fad0e5f69ebc4e0b4229bbf73d7093e2e75ca754ff114055f9d7b95a089c11ecd334fef20083498007778fc27265b3f3dd17407744af98fac");
            result.Add("ms", "e31162b36b6fd432a65d2ea0d640dfebe4234deafaa1d8db2cd581a850de495bdb72e2f9bdd6e6d74afe50be9e1f396d81825ac3b86a834996cefdb82f0eead1");
            result.Add("my", "d20dc7b10e81442c071b7aa0531dfc6f94bf547159c57f1a96c80df7c568a90c890fc8910e0e68c595f979a9f60049d047381ebac67c7d979ace0e45008a6ccf");
            result.Add("nb-NO", "de42ac07f5ce2eba3607ad1c6c68ee78bc43ea6e856178043b0f308c97aed3b726be8d42c0dd7943f4f9e2cf552a144b1fcdc87df445ceb35c3f51266fb342d9");
            result.Add("ne-NP", "1b26873a3c72ff8fd0cfe2b1ccb2c3fcee80d580762cc3e71195437db8b9e438495f71301370e1a8d8ef31b4fcf2ecce5ac42666a5b16927d663f6e66e5e2f3b");
            result.Add("nl", "3da8046b4589bfac3436322ce1b9cb7f3251cd99516ea931c7efe21d812c4c71a9f4100bc73d2d1a84e4fb2dcc378d10b0e8f5d3a160edeae449efe56097efb1");
            result.Add("nn-NO", "827c5b4057d8ca183ff500eff11ef8ebf07bb8e47a30d0551aaea8328498084fe41386e199e89cc3f1f7d93358f44f1c54a28ac822c34db1da34744188bb5c44");
            result.Add("oc", "4709248331bd681bbdd5b42c13b602fbdab5252d7e532557553a7bdccb2c470ea08db139937bdc807c820afe39e362526d2180029f539865d1f25a0798d2af0d");
            result.Add("or", "06d906d556915cbf8ca81f62ab4db8875aba095f42f79cc80ee3e39d35ecab927b2721522dee7e31fd80db31fb975dbde9f30653109e55519990267422319b32");
            result.Add("pa-IN", "d8a4ed1cb3419ed8cb24e7c9a36157d0f97f3312cdb7213aae7918b2ea8f91084af90f59209f44193dba66e07e4cacb5ce705b9cde0f6fba17aac5bb42c1c91a");
            result.Add("pl", "577c53c10dd415e62cf78de61fd8812b2e218347c81d25a86a39409a6ce382fe81d019580b3ac2b5297fbf5f7cdd8b627f75d15476fbb1a36aa45f05d362d58c");
            result.Add("pt-BR", "6053dfd3533dc7550d8deb01114370008e2c6ef3db0ce0720694e8fa3afcfed61811d510c1c8252afee45222e16c6797518a64ced8d562db228b5262a1b29a58");
            result.Add("pt-PT", "13b31884f4c0ca4f67adf20bebbfd3feebc94ed4521c16e57f5afbb309ced520718d2c04949f1c1711bafc310a0f316121e84d58146c88eaa50c82e9abc1a09f");
            result.Add("rm", "2c10f012c347a2d4ce807214c6e1bf3b60581d4314a5a277124f6bb2b81898d95d272ae0c388da65af8e1d4b165081c5a5ec3122f090904bdefef8b6acd1cc74");
            result.Add("ro", "6cd6c10d7d839c3e40842c5b90398949b63db1692736cc6e884c9ef1ef47788701533f13046758c7c3c62982e2cf2b84e2572fd2235d307e57ebc7490d35e7a6");
            result.Add("ru", "2ee15f202843c30db1d64b7317365c6878da67fa09d0b2b8049fdada53ed2e38a6b2452d5479058a41e73781fda1ded965bab219c7b8fb6c92bea9cf36ffa27a");
            result.Add("si", "5ca162c0b6b6ebd98c72a2507f9779648275b0ab3a031d6014308009a532b6577cf66226f96240f8474b57fd40fcc072987762ba775fc2a13938590cf380c86a");
            result.Add("sk", "4ae53fe5f2798097b521a56e7e3aba1669511fd393661b7c67f011f1c8c6995229204bda62694de7398d76a74bc204fe86c26007d2b4b1629c5f583b61951a6f");
            result.Add("sl", "3248de98016545b62e71dd3e9dc2928bf92e96274da62d2121f2a6b2f4d3c7d86c5487c4a473fcba747878234a0ffa00c07310aa8aec44ce2d2d12ee92e4be00");
            result.Add("son", "ba4eee9a27db6fb9825970f9e0aa89670c315fb319c4853165278fb01e90e3eeaa517189ffd0a8e7684b52df599256b567862f72753d4ed8f1732f60085ea6e1");
            result.Add("sq", "799dfbe6278880d639c56be1500309f7866630307b86df78e6b3ee012a668f477929dbc4ad0bd49936bd3bd218c4150884a77b9680304535edb349d9aa289d3f");
            result.Add("sr", "a5d9c62ceb1a5f32407ad9d434f2be340434e1c76805faf8adf60c63cfacfb238935732b4aea61f44ae71758d169d42928f12248a95f661bbd7eb424e38dbc0a");
            result.Add("sv-SE", "ed2bb4acc3076e0bf2282440722dff95658f727b3b7c0c16f284edbd4faf91dc7c539cde8d2a50eafd57970cda4fe39362e50c350cd692b3373b43aacc767697");
            result.Add("ta", "0b2c928e0ea9dce7c01d90dc56af9208ce9cc73b1ea7b991d4aabbcbb095824cc074a482052e7e7117ec042559214ca88652697c4134233c00de0d9efd9ba181");
            result.Add("te", "47bc3919747c5dafe67e0239f514c9e876752d60a304e7fa208cd530f516802933f804a3bfe6b20df913f99d365c290d82c2a6b6b1d60917496e1c5960e65ebe");
            result.Add("th", "aec0eb8133fcf22bfa798551a7aeef93249e9c521e619c0cd43c4245e60a25ebd5c81d106338bf44e9a7dc4cb01b857cba0a3f4cdb2d2d657237dececc63522c");
            result.Add("tr", "985aee2b3de15075a760078ac7477b1c0e9601a44e550008772385b8544aa8875dd946a9ea47d67a148daaeae3ed31edf55e2d712ca9e91d0f6b76b8f66b3862");
            result.Add("uk", "da82ce7a99a0796350c2b0a4c72c907142c4f47d9eb0bc246c5e3947e2ac64fcb19e6d7f8acf129009884951b0ec53201d8e36a16affdc92d3a35ff65074b9b8");
            result.Add("ur", "69d974d7827b878a26f18bcb62bd431b2d53f0bc28699447505c1a15589bf6d9eb089409ac9d540b57ebb878cd22d3e301a4c3efa292ae039ecc2e54893a57bf");
            result.Add("uz", "9360c05d28659046ac92f55bdd80a679d576d715069570a96e79f8fa9a3b6cf30ee6a2f2ace9a3371d9062eda095341e7f388b37588fc23a2c04ffa5c2eab410");
            result.Add("vi", "51a22b444374fbc67e6c9479a45e5fb0b13c2af202b8d82636c2079a0b0f73add084a9cbc9bda1d7eae72147c893f983639987965baf117962f56010f8a35f43");
            result.Add("xh", "9536381bf698fd4a5a26996c276253f0f93002efb209eea1212231082f634c6455998f36a12c35fbaf10090a9b77a1f4deb79c770044f24ac60fd182e10035f3");
            result.Add("zh-CN", "d26100bf0650f489b1d10b579f2cb3050b10f45ad3e2b0d45a2ffd073a946e50780ec91147577c959edbf823f4d2382ebc01e2f2cd83e56247ee4ff8393cbc28");
            result.Add("zh-TW", "99fa3346d043107072c0cfcff4028b67a5b1c212c6bf9760a38da3a1030a0133fcbc3eec39b6dbfe1a7507bd4107df91b2483f10069a05d182de82aa0c9df6e6");

            return result;
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/60.8.0esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "1ab8ab7367c9363f4f6754eaead66e12a28db63fa41cdb8dcee5d30b83d0a73e56fd298f5ea5102365d0791c96d59d5a90874854ca88697707252f06e30a7d9b");
            result.Add("af", "fff00a55789899bfe4c4ec902d8f5d399680657b71384c29efe777cbd63dea0fabdb48e7d636a267150025cd03ff8ea3d7aaeca88cd34577d68124e1ddff7102");
            result.Add("an", "8f36b24bfe15a03d183ffde4bbbf5bd00d3350ce5750da0b8a6cfa38f87acabd20666d8978b02b9f1729b6c9ca44268230fdaef4a81273ee709590789b5cf1b0");
            result.Add("ar", "1b3058310e358263f2f27373b177969cbc9cded94a450d8f3d4c7593723a99ca6b7e927d07dc9cd2c6619614deca2a2e5696079bb10f0df1019866947c42615e");
            result.Add("as", "743504a5410d242ed737eb0027ebf84e0ffe238434ad9cfdf2e67f0ff554a7e78bb74b5fb54ab4ec253fce53f9f224180d61bc429a8da2146ffd8c3f08b1b7ec");
            result.Add("ast", "a4a2614ab7116fd093cd0a2dbe6e7f2790f7c04c6c86aa39203c1dd6a262d2ef919bed6ceea772573af0d3d35b2da08ebe9e48dc775012f185bcabb4169abd39");
            result.Add("az", "90970e6e82fd4abb2d1dd89fbdb0b0b0e68350a024a462438cf7ef4787d688784b1c0ede980a3897a0d5bbb800618fef46bf8b0a65fd38a6abe746a4e6d13d57");
            result.Add("be", "697d57d54d858566b5fd9e391ef3fd9787266a35f71f4842f25cdaaadbba59faae67f2acbb335652e029111fff0d79d17070e57e699a446042c24376e6d65e10");
            result.Add("bg", "cd624a349bbc0f2885c16b244c48d6c07b9ab94c829322baa74f48ebe8672b301fafbd6ecc61a14ddf329ebee10080781dcc93ff91e797acd9a4272dbca5e54c");
            result.Add("bn-BD", "b7ab7ba75c895a0dfca860ed6f509a7ba0b6b2b8e7ea0f9a9fae9611a3bb197060959fe960d6535e790e06772c247f5a8aee59fc2077e4532cff88d5550b6a11");
            result.Add("bn-IN", "463c73f3c42a7a906e13e0a239f8da731b633f0a56a19b8849ed534ba7983ce9cfe4d2fa3d28524e2a12449cfe9ae26dc57a81320e3d7d0b9b0e32eb1781066c");
            result.Add("br", "c2818ef01a1c8ef64ebdfa061e7d7bcad4aa7ef42323df5bcda68fec6db317f8758b541a7a826d730f9bd9e6aa310cd25249854bc8ece52d48db2f981cb2f121");
            result.Add("bs", "9ad706b2d6fe9f8e0d0ddb7348b5ded2b2dd176abdcc495b7bd348707c82d5851b822bd4ce727af5bac7defdfca70d6c72d94d634272b670c4756e8fa87c69fc");
            result.Add("ca", "e10e6a79efc033554dda54dabe9c26b689858223221d6d717f0a35e30e1a3b590250d47cb44dceed713ea12bd7f9c23d9a3955f881222b52f1e8aaba4c998cfc");
            result.Add("cak", "9bb4326b7dcb42613d6376573806ab8bffa2f8aa00f46ff3a412fdc9085531f4af933802c1cf7625633dbe81e5580c76f891207abb3a3ce6b389f560dd6e7a73");
            result.Add("cs", "3e732ceb92316c68fe812f8d753a05868b0944259c361aa2834f64184583402e9c2fe80dde6dc5f1b3d5b147d0f8afea3a5539185b0e3cf0de199f6fc97d57f3");
            result.Add("cy", "cb8e8f7de8b516484703a0cce9caa499dd4d42a3593c7844fbaeb627a6afeeb723029088d7b26cc83fe9b6a5ad6828425c9970efd8a6842c09e5c64b4790c2ff");
            result.Add("da", "fa7e936b9560862fd902a83e5212af38ccc245876df297b40c0e7196bc235261d655dc5830ddf38b212c35fc6112e024dc21d7bbefc7142330082d065750215a");
            result.Add("de", "47eb949b093d23bdb7aaac5f4111e9439071581b92ef35ee900811247e36b4ef9e5f1160df801ac8bfb7350dd6d1fb656ac68d925a25bfcc265989340ac4a646");
            result.Add("dsb", "8c71695dffdc4f8f88ac3e43c9aa73e67c5a57248413e38ecda8781d823efe72b8327754266cf50e0ab1a527aacca7ec11918f07d8d6efd74a1de372bce327b4");
            result.Add("el", "a788583c9cc208577058782ec2113ac84a77c2b4a9bc6601028294bc5f50b891e26362a0944fe9121d4d8b0a19b8f9c9af828b76b28bf89a8f350b2f526da03d");
            result.Add("en-GB", "aaaf206c6bba3358dd27283792523c4e3c5b17a4575822299b548a85bc239ff5c147c8e05682fbd185f7ba134fa86ee656a04e461906736cd6580e3c6058380f");
            result.Add("en-US", "587b22e8a5051290413cf7fbd847aa8cc8965ad587a3a3e3739a578d9e9453aca95db31b807a482eb2ffa882df775f77b88b67ce574136a3c6b0a4bccd6ebc91");
            result.Add("en-ZA", "90e8af0196dcf5e4b2ce1df1cd8d82ed44badc8aa5583cd3ffd126014b7fac428bb77c26ef6d0b4f81e350f20c5b257670dbb6bd1cdca39cc8f97b7c528c0b6d");
            result.Add("eo", "7c9c04e449811a98bb10761903b6033b875afbf1414e81342a03cbc1aa8dc9a347372140dd670d7f6686f2c0fc26b068826f68e8fdf5f857d20d50154fd94b3b");
            result.Add("es-AR", "5a7e6a1a33fe589046ab7df49f09ca738c4e2ee132b92d3ed92ecb1c71afa461481dc9403947243ac89c7437bd2d9ae1ce4ea20447c423485df9d4692273ecd0");
            result.Add("es-CL", "1970b16e6c08af3e57738be3cc5e24b6c0087db628c371bca85a6a993968024820ee43a301b76d432f7fd17ede66d6839f1fce8030c06cd977e3abd0047468e5");
            result.Add("es-ES", "d590e299fb9e076a3ad96571ae8a3b07a7389166488714032c04b2dea52560a7c56eeaabe3339612b59a548aee39ea740257b5da6201fd4f8aa6dbeb7c13c60a");
            result.Add("es-MX", "3b0d37251ba30bcd5f064eb8df648e9c749f8479a452d41fc56669276a3a9ebded6491bdc9ece905db0191987c256bde2c53d67d153d39dad685027fa80835f5");
            result.Add("et", "4ef4433c5ad25f8d0930dd20c992d5e82b1d6a5089848bbf0725689a5e33c7297b34b55e36c463d9f9f5fb11fc2f4ded1c1aaf77809a4bbd9eae1d982f89d562");
            result.Add("eu", "01750d7b23844fd7cc27a985881718b1d3c87df12b8f1626c6624235ab1689f8770e87e2286fe52421b60e6b3db9e70702a3ec739852a85ae1e1cb3113ce653a");
            result.Add("fa", "f9f57a067cf46ae9190feefaeb3c3f219c00cb4b927b74bd4f5ab3a246ecbf083fa2d01a5010eb23224d028ecf60205dbfdc815b0e48d345d14a9601bc764492");
            result.Add("ff", "b3f1a3cc94db9d445a2c806b98a6655e006ff20c60b326a1da9e0ef51a942dc3e27a222f49f37290f5a5565609185b7f8cd42a007386b6799060af50f5ecb076");
            result.Add("fi", "622f18dbc8cbc3fdda36cd2ae9109ef0a317c07c8185211a6642fc40f9707ed8841540588ce1d3d8d1468ae8047931e33bfe5e8755903980791a8b1a28d323fe");
            result.Add("fr", "dcfc8b323027212379d0b704e97d1c12ccdee15d25888b6afc3fad75007b55a9263d60cc01665d95a85edc9544e55419f0dfc6f5b2671a6141bc36d37499574a");
            result.Add("fy-NL", "20ae9c94770a81354808940c52e0d7981e8370843b01b1ee9c0e1c775795fba0c5383bc6a3b1290348facf0414f184fe269f91d20358baec2ce36865daa90716");
            result.Add("ga-IE", "546f201f17fbe7369d7455a69d55a2200948230af44a3b550845412e22babd5d70ccebdc63bfcd8f046ad611d7c4c0a3fa25124ba7633d09fc9e551a48f1a79b");
            result.Add("gd", "48e7af45952b5cfd48a8f13364987d8f7d354fb03eb2624d7fc8b02a52d61668e1d9bab6d2745a375034017a62682cb2eaa270d7e7195a98b5065225bb74e802");
            result.Add("gl", "160d37af974ac700d8c07921499d67ed75516baa1e0372a7237743f80aefbc710a178ce6ddf216f181d72639c63f905b1ee7f34be26a122b2a41fad01a21a728");
            result.Add("gn", "7cc77de2b18d8134ae2a6ad1bd243e2ecad103db748f7c3303b615efa6c990bf0c212f4ab15b5273f8a82ab9b3b6ce6811a8594c59062031e9fc828f7610bea3");
            result.Add("gu-IN", "a4b7991e59b21ac359c0c0e32d5c53d6259d87109691eba24cac593cffbf0345a3bfa4486cb236bde1333ba29b901077409859166e006f9824cec8ab7a154a94");
            result.Add("he", "5da1b715f6e6b69118bee2a9e7f4f85dc41f2d5b645fbbfed2254cfe81899872cf1f0537f345e21b4439aaa75d3317c86932550d183be7349954f5f690d2989d");
            result.Add("hi-IN", "ee356e03f8d404dd300438dd05697a47b0246700978dbaff309163fffbdbda489f2940092e1bb296b7fa661c7ab82524b4f3fc7b70cfd2a2b0a3a24dcfc0f202");
            result.Add("hr", "ff6dff7796831208fc5e7d132d295637b34797199686c47ce6fa163afe470c10c80c7be1cb975f8800dad49a184a718da541f36f70b05372ed7532b94eae823e");
            result.Add("hsb", "8601dfe11618b6761913ad1eca361f5c0203bd82bba0b831163e187b8e3bd241a3d94ea786d3e4037b600b1da333304c1c40ff4d2e6b3553c7d2082cb25ed28a");
            result.Add("hu", "c4582eae31029f2fc95bb36b33d3d8d85f290af900b1649cd29a5a1118b5e78b468f05c23fe28190f868eae6560e32eac84e5ef03bd4a85bfdf8f6a1055eabd7");
            result.Add("hy-AM", "5b024622e4df1242f93428bcb6bf644a426c287428b5b65350b688195a3f1884500620492f7af67a75c4e8a101620a847c42fb885373df1f5855cf713eedc934");
            result.Add("ia", "90d375aa277638bd8d72f24559e70464b33580b969852a21347ddfb7797b0a3bf9f8696ea831ca6c42c263eaeb724d7cfdc2f876b7ee53b84250f6f16f36315c");
            result.Add("id", "d8fc2b54d5b8628fba5b74c8d364379a51f15123d55cf68648c32eb4192bc29ac633ef851042e5ac4f7bf8887b8287115a82860be88c2431730e7a359084eae2");
            result.Add("is", "a5af11548ffb654c759dae139687223cb89875c473478a1e0263b1baf2170221fcab7f395bf20a835004a09ad7b0b2939951ca55f2ae46cdfe41ddf71839cee5");
            result.Add("it", "9027842a188cf91fa8dea750b2e22bc8533d32f9735135767407c1084beabb645155e3bd96caa5a082e2c3d4532f6a298ebc27981011eaa87018f7dd40741dc4");
            result.Add("ja", "02ecb40ebfb707911404263145b09bb783998f30163cc6c103d3855c8ffa51dadb0627e3d3ddf07d72daf98fb1bd6a40b655ba674deff10799543389d74b497a");
            result.Add("ka", "8072a4acc974489360807199ee87f966c469a912f64584d8055d611efbc8cf4dc2f65473c158dc54e002368072a104bb2a348845acd33d0d5464b8beb5dc06bb");
            result.Add("kab", "74773ecd5d3d09c1e1d08f67a8df98b8574f2fb80cb794c8be5c20b58962652bff042652b69957b87003e6e8a1f23876f88d2d323fcd400371beaa076043538a");
            result.Add("kk", "b779a265f6dd2d5f042c83bcba0627338bbd5e2d2f3c7c88c1ea5e82aff78cd0ff3f04bfe331a5536934c0ec95b521e3cd840159c75c12d91364a84ecf8722c9");
            result.Add("km", "b41c8319bc0b6131401476a97225003621f528c641bd4b9312d6ce90e4c01c1eaa7bbb395f2e2693e1acfa0bcd2d0d0281745d87e099dfe4c99dde99b804773c");
            result.Add("kn", "adc6407a17d80b236db110d321c8e7c1b14d2b2427ba06e4c0902da3641cf626652dd2f7902532e547fce7f5a88583b7a00851eab0b32f191a6bcfaf5d2c5d11");
            result.Add("ko", "96cc6b8b308399d453a7fb05bc690f61eeb31e8af1432959609e1c800cd8f2569760054d0a4acb3b7809ca8e5a0ab1251c49032a189e505291a8fcfc9a391190");
            result.Add("lij", "da2db75fe4f364631c1ef01a1601eda796fa0e1a60a067f6e7ca7cbc0c855b8c3b624a0e715b281e90088be823f0e7d3158a8ce31566c2cc28f28d7a182244a6");
            result.Add("lt", "1c4e29194857a128c2f84944fab23e777090905cc9f43770c81e3d065a66f2cbfebf357605fea891bc37757f1c5ed6f1a083e2acacaf995328101ee94cc64d18");
            result.Add("lv", "42638bba3e3f33e755fb606690c27c5c6efaeebdfb21fae91346d0bbf4974d92be0da3319b7a6aa15ec2d6a68fcec596f0bc70ae5541c7ada64d96a5b7d55976");
            result.Add("mai", "671a4ef4feade63cf092cffd9a3437880242e0c23eae068a69b712d629063ec029d56377fdf6499aa6ff489e80193218df00e7a16df175392bb988be15e65240");
            result.Add("mk", "f2ffba91b092281c3732776012f7c398cbdf77424dc9fbbdf91af3e5572235057ff186f8bab187fad775f909e0f27634e107849bfe111f1c5ca3884cfba68d89");
            result.Add("ml", "5c12785d182c5a0e5fdd823129d09e468cf537afe5598f73e0bdf456f2af56e061bff879d9abc29eb2b602cfac9c31b13ecf8a146bb6f37af40aed2e389e7b88");
            result.Add("mr", "3c3045b0cd3235ec3f12cecb85b03560d444710274acb9b60db2ea5563603f7dba754936cd6c11807f966f2f6c1da132f0b1e69c5de8b5e4d3d0e29fb3b3aeda");
            result.Add("ms", "95a397a2fc12734052d0b7a43fdd49e74782623c4de46094fa39c88adabf4a539e579994d2904a1c337e01190f00de6d3cdb6a43a74b5dc3b3ce0b5a6f99b304");
            result.Add("my", "a0a0a560df64f1ce998721ab0d93ebc33368a4d0cd7c187e185b7d714333b3e1908f260ca7eb36b3f3718e2d555908ad1146b94ed56e4cdebf4db91214db3252");
            result.Add("nb-NO", "a6ed3a29f761bf6fd54ae1a0a75077394956550b57d3464d6820c7b5ea597169e1a4df8a3a8c34b25d427b59c26f2747d6cecb96814b8f8f4a91dbe22f6a7497");
            result.Add("ne-NP", "adc66055977855341ca70cf117fc770ec5256c86db2d719274a786293b0983c7aa52e402c31282403ec9a5f7b5f41bddf1b400a6fe7b24cd07b3d2209ed380ed");
            result.Add("nl", "8f7f6f711f6b35a839fa829cac08763e7e3725edbe78c54e77daa1597bad92b32de3d40f90921eb8d0a1526aab396722fdcf9c5ca017cabcca058660396e1b81");
            result.Add("nn-NO", "96ff5560242ceaaa7a9344cfb0d85c73d73ad65d5a1dad0ca6186c383501e3196f4111f59a985acb14540aaa5a905a00c61b265e1b2bc7f44437abd67c880aa4");
            result.Add("oc", "1108733b45b53c8c9d11082d95a6c62981576445abd0b378836bb0c01cf3f9b41e6e6e7359455b887c66a4a2633a20ef9421cdf5347b1eac9360d1978ea7331c");
            result.Add("or", "544ce4bb9487e1397068810404a742893465ed98d90a6f8ee76b6d859714d0946a1b368d2c8385622480596ecb6546c47b3a7b2f4971078006e314c6eded839f");
            result.Add("pa-IN", "37dc5e4660cc93638e6fe2d0012105ff4a1713a07bcb65412e771be609b0c971fb18eea6baef10b906e3b4b81d0d95b887a181d4656d2e4084fff340779736f0");
            result.Add("pl", "6b1df38b65ac6f0fb5aa035dbde2e093fc5288cb4bdb5e91b78287a4f7c4a8b1e0c5cca58ae17de5f3880ca761826a04d942632966416caac04f7c089277e4a6");
            result.Add("pt-BR", "34f396d52167ba222c9e2a0571e7507b67cd110eb50831568698d4a40b11b84fe5a39f4672cd67efcd330c381f3ebdb08937b11be1eb528402ecf9a30f9786b9");
            result.Add("pt-PT", "d9a2de13b52b7b6d8dc7d76df2fd8741d6d3f689e33076730d0850e34082f4dab2b3a10f5b4ea36578e78fe5f93de0d9836088d75d4a84b97bd088c3181af94a");
            result.Add("rm", "29e03d58ef0fbfa778ce1b4f60891d8979161b2af93322e89afb0495ef118be78af549af0ad4d68f54f58b7d47fc893e909944bf4f3423634a0a922cc71f3ea6");
            result.Add("ro", "d0b80676c13b14881d3ee086e4e7f84c3fa21fb0c1917567e8b9d3de4825e0294c93aac5059058a1ad95459d2c87dca055ec330c67615bcd3683809fa5ffe33c");
            result.Add("ru", "e29b8ebb4d25d211876a170e3eedb9464e6a6f7e6aa1f18795b812a3deb758b80974edd6c5ba3ddf342baf1d47fa6a1909bbba4beb34d0f9acb7c832d410a55f");
            result.Add("si", "25869ff028e140e1b67d75624f5d3debae8412d97c3b1b28be28b475b9b76ca9b3635ff44ce569d2af5dbff19e8347d9fb396b054ea2f784910ce99ba9e8fc60");
            result.Add("sk", "5eef6021c4ff14c6f936bbe941b6b1dfad6b21df36699d105f562acbcd1f12e18471a6e4469e1e3a5dfa93ab2dd9f881b0746b9c6f8810266912209f34ed484f");
            result.Add("sl", "774c1380b22aed9192e0fe629a28d461a498755f003a4047faf1368dc6adfe41ed9af07d954efd775a273853979dcb6c56fce1d387aafe3146b7a2416d075a95");
            result.Add("son", "8b1da6619d2716da02aa5fd7850418233a523dea515e25027f685453701b9e6220a43382bfb32eded5a63f88cb76e26f16bb94b82b7af79c97261c1ce1cc6037");
            result.Add("sq", "18a72de2438efb8cb3defcf63cc29f937158fa7a5fc137c601dd3df7422b4965575d9f515914b52557c6508324f3d84075e7dc03c9a27e616a8cfc3cc3d52680");
            result.Add("sr", "866da1ff990296588f502e6a9eaafb55134ba9a240d4bb5a6c019493684f5d721bc8d5fb3ba72f48940c48bd8b2893fa1232641a0210eb638df163c656b48a6c");
            result.Add("sv-SE", "f84486a654b6a27d86abcab6c52351cdbf67a3e462d02ba88d5297b1daa9b0720ebb3fbe292800602c9e09a57c25a783385d7656063be3f8701ee0db9b8c1711");
            result.Add("ta", "3692def7e0ce3943d92712d2e75e57c15950c268d4971ab5c6ad8958f30d3589bd827f9f7ba8ef6aabb8eef93e6b3cc989fea861fac98cdc4727efa6e5d93b59");
            result.Add("te", "722dd67a0f789c599f97fb79147f4f06762b376d74baf7d62b2d0bad4992af9877019ac6a9f2a5101e7b8ed32a6e7c6889625ebc27b3b64d4a5b1fa234dac9d0");
            result.Add("th", "2eaca25c9dc88befc7aa5e40b72fa88c31bdc1aecf41adb43b833bdd18e966407ddd912ba6a47275c468b4c0b3fb387299c1ae36b1a1ae91256a9829559a0eff");
            result.Add("tr", "d81507d09b936b589137bda77a0a4269c87544f5964fca393533ad5e6e0e8e81c3810bb1478fb65cb11b43b6e05d449464308299cb6473f2d2871cc339071a8f");
            result.Add("uk", "9f446fc4fe34a1634c1298d8a14d3aa696d5de430d5ebb0c9bfc7d50558689e5327f382bfe843826e130f25e34b99031ce2f38a4cad5a596164e69f8e14a6ea7");
            result.Add("ur", "0f085f1a0397312b71ac9559a83f418cf7b363701484f8aaf5e9d54b421339d5ae8681536b3bff35065b07d0e4757c3e6e82a8049571ea71caa13d41695a18f5");
            result.Add("uz", "c290576586cb84f3e16d0592efd352d0ef363ad336b3195492c4d2dfc7ba7f1ad30e414dcdc0eb44b82eba615342d765a0cac5915c041026b776e04cbb2c8a5e");
            result.Add("vi", "2b54d20955302e54df654bb5df94b5d10be9c256aab563fbc7634a2e456149ab53c89f008b424e25b9ad0568b75ed8212bdc118b4f50f1fc19f1c2eaeabbde1b");
            result.Add("xh", "2365dee14b9f4cdcda189f2ecc80dd100e83525ec34fc1b2bd93c6c8ac6d167992b113ea982724b9b3da6e379d3b5e4473becbdf9c1c123f3c22b4a02c49fa85");
            result.Add("zh-CN", "f419e16112ff291a58c832edf74478752b13df1df5516b051df9781d157cea6907545d8f4a613cdaf8ec0196e6b0e14c59179c2ba261574bc9e6311935f5913d");
            result.Add("zh-TW", "0930f35cc3cafb936da4f7bf870fda83c74bd608d37a9b9cf18211d8deea38890bc0193e799511778476d94734df9633d1c8f379def9403e7ee044bdfcead3b9");

            return result;
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums32Bit();
            return d.Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            const string knownVersion = "60.8.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    publisherX509,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    publisherX509,
                    "-ms -ma")
                    );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "firefox-esr", "firefox-esr-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
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
                return matchVersion.Value;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox ESR version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
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
            } // using
            // look for line with the correct language code and version for 32 bit
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value.Substring(0, 128), matchChecksum64Bit.Value.Substring(0, 128) };
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be update while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            // Firefox ESR can be updated, even while it is running, so there
            // is no need to list firefox.exe here.
            return new List<string>();
        }


        /// <summary>
        /// Determines whether or not the method searchForNewer() is implemented.
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
            logger.Debug("Searching for newer version of Firefox ESR (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
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
            // replace all stuff
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
    } // class
} // namespace
