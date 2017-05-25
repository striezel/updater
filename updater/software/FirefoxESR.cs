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
            // https://ftp.mozilla.org/pub/firefox/releases/52.1.2esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "fd98a69743bdd9a3589c69960e169d09b1e9d1d2d4254234a50a32e5854e7854766bdc4b3104332a0367977b50ed8e0608d424428f7ebbf10b150b1a79e79ce5");
            result.Add("af", "31290737574637f191331358651c62868ca291869c3501e80fa157bd2e26251c78f12d949a2ceb2dc0ccb6cda80df2e7801d049a3c3f275ed44f26fa4686346c");
            result.Add("an", "b2c21ead39f887f167c8f751b12f7eee824c9ab1fdbf71ab0f28111c699d60b3b9f56e87733eb4c37e9e736fdff9b7abf4230ac874869e16d22f7a60fc250169");
            result.Add("ar", "1f60593f4c46e6e208ea986a5505596e07bf9c019a6659829f5120107267cca8e054e602d713b33663f2f6e99169c4b8e0e2a0f2ab1312bd41a48d8e16e2a152");
            result.Add("as", "47c80d7d7a2c6c796d9ec315d24594efad1f73622289478224add1c90bca87c28e56fc90ee38ac60d2520c4794f493d9030da5822f5871496d8d1f64be8c6621");
            result.Add("ast", "e7f7f1b6ac3d411aa67f5a93cc2291cc7a906a181406b93ac36fe5927c9a94e4b0bc828f93eabb32e014fdb08699f4d7f28d6586d66e15410fb9c96fa62e249d");
            result.Add("az", "1b4610d0c95171843329339ae6484cdeaa3c499388b201e606c3c2cc57d31c81f3458ad1d2c5686d090cdc7048cf90c7ea237fe8fa4496e74cc11d98facbf303");
            result.Add("bg", "eacb2f3bdd508df4971badef77e12d0d6e9925783cfff289ac91edf8deb27cbda5e5bb71405216d0a23bf44d14d95bc83272f39a7db0fe0ed0f648ec144181c2");
            result.Add("bn-BD", "db8ce85b6e02301f99f09d095c43f486449264763ce4da197a920895004f49de7c7194e3ba920468ae35448dbe0465bd14a704a07c372f1c0b5e5794ee6abdbb");
            result.Add("bn-IN", "bbefee231f5e8813ff5ef3eac594d69d83f0304d5b446eab7bfdce1a6ac795b4dd2559c19e9e7d3500f0ed9279b1a79e27a4cab41bbfe40313d8fc0e97ab32a0");
            result.Add("br", "8f7d7a60f5711ca21499c4aeb2a81f7a13a258b516cd685ad373d52af2988020be130856e8ac7e2a71cad066fac4685d96f74ba8e077b2402b90777b73584173");
            result.Add("bs", "970c1d46758d9f516939e24e0693e73e0ec562137d0af92ec4fdfae6c0aaae5f56cfca4f7da6609334e56cf09c3af40716047e7b85dddfe0d400589dd0af5192");
            result.Add("ca", "fabe7ac0fe94a6c9fd66a69400a994b4a4d8edcb22f540de784d5d77243fbee204fa185a693dd283e8fb487d370d6595cec4b5ee8d12a98ee82b2ffcf742d5fc");
            result.Add("cak", "44a6df29c00e32320483a0678977910ae4b1b1edc663b9cc5aa0ff47a75ee8f7f687a6371670473b55ee64ec42b5877d4944bc814f161c3c0d8ad75ce2e7e84f");
            result.Add("cs", "14449b9ec01d4206b9de7c66c57d17e649fe8e094b63cc72f5fbede25f1d9ece7bf849d18bc4ba5dbb798d9f10fce9256280012ea2c3551e73c16f3656ed016b");
            result.Add("cy", "6c1791b8e9a91359a16268b099c2cdd936ec67dec1342d27c756ab576bd653f0c7bbf8cdf71c6a254ab3d7edcc5b1edff009bfb6620c4821b271e729d0e6f4c7");
            result.Add("da", "83bc20bea4ef8946485e9fdfda4b5c4871e64292b3161d157c9b54228a30a955dc04e047252804e5aefaa930e9a52450ef02e0b59cfcd49a24bfdb75b96ab617");
            result.Add("de", "3dd68bcc74e956f719575a2e5a33befbf39c5f9ad4cb9d65434168a8c196c180f865f75c672e1d687c1af2dfacc50a455952604ee0bf89c8f274235c1faa0d19");
            result.Add("dsb", "aac05bf39095b39ed7e5ec516830155d249f11f8a3239f61385f4fea67c6d96c560f62f9f42bbe6fdf9c6d5be8e4ea1fb0ab799ed28cc0f8f1cdfcf5d022d4ee");
            result.Add("el", "ef1adeee7c92fc9b4a6925f709819a118b5ad91febc9ea662c0f94adb74f0d4a1d7059a5c81f7280e93ae7e3ca6a54b9f2ffb2515b37a4c933c1b8ccf1191361");
            result.Add("en-GB", "3a7bed2eb08198c25a55d80538897ed46978d3061ec55e90fdf955f963d7b839d6a095fe44908b7944533da6e892d6718d6fb20946a1f2c0b919d937fa2b7162");
            result.Add("en-US", "dfaf0f829f5d3987f9a347ff96e52a618ff5469a82dd7450781e36328206048ee6b4a97bbf4b2c659422c181bc66c994fdcfe5a17e06e01f34c68b7cae07cb2b");
            result.Add("en-ZA", "36f908b85da20b73ca51b7962e4d5db0cf3f5ae179db10c90a22e0f9eefe1292e53e7171722d5f9ac7ae1f56739bc8046f45aa65d24d74b3f38e89e1fd0793ab");
            result.Add("eo", "8e3577d2e172eb9c8cd45589692acf9939f80193b0da93efd62d534b716b2205ffa299083f7398604b75bf6ba5810b3378fb190b4bea212ab2c346c3e664b598");
            result.Add("es-AR", "70a3d547137bd864f98f1ecc762e79af3cad17db5bd391db078c18f1018378d3501b5b3479c5b33efc1844e9d8a77e6f8dd99b6c4acb294473781075fccc1773");
            result.Add("es-CL", "3b0839018cd8859c89b4f6d6478a69477ab13a27122910e3facf24a53a35416af4510c38fc1e8a0b64e2b94287c788bdacd6892d4f597e9364832f78ec6b4fca");
            result.Add("es-ES", "a0948d74f5889c048baa7d7da9163b688600a86b044e93c2cd602e8c482b5deb372b7ac98dddf65bf61b97fc52ee9a1f97ead51a47bb7343923cbb82948fad2c");
            result.Add("es-MX", "f8fcf0e1472d1bf09d20d4355cf24f7fb0736b1c07db1fb6565b0cc98d965f36ef330962371d020abab12a077e6a1c9e65e01e874bd6b87b40a783f692e649c5");
            result.Add("et", "c38c63cefe64f3b14bb2a0aed2595d8931d7c236c874fe3e10f8596536b05a1ad8d01d9bc9fc6180993c59a077e8339ab25b44cf39ac029672aa5e7c2a1c35ce");
            result.Add("eu", "dc0b307f7a06caac30c9c7559889d4b5365bcfc7c32e2b1342d3f7245218e2099549efabe835c8c61ef221c9699710213fef790722468207dd7070ea2c48f2be");
            result.Add("fa", "5471d864821a38aeeb71f978367b1d7032fc552491d3ee0d096d56ae6ae9481f725660d651478ff0eafbea075f0d9f8852e713fcd70546fde51cd31a00dab1fb");
            result.Add("ff", "12581fd299e9cb2fab587650bf22fe00ca25898278f6d2da654a83d95daa35f43eb90aba2e86281f94c2047386a93071c5fcdb4b2e5ac08b93dabe4aee705419");
            result.Add("fi", "32200898b3a0407682e27ed22f2d9f2d6f65870a4b4f17a6e25caeb39db425b94ff6617c8cd5adde6245e1cb22b008f5aa89decb80296e7549593a1e685f7933");
            result.Add("fr", "cda7406fafcb74af8c925f3b2d1bac1fe0156da906644ce94840f3a53adfe698b2d6f73bad6fa4b36576105fe1b27175adf37f9394c502a0ebcfc9e5c4a985f4");
            result.Add("fy-NL", "0e921a46db2474c96a6bdbd76ba6f2b02fd079a4aa93490f0713dd0cea12b8e2d2e021ea34cb1fb4230c5e029ead43984009df2d5d770550071dd2915d44b7dd");
            result.Add("ga-IE", "f43f723f67a3bd3cd91f06446921cc283a54d4f3bfab8af2812e46f19490df9c5bbb66642fbc53ba0f612462d2d92f0c0ad2173358a8065685974913887ea5c7");
            result.Add("gd", "b19d48fc465cb5e24e5581abbd53eac9e12787a58a5c5634e055fc30896253a3961a865079d18b66bb7fdee6a52b073d21ba5ba7626e5b0ecdb07d52813c3977");
            result.Add("gl", "cc0de356345c1b42466939dd7dc9d518fc2519a885a41fa64210245b777e5147f91e4031fd66dbe73ad044dbf0be0697ed8474788b344dce4cd1b17acd725686");
            result.Add("gn", "e65bb4391731782be49a5b10cca2773175e5bf477f2397f53316a66b5d1c26269066c42953566ff68c6d3b5e37bee1df038f13d6d9d6c8952eae4f5f2a356136");
            result.Add("gu-IN", "8580c3ce512bf42b5b6fb423c01354988450d6893763b55b0f302cc6fea52a4c3ad209aa47f7dbbad7ae99425fc0e04a959c218c7bb66db9162250433223a818");
            result.Add("he", "b3de8941acd370db49ffdd939b28de2552993fb6b86974d2af793b583a1a9ea4b86f1b742e1a7ec00494f763a26b2f1852ab7ca75c9298e3bb03131dd23bfabc");
            result.Add("hi-IN", "004cef85c00a66de3e980d06c5b9161d506e685b9cbca51b56ba3e59d37b16edee4be5ac922cfeddd80e0e2a15a5a4517f21fbc6342b6c6ac3ac604eed732cf7");
            result.Add("hr", "a56e6a1b732fe28ccd83b397751bddfed75cc2748ac9f4efde1791af72bcd28f57c26247e3fb52e3803c4e29fbac0ef251695c91c0773bbc7119a1feb4c1278e");
            result.Add("hsb", "42cf03cdcbc20ff5c3ff848e5910a6d09852e5452be8005864e69c2ddb39305409a3d2e237ce3d4910cb922c4a83cce6b48b9cb5a61fb2e2af4cad72946f0b40");
            result.Add("hu", "f82f010ecb14ebeb62e86f272ff430494d43b0b763984b63c7430fe62336a0d90deb473db04ac2792b6802d49e86f64fd318791dcaabe8911009aaac981fbfaf");
            result.Add("hy-AM", "419bbde0a83b140780b66ee2d2c5c64ad6858f6c579a6fb824325f0658d405d40a15141d3fd2a36556c2157cf5a3fb2b9fa03db42a9b2aaa7e772e844cb6cd42");
            result.Add("id", "dee9ef371bbf6293558afca1a574a86a5628caeca90b62f47f93a1ea4716e6defa1387ab60b2909bc311579424fa26b54c6604a569688611789c36b8a71719fb");
            result.Add("is", "75a9f44d2182bb585214647b0c19be6e24a542e432d7fe188a20b093dcafcd6002a5696aa3f4f7dcd8792b6f5f093ccd63032d1b211eae245d9cfad4988689a4");
            result.Add("it", "2f9d01e6761765f28bc6e26202f788757c24e662764dc7df7119a43f27ddebeb3334dd398184f4d9b6b919a4a8b88f87feb037c43c7929fe5afdc13af76153c4");
            result.Add("ja", "fca1596e3643f51cdacbd0053a6343ef66b57228d5e1e5251b694761918a4b1179e8d7fc56bcb2a74857e82a0b05871cdf6a6d0f666fb34f7e0a2d9593f630c3");
            result.Add("ka", "a15d29970755d3e7e7f3978dd0594b7d15593d9fdee7865d01a11cb1f13c4e4818805a2c3c8a5440761c27315f9b674e6f7a9530d3b1b9b8ac5d4d87d57cacfc");
            result.Add("kab", "30ab0f12837592a94ab76aeb6d25edbab1eabf2fcc80ee4c03447b175efe19ef60409911facbc8d95d9df759c8af3923a483e52391083a894c0caf11d2e4af47");
            result.Add("kk", "7f85988d3716c47a9542bf3a26b01bed0f46ec022deefce6db452115a76d48452e58ed418407ee440e783e6e4ab45bce47ee23c4431fdcc2bd31d51468be6c2e");
            result.Add("km", "6856638e4d9afa6b7095b5231ab11d1ff5e4a304370960ea2c13755cc3c674b5adbc6314edeb1b3920ce178a766611ba2672781de96ca4333c264fbb3be8d0d7");
            result.Add("kn", "f96043c65f44fe3224f0031b4103b820cf040603b5028403f16a5af98ebd57e69c54956ba773706235f82678dc625b2be6cfca8acae71e820fff0c7f4f0755c8");
            result.Add("ko", "f48ef61771a83c68d167e1d954937180d222f528c25e8ab2193bd59898d8b8861361003179c8a993058d470e4b38f206d83c5ace465fb8bcff13bd94d525aad0");
            result.Add("lij", "27f2f12409e9125a5a8011a8ce773256799b8a8b67c985b35e128f3b0990d3f59689b1d43388bcf6053fc6921cd98d0719ec7d7b1a9997fb78528505e468679a");
            result.Add("lt", "15850154b0edbdde5795b07da410cb97d8c0b1b4c00b842b32a32b8482e85e640019b1dd163953ff2fd014dbc9c1e979ac044dc630df3f163ce4ad6139a5c2ef");
            result.Add("lv", "57be6c251c0e00b39bdd042657f297b6fdb309cf7dbc33c8ac99e4c8ad3ad27de9bcff8fe7062996c9f3af186ba3cb097eee6ef6d71f9be4c372e7ad7f6db5ea");
            result.Add("mai", "e2475e4b41c6acb96f7789c7a7cb7045a95d85dff52cb21ffd3f12b2c0c48c4f78f8a2d835471ab0d41e3a1770ccfa9df42b44091b524925e646fabdab849965");
            result.Add("mk", "6627e2c05195ece82cef37c046ce501083ba82d2376ca0048e4640294fa29f3db52dcbaec1b64e20878a25bb16c56ac9c2cfc09e4aa6c06a59f1aa7385ff9c0d");
            result.Add("ml", "9a31da323f31e65d93cfd36061dac9fb6e0df7a932b61cd7d46b4cc11c3903eb28d1f64a2da342d12889dbef83a35a02ba8dd20e286d278228cbd208a8ff3251");
            result.Add("mr", "d9b4025886e70b4bcbcdf261388499cf67e3b61c8a1d583cf9c4f512103efc0fe6434cf7419d4dae200b58f29aab431840ba4c8431cd2f5626c8667b4b146383");
            result.Add("ms", "de127f384be651dab88b0c4e5793001aee64113f87718e6fdf774beb3fe8fb76c82d27d8680e833138a1104ae6d57058f5a96c92b47f3a2e4cf1bd54729ff9b2");
            result.Add("nb-NO", "3d1f65d343000a9529a5a84e163c087ff3ee337f6c17571f360d839ef621dd4db18f5686c235f2689a7c9dd194de9eb6462752a612334a39051ecf83d3c25c0b");
            result.Add("nl", "3ba90cc7cdd434401ac31760a12850db871c54c209bc2a6bd269e3cdfa42c3ace468448f15107c021e765000ab9cf1b590a3a3836abe11a0f4ff6e431200c1f9");
            result.Add("nn-NO", "ca1f2e33c39aeb7fd444a33c376dccc152f8441a6d2355e3f4870d66e96c518b55ab1450819fc8fc1a2738c6d51983f2d5c87ba898b8b4837e68140e31442e76");
            result.Add("or", "6c0417dd8398ce2a3d938a08ee71a75c17b92843d0522f8bf1d188afe6841d9fc108df271c3d31910e72c26c129a7606240b2c45134af8bf8352f665316f52d4");
            result.Add("pa-IN", "9e0db0b0cdc109177206f38f035d848cbb82540f64918f3582a6b00af7594df7dea791e0f4ed4d5357c4ed2ad38794c841737f094e3f969fa2ca519d75bfe821");
            result.Add("pl", "403d2e610eeaf1a678b130304ebcaa9bad2e429222c5d3be0b45b46377f2da895899f0e8bbb7643553f7ad7ac5b1cae3cc5864347cfee239504a89ba6449f114");
            result.Add("pt-BR", "3874db3074d46893044cff0b631dff7f1ca0b3d27434d4a2fa69cb5a285b26fde55a2e0caf78399530c6bacf64bbac3e3f09858c49f5936ffae636899f941651");
            result.Add("pt-PT", "c3c090b467c7f57dbe82f6343b7e69036cf844a45009889609c793e7f06d607c7fe971aa49c37287e23f293db4cdc6f0b14135a20dfa02b8dc784a877f6afbb3");
            result.Add("rm", "6b8fef96ef77dbfc8ab18e46ebc8cd5f7e3a21c15862c052c30c06b16af1773fdfb7562c058ecaf934f586b9b4dc343bfd23c58f1be15b2ea44c47f2b1399194");
            result.Add("ro", "22a7faa86a4b28b2e709858c5ba0aef08fe1ab19635aff3ac267a135a33bccdb5e42e1cbb0f4fbd266aa9bfb1bf60587a5e03afb60be07f4515c12d45aac712f");
            result.Add("ru", "8d230c377fd5ef0c308f21b419cb110b976a67b5e8f7338acaf7ee1604d363b06d8ccf3da6079722c2018e886f157912162e35583b96c3af8d7277e19adca8db");
            result.Add("si", "e502ef0556cd4daa80992f61d2421447cac04c005e69b032280139ab05bdcf6cea5c71a7debb48f59fed2c498a64e99a2166b67c554062575a5b5ae2ba13e388");
            result.Add("sk", "9a35cd4de3f529dcf9e7e2a33421ab1bcf4b5f6c3d6b1dbb6e029615e83b28e58a598c2fc885f5570fc07f4d53c9bbad7ae9f41838bb315b88b8e728d7b77462");
            result.Add("sl", "8260ba702663331912349f7ae1cb2b2c4cfb9550bba4a455fe13df81a84620aeb48537c449790e5cb7373ef0618ffb673ed8b81619a1d5ef4d184ef464451201");
            result.Add("son", "1c48005c87830350e3053b0eaa8bebb8c9a0cfda6f49e5342d69b032df23f5a8d3f5e8f81b437d583b0dc345a6c7b28f1b4310f2f5fe883789d9d3b62cd01976");
            result.Add("sq", "83b61c047f1249eaca2b1a2aa1c7ed09ea638b8f542bace1d87d4f8f42eae2a2631d825e0fdd93f78e5b3d37e008742a0ffafe341f32b86a395cbf5613f5ff44");
            result.Add("sr", "a76c299aa049913109f4e450ec55c7886ef346bcbaf78d8032f5b73475dfaf3acfe347e406b7d0c070ee332633e5149a8745f1c10fa631c013b69875bf9c486b");
            result.Add("sv-SE", "b9219abaa47bed733e6f038dd3f85d8531c3e7eea9af11fcfdb9c2585049bcd8b34a4ec85dc42e6664773394989428085dff9b2ed74610cf948d10ebef55fb1d");
            result.Add("ta", "f336dfef3727d29c954b38bbfa1ba2be7872cca88a95c1da898973d8672911085da04964755478fea0a0676c2cbe5e57ffee479194a9832a7a03d529a99e3d7f");
            result.Add("te", "57c9c51d85caafb69860c1451d1330aa5cfd397d004251c897b8399ce083bf64e168986fa8df35ab3544b8b29494b106d11bfb9d380a513442221d80b0eff53e");
            result.Add("th", "9ea2181dfa5431c8626562768d52316ba89b269372e9a8d395b46dde644f84f2940ba8c527804e913971420489dca8233943a7947464b4f01f5a55ae6410c4ce");
            result.Add("tr", "5328b7149c053fb673ab883c7ea3fd76286683194c9d72bc9f00ef87fff47f2f8b70b066e92e1ee54da9b10e41dd973aa72016dd6efe3123921273e767b29930");
            result.Add("uk", "8f566598ab5c5aeaf07675deaf669a6b27e83075d39d5b992fb73ce2bf1f376635bc6fafea400895bf3185c056c62f99716a4ce7afde4599d014861a466541d8");
            result.Add("uz", "cff2343c7d37dff99b4ffe7908f489aeba5c8ced286cfe81d3946788c55eb635f6289856e4362ec475691d23b73ac0005ade577c7ead7b267718849a064ffa42");
            result.Add("vi", "37699ca97470d5819f83aeb329fedb6adf6a19bffdd1625d96798ed4dab038779ba66fa8dae31a2da418c55b602dc98c0874b1bc2fc15d416e0253af088a779b");
            result.Add("xh", "226f15fef71c82fb359d1014e0aeb2c96fa642dd32d0aa4f69e21734247da107d2337c9c268ff4d0924c5a397a13487240d36aa66eab475c1debf33d9de48c45");
            result.Add("zh-CN", "bd95b6c26b6517a4c59fa93b655312eb88f9022be9d620880762ab646faf61b12c7b5f1bf84166e5c3aa6d5f0726528b1375e266bf7c072788e2e387811ddf97");
            result.Add("zh-TW", "405861adaa6b01456699f457d6ab7f4fa722b45483380647becba22b560e8eb3db9edd726d69f42a4def59918d7259f13888c53bab3a238f048871b2bd71f0d9");

            return result;
        }


        /// <summary>
        /// gets a dictionary with the known checksums for the installers (key: language, value: checksum)
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/52.1.2esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "48ecb0cfa6d488f590eecc8da92fa74dac32f46be51ccdf18d33b9336482764f5c0319102447489bee0d211366a28fc486e12167c820d134aee1bc790b66d50b");
            result.Add("af", "990f8ba3ffe36b31243899215bfeddbe801557f45b5de5853c9ab2a7df422950a83955d554c86b630db50d3f355563e183c0550db5296535ba7d71897e386e73");
            result.Add("an", "349a70e0075ad88ae742b8f187f5426d3750ed2c0a6728bb6cbdf35c538d1603f494c0102f5615b6e4e80a1da322ceb3f8b3902de81645a2ff016db1f31506c7");
            result.Add("ar", "f348ba8f283edd057b52b29827350e65a686edb405c49524be3ddc89d3a3e51c962b94f9ddc4745dbe57f0c857b9f6325e956144630ac7ee6051c0ba6b5816d3");
            result.Add("as", "cf0b1629854ba1d70be7230d3a4f1f786d42dbd6d601a68400f798cbb70a9002b18caf58f95e041b81d9705f690d14e30dd98496924dbb666fcc362c250a8010");
            result.Add("ast", "a09ef6530a50c25593c1153d27dc7924e475ec82c48df8fe756b8a1a5b15e5036ac37c9983fce80de817d4ee69dfc0548b822028f3c36192891887bcc3e5ae29");
            result.Add("az", "599b57e0336d24027404c91ac82723b41f2256ec5c24cd53e777e9998b290ab3bd5491b04517c3c3f9a3ddf694a42c1c6606c8323434ade94e3b29e5e2641098");
            result.Add("bg", "a4f14f53541d61446dbe95dcd14ee183eaa6ef00bb8774d02c18d1f35185a77e68e197252c289882c0a38399b79aa526174867692cb63767f1d32b0beb9af9ea");
            result.Add("bn-BD", "b539ee6ef5075e84bac762fb9c8a57059005cfe2be98b7cbf9b98cdb399dcea353911bf344e87ff94e01c15af5ff07ada71f1e06fd221b97b455ff492af7b5e1");
            result.Add("bn-IN", "7e8c89a7f7b5067d8d4fdd81ff49f67301cffbb2c498f51c7c225db5d37edb16570ebacd7f114c8d65a8c37885e701e6fa075a10d8f55385423f059d1f84bfc4");
            result.Add("br", "f0ceeb5c1b261640cc460baa1b56308a7f311df484aa72c1b819b7fb27d5f6694bdd8997929dd0b35d3ddb75571a6c430c07157df5c0a7825b841e0a43a073ba");
            result.Add("bs", "5c210f4038e962d803d287863b68acafedbfb0bc65e83b3b468acb2d21b2591e924cf4a57e7cb12d4b89748e5f118c810d8e2a4ffc2516f1e01768166a0aa6cf");
            result.Add("ca", "c040140e4a5f900a1c233c165f9d04556b5ddd94195bd3dd40fbc23de74cd3f3863075e7e70c713f6bc87b8682a168b141204f3d3f8a472bf1464630e81db335");
            result.Add("cak", "ef11050e97315ca87997da26ed22bc7ef5b0c67fd15a5bb09e6b1fb1ebba9cbfac756c5bee0745de7369440bb099d4b7dd6c1f69b9f28181cfbe2718890942ef");
            result.Add("cs", "69b0c1e8dc2406647bc154fceb198eeddb847924460dcb431508c68a0794e7318ed333f2757ca05e8168c40de900307b40d1c385ed626f0c853b5555b14b4627");
            result.Add("cy", "e67180d778e98f88bbdd019a0366c87afe180364768a550f6b61b6f6c5317465f44c29c2790eb33efedaa442d7fd5fef7e4fcbf10f161d7f18b03788f633ad58");
            result.Add("da", "8011ab5e56f241ad9c4ea3c8ff3f1ab5dda06488821921ae1d610534f7c564cedf6b59e498edfb81af35700f76d2c724486e195de1bbcae84d1681b59903b0a8");
            result.Add("de", "7b1db24772bee697e98068bf7d7452e1eda2bc973a2b6cbc21cef590f148c64453f3db3aea9e6f9a416b5e5206a72be4410baf58e06e1f2851ac807035e5cae5");
            result.Add("dsb", "f4713ab218f52f33d0e56bb23c2fce4a896231e856dce20798f9997b4207ceeec9c03eaeceda483aacd7af79d1c21905b251745894565f8ecc7b0633e1092bec");
            result.Add("el", "021d9a4ebb91703c3d12f1ebecc932245231a07e3b573639a6d21a9941df1deaf035825a660cce3f8628f39c9702f26d8f868d3af830114df35ff9132e255579");
            result.Add("en-GB", "e82700fea2df2b283c70f6a96fab5c8cb4dafce0564b80feda52324c559414c9e7d14f40dbab9fafb2a0566efe3c4c21383abd6f0eb4006bb3bfd73fa6b18590");
            result.Add("en-US", "77dd2801d2f0b5b1d629009eca841fecd01b76baa3b01e01f95da5a7c60501183b78dd84c0fd5c0fd44c5ac6446131ceb9c29d2cc3fa6d4105f6b09bcdf44b6e");
            result.Add("en-ZA", "5941f80fd11ab04140d30c42173aa35a80ca31dcd80d573fec64364c1931f53afb34ef5c1983b8481795131abf3f635ac9fce7e8fce72a2b8349a3d11e9a5c44");
            result.Add("eo", "de19f1b2a929ce5335d15bc035fc7d7142dbabbc76ade0c7ff3cdead406964ad5c81f2c5d3a3b01537d2ebcdaaa35846a3195136f42bd90232b6591c700f6d99");
            result.Add("es-AR", "e335762ec05af98bd1aac004b61b33099884ed6e81fff6bba44caa69e9f251cdd836dfcc018e3b6439355fda91af409960264be04ae010a5af3cdc7448ab8705");
            result.Add("es-CL", "5f7f12d349498dc37e7a725b7a511efbc7f043e045fa151c02572ebded9b1dbcd554c2ee240b0c554674f4eda7f4bcfaea3accd905288dd005312a4fa52d3d27");
            result.Add("es-ES", "a4c8ed2b3f337cd853bcf91ce8cfc3fe8d4e92bd3156f0193487889ddb77a50db3b2e0ca8edbb0f2acad49876336fcf056261ebcaf2078e460007c6e6093c8c5");
            result.Add("es-MX", "73ff7d890b73fde3125ea4fe6bc71a3a7a55c14309cbce609f4f14a53808c79f3d1bd4eac55b44b38d7fb553d15ae9ef986623dd44fa7ada2816858c4dc3f5d1");
            result.Add("et", "5f91fd31a7d7ab61a5631057da953787d0226b7f460a7b287c437a91aa452a9c4870c95496693c96623bd1bf46853805054f673cc3da2c9159cc1cb41f0283cf");
            result.Add("eu", "98b26e87fbc649fdb9b8647ddfe7b6bbcefa15bc0161158426f6f1cfc289960e5d1748cbbd2a2303a898ab281ca5122b966df527d2074d7f1e1ebc80e595a60a");
            result.Add("fa", "493800b82149bd81e71f402407293986231c21d1ed925a0a85cc41750b66ffcb81ba20475e23a4199f307593049afa6c5454f562ba6a17b497d81db821a4eb76");
            result.Add("ff", "623c2446b36692df7786a6935c0a2aaba56c545a5a98d505861b980d2302b8a4e3001292670f24e83adcb309098fd2e5eab8a7046ebde8ab7d6b0dafc00ebbb6");
            result.Add("fi", "55ceb55a7ef7c0d7582b14a193dce6732add88b8e35cbd4405a1acc557e6b3681e2f4d998c9715afdbdcd5b27538862ac590eff60e1e47746b840ff3234fb45b");
            result.Add("fr", "e96c1a0dcb9166015dafb9c2a940a06730f56bef550cc15e39bf3293c2ce82d3b5cc39bc4802c182a6fd10ce585659b09944300909d1279552f91f843cfbbfa7");
            result.Add("fy-NL", "4a45e8fc52d136a46e5111dbbe6ded875bd8dc33af98c2959a3c80898c9df11a418c6b6194ddc1461f8c5a5f9146be155f287608258b307e070db1cea2a5e103");
            result.Add("ga-IE", "e8b2a37feb00eb7a00c03197738f579e726f279ac877c8819e2294ffbe7e4b168e38cebd6b94f611514ebbcc17c123ff9958d6bc6563093c64a11ccfe4a66780");
            result.Add("gd", "a07faea6f2c74fd606f1b39a185f7a3fd159c8ac62854ffb4a1d7c36f9b8e63315836022f5235bc8597098087ea7f30eeb12a6d0c281b9f0d06568b42af4546d");
            result.Add("gl", "c4c00ec71cf0085cedfa55d01391b8c412faac7d7c1558d5acbd489594ed81d82d261db2a9093720ccf45c2bcedbcbdfd600736cc34f5281da0580db2d953b6b");
            result.Add("gn", "db78b85d9d3ec5288c9fb5cbc2264513d203bdc1b3c192fb05844d0822abff036184ebf56751fd2641e6ae2bbed2863014aa3590530d7714c6b2756765b96239");
            result.Add("gu-IN", "520d0622b5bb39677254c08f7462be9b1073bb4d9132e831533a203c3169053f8590b2b188e6ad8850bd0c63d8a2a97fbfea02d92cd1dadbb2d294a7c3e1ee23");
            result.Add("he", "b12a0ad5a76a875ee78fe161e6daddf432190d413b192f8e96bcc8a83b913cfda5e5f2e774439e82efae2cb9817f2b97c143c5a4e7c4d2a82349b3cf2626dd09");
            result.Add("hi-IN", "8f307993883f3eedf5e5dfbbbd0ef3593bb61dff05849d4d983d8ab7942f74b73a25ff24e52ff9e96ac3229d0d1f975ee0108db175a4ba5b46c866409a70dbb5");
            result.Add("hr", "e1785144628bd5e5e189929ce899203683ea697fc63ac5f230e40248afa5415e89bdf05e862e9aac7ad5f03e9056a9a69d5965f7cd321776bd067cb9ab25ebd6");
            result.Add("hsb", "0d43986d396ff07026fdbf53e3f47901bd8c7fb28cd65a0d084e6fb8abd52d046ce603e113bad0459d1b964e80ddc05acd90ce1593a3781bda0e9e4739ff8743");
            result.Add("hu", "317c1882863f9a45af03cb333ca2ef0266cbaf54e8ab3670828eea2d44d646de70b44489a14da23aefdfc9a76e9c0a809306791b8c90ef18a370762d77859666");
            result.Add("hy-AM", "c60c02c67eaee394e6fdaa9986f1b414f0ec7ae4a5e3b2f3d49f514c08ec4fc7d0a9d38b7593f649e7eba49d48033a5ab525ed93c9a704ccdb27fdf6531d5321");
            result.Add("id", "86d6c3acaa3692fa8c7b6ee7b13ae7d13a74280a222fff9ff0959ae78ea278a29102871e2f008f76189f0b9e0b51863d5b36c33760f888950f5db5f9a224ec2c");
            result.Add("is", "9df8594cce2a1ce1f758b92e6861893161df09eb4e1f8ba74a659905087ca5eae44f872e75ae1a5eb77980ecd27a0bb4f4999576a2fd064420341cfebdb979a7");
            result.Add("it", "a31e204e1853d33d8b26d2c04d183a73624834e55592602297b9003d08418c137ffcdc0a2057cd8c5306b06fa7b733ee591465ac5aee2a11d58d6b379b11e487");
            result.Add("ja", "9cf5b47fe1d83f9cff2391905249b1cc03b4d2eda1a81d05cc617c646a9f31bc2e7c79d02e825c7fc3827f7f5ca99e8ff22e3ec60bf81b5c5a165b93900780a5");
            result.Add("ka", "eaa65524fa48c040116ff52fee7fd6bc86c8ff14ce16972408ef875945173fcb7b9b1e737bac004344d7b28348e19d83acd5c3487a7f21f1ea9890400f6b30e7");
            result.Add("kab", "f8895f93f30b501b6a6abf64f4949bdd2226bc65b4c3c990eb3625d1211c0c8c1d211c206b57413a6455b46f3a85d5d75206e60db26ad7465fd9cf5e96f08ae6");
            result.Add("kk", "cc83978730e594c5588f97615c3bb7f5925eb76ec72bd6e3b5c8fb09b53eb0ffe7eebb3ade84aaf5d7070a55211eb694b4dcdea27f4243172ba8227fa4487f3e");
            result.Add("km", "c991cfad9b1f4a43b553726599b2e21bd94e7ab1a83a04f58bc8ec6f930608370f5842333b7c2691e0f70a5e5c7c947164e4b414c090f4b4a3014c2affed0471");
            result.Add("kn", "b7e2e5514d2ba777a5c653f367ae6ff961973eddef897d9f05256f5c84d188f7692239f37289c8026e95f487b503fd03678cb56f6694f5c8f6b88e001150caaf");
            result.Add("ko", "12edeff3b23e6702deaf4ebe187ba57001eccd919dd57ba9223f4c9477dc4aa33dcb731d839e1aba6703bf20f41893ce2c8c7e9711cfab0aba3d98f466c34759");
            result.Add("lij", "9ccd0994a2d6726e19b01adc4ff78f4d2596e9d9237c8ace2256704319afb2ba82d2491267fc8fb1dd3830e59367c7f494c827c924004bad1635d41518cb0d7f");
            result.Add("lt", "0f5ec682ba86ae5bb0b64149e5725774ddcaaf938d3efc7aed751dec0dcf153c53d46f771490ea6a39334368991f72e6b43dc78d7bd8e717e2d53eadf5ead9df");
            result.Add("lv", "acf4867fc3e3ed5fb3522e29c4cfbb63d49d1f51ea47aa5489184ccf9cbcd4c5589480c229de419be3edbcc5632a59da1d9facbdfc976877251295a62b75fc4c");
            result.Add("mai", "007fdf60fca886dc5d7f5b8a09d45d06b975a97d3f1d3000aa8b5f238f661f46d26a135c9128c84df8c460c2e600d0dafb5ef5ebf817415b1a85c5dba02662dc");
            result.Add("mk", "5f9eb6aa3ee2db381e5164c0029177e5cf8a0fda1ba613b2a3bd86e531a4cb7a3c6c97782e92b9faf89c2e1f7f9c2cf1d914ecb7d5daad775e44a9fa03909488");
            result.Add("ml", "566ac1df060f71513b803b3c0b312da4d145a1de0bc8095fa31a1498dcdd00e607e6fd924b5edb55d0773d8e6701a083583f5f0adfec129c395929732b9066b2");
            result.Add("mr", "20377203556e105749438c0ecc1e6e32c15419794ae55e772af741919ff1b6a81a314ebe9cf69d410b5da6961d485ed764c2f587d6a945733cf2b423fc3840b9");
            result.Add("ms", "ff4ffaa69fdd14d13f4a8c6effec596caaba47e6ab799f49e204945440d1c4740e0ead4fa023f1460a8d6d5f6384c772fbb1541ae1db1a84472ae701d91f6bcd");
            result.Add("nb-NO", "89b9d81119433f63bbdb2be35d2dc5e747d66bc08eb136016ef769a1b562077589da4de731a96f0440182060b2bb4ffd2baab2d7156f8ba00dd517967554c3b5");
            result.Add("nl", "3335d335397f331d4f3a3336df0be305e2777d11c99eef68de4aed2a8a7527648ebbb288fcb454177af0337bc1b67b05d26d983166e16a7501b78ff57b8cb022");
            result.Add("nn-NO", "0c9df1cff7bec14a7b71e2041df134ac7ae9e45ce57b54edcd9a3a45782b8107c9f5d92068d1ca16b83f1c139fd18dbdb270cf77a28710fc6fec26ab2e3fc829");
            result.Add("or", "4ab5a67db63089d0f20d441d17086583faaa972e784bbced9b9d753389332e3b9cd1388fbea19204b01c4ea846bbb518365dcd8caf398186bd55b16d9fb6e7e8");
            result.Add("pa-IN", "7f393c86fe4595c01c957fcd1ff95ff6a830a5a91129488288946fb8e478f8b07b9e9f87675e7f980c9caadaf69ec2a985874f9453c418e64f902c26b4d91864");
            result.Add("pl", "fa330284952138f60e499ce435794d931d03a2d24b89198b601e8cb13762e9eca9f1c6c18bcfa4f679c7503757654e3e3a93fc8e2034c6bff9567dc290447d5e");
            result.Add("pt-BR", "9b0888b6b7b9d3d26116ae0cd7b4b9a1cbc5757143d8a9c416d24e582965c412471bda873c7b64a97786ed6e56345ab6383b97bfacc1e6b548e642fd25dcc41b");
            result.Add("pt-PT", "cde41f05b42aa811d3d6f5eaa63fb9109602c2a5ff146c2e11148eb2144e927fd7ff22709459300add4ae7d707fdc021a8d58058afb76db0220f3f54cdde1f41");
            result.Add("rm", "4db6a9868c4148269ec2aeec5d485f450ca85c169f066940eaa61d95db59ef81db9501a6e484dac44807c83469378cbae6b47b8fe13d0158f3254a9eddf8907f");
            result.Add("ro", "32818e80ee4ad65e57b91460343b49a3d65ec6cecfc01f7ee24f6a3e2aa2f7f2463307f9a469895f6e3e438d8b0815383b3f2824443d339e20631cbf697d54e6");
            result.Add("ru", "dfe6fb5ea0e15f1091e021cf1614ef66e9957519069670d868bc4a7e791dec65eddd9bf7db81c9773bb92a35408e153d5ed80e1c45571c24b8e886d292f08ef8");
            result.Add("si", "43bf0de4b9f93ef764a4aeb355e5598bdc94944a35b1d3d5c2185989a0cfa8994b6d69ff9cc71cf6c0fc961e3c756eff093ff44ba2be4018da055ae30339d7d0");
            result.Add("sk", "5f7088b181569c9bba22ca575f509e8893f8d3c0acdc56acd39f4275bfba90717135c5f395ecaf2831981490d163ece71f4c9b2c0e7479e2f877796c78e2aea9");
            result.Add("sl", "fa97ef02f8372b9e711eada2e94b6230492fb9751b9d88859335841be49d71676b782841bc059c6a87f639ecfae6583290c4969e045980dafb350ab46c471437");
            result.Add("son", "d11b7e7c7663a33c15ed4771e5cd3d61853c2f64215c3d40b9841a332562d0bdc87334be87db977a156c3c431fd0e9c250cbbf35260c062cfe8bbc364a8dc721");
            result.Add("sq", "2742259db2519bd60e5178b97fe8b91120bc04ddbcf94d1ba3312deca8568363a96af0ec5bfb904667727f3b3585c4e4b964e8a1814717c5b392063618d07c0e");
            result.Add("sr", "90154f9bb27a4c1a482ce9ca6067da2f6b91f06b0bed82b3ec02ba0741b995c767c159ad4c473177b3029de8e7589e3d6676ea3d626d1f829660727e23b7fbea");
            result.Add("sv-SE", "cb7e4fb5391e705c240cf56bb0a1e8fef1ff135ad942d59addd8056c194b857b446be73961df7b7aa30e13f3ab9b6f1b0466c9bb9ffdb439737475d79b9b47e6");
            result.Add("ta", "4e5563f53e63b6da2d5b80546feac7027e838a54e81817b7a6c4b5add5e995869dfb9110719599847b0db073a0d6587074dd47fad4d3609b96e13fddbc82920e");
            result.Add("te", "25230f702fb408436008d73e4d14d6416431b596189c816baf0240cc0d1a7193435afa56e712ba84df12b37d9eccdec8d091f2a90a1d7fe0b48ee26f2f796507");
            result.Add("th", "0f65a450741a87180fbcc1309fb54db338700122fd95daa6a818a0654519d56074e49a7bdfdabe16e4c87aa33b806590e337c56299bfb4ce0d5a2669dadc4261");
            result.Add("tr", "8b162d24f3e67347ae57388b49c6af7c54015b63847603d406ccf28455fa0e1efabe4996375ee05224257500c98201d2fbf6315dee74a3059735193c07d08939");
            result.Add("uk", "c148dd72a9267fb8cde097d54c059e13f0ac77eea581a32ca4c998fec2ae18df055b29dd1ba83b7a80688ebe97b6d3a6f1495845384a3ef9a0d4a549622ae0ab");
            result.Add("uz", "63b5b0b4ac73febbad8e6890c871de822d94e5975f585e1ed27ef9d7738cdff8f9b82a25de42ba8827e85f4aa78ffe1e64838b8ca110ac8a58e3d853861c6f7d");
            result.Add("vi", "83fc852dd932a93b38cec4dca4c64486fd2c0caa6588db13fe51c244689494cb9a8bdc97e639b1bdd400a7a4004e2c5f754392120638de7c662961b0cfb10856");
            result.Add("xh", "c54adb0a937e38a65fead8669314b59412f0e0b1b1f0ebe0f0e78431457ab69fc87300e3a7647a14b1f2b2f376b546d04bd73eaeb97c1e1f80eca9ab6659d0a8");
            result.Add("zh-CN", "a7ba119fe16a3743007ca504e2e747a193d16bca08c74afed83ec844fd796441806cd581dc27b8015204bc20c55d58c896d406183bf49f5aec97fb3cb2e7a50e");
            result.Add("zh-TW", "54bd88189e1a433a53fed7e15b1d3f32e43872c9b2c71f5e85af3ec56dab3878961ca4bebff9d964d505b0d08fb0f170e8fa380414d605199f1ac2bd45c3d039");

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
            const string knownVersion = "52.1.2";
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
        /// list of IDs to identify the software
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "firefox-esr", "firefox-esr-" + languageCode.ToLower() };
        }


        /// <summary>
        /// tries to find the newest version number of Firefox ESR
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
        /// lists names of processes that might block an update, e.g. because
        /// the application cannot be update while it is running
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>();
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
