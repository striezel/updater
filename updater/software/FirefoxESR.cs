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
            // https://ftp.mozilla.org/pub/firefox/releases/52.3.0esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "0e64cf44d06474696877710a2925b7ae05f4408902a4f97bc7ae78c2c969baab326c438726035dadb61dac1d66743d1547db38c0895a19e2c251900db50ab5f6");
            result.Add("af", "8c656c2d23409a972fb670c871d43783521f9227e87215bb4ac2b3397ccf2c8768edfedc6658295d1e070caaa8e81f13e027aacfe4e8ed1b126680f779a75d34");
            result.Add("an", "3140ab1b78a320113128d3bba94889404c85802cf393f664cf8755f99d00c45d8687d692fc93e29daa82b31bed339bc528070b7d4a63212891d322de46bbf42d");
            result.Add("ar", "9bc3f8c47beff2b9c6ea6069bba2e78c81205b5826c215ec35cf5f2dc4887e1eee452facb6bbf50c125bddf2285f3988c3dd8a959d87bd167a936b5b9e1262ee");
            result.Add("as", "b5848eaff052601c73847f0ace2ab61b19c9c3469786a1057cc54177933142b6bd9edcb20ed2e89a2fb63de2cc9a4c886a2d78cf99a27cf07cff9002979c68cb");
            result.Add("ast", "eba312392e52f246202c55a0b1d86635615d1015343b010d0e657f0ce01526b9f73c85dd82e2b6972419d55a10da76de18ce4aa3df0e0ce07f8f9707b4cbeb65");
            result.Add("az", "97b941218b9240445a8e136f2bfc957626116694e4364520607f89bec2b09619be7bfdb875a75f50683bc951619e16b66d959ca16a02889a0930ad4961dcdc13");
            result.Add("bg", "19742db5f82eb2f23c7c987e0e2d73a6e31dc57eb65b0e09ea9313e871c35af1f8815aa8241727c94629e150aece7517ac7bd7b5476fa13f1c0e190f3ace627f");
            result.Add("bn-BD", "f50e0a8f7219319a0f3bbfc65aa9fadec96bfab5f7887646ce4ea92527dfbf447c82e333d697b7680388e758e5d1a0d5cb102d4db0fadd9997b5b45ced2d9d68");
            result.Add("bn-IN", "e223e65666857cd628f8bef53ac8e5e77abc0e5a3770e8c2022a499c4c8af50ac1b43e7301e89abc5eba4a7654ea9f79f50df251ba7316f2953cc9d42b9b17ca");
            result.Add("br", "101156a8fc638714b95ec4db67a46bd70eb29f434d3be4c2901f4be19bf7ada8a8e721bd6b1f99d97d28f1c40bd8e8b0fb85e652b1856781e0a565b8cf6cf8ee");
            result.Add("bs", "5749bd9a1d47057c044c1d5f0b2160ff7f8f4c8ca1f83c253abfb223a3e95080cefa068d433bc3eed796e4f12f0a3eaae1cead362682d2a4b4d86e48a0a6fe41");
            result.Add("ca", "41bd3744ac60bda0cf41cb708c3faeff34526efd44e4ada64117f62ca1555cca8b8e0a2f56350d5ffb5f07af4a8ae66fc0e3979b2764bc45a1017cd7f12115e3");
            result.Add("cak", "442c17d0bf21a61ccf67940dad814d4d734d09910e461d95fa51ec172229f0ef15f17b319a85dd89cb0f1ef95233cad951373c93c57822e8b09e3fb408e27ecc");
            result.Add("cs", "290126e5f0f3e0039810ed3ef278d09843ad5751fbc06a988b9d807e996021473d53d41967d8b2878953259824242e041442b91f773108898ca9c27eae9c679b");
            result.Add("cy", "abcc27b226aa0a48251406b01418ebc0ab83ef7809c8c42c9282eee4bc3ee908b8c2028e26fb4331e6de03240eba97007153526a458ac857c2af4c2eb1049827");
            result.Add("da", "2696ac92d0a64cfe944dcb42f6dd1e5cc2eb9c2a8e1acdc31ab3b30cd8875a82793a682f34251fb8ef8d66990b68ec09115b2735452c3d6f0feae9b50ba46ec8");
            result.Add("de", "80b9f362c44bf1c693fcf3dac0c5cb6b454cb29485c0d78120c6f45e5e3c4fb6b5907fd011505e0f1a811f649bad0c321f3e471bb533a01ca91ca5e5507c3d20");
            result.Add("dsb", "b72e7cc386d8a2324506aa68ea29530e55eb4078d615fecf920c2265965e27373c39c71e32dd583d7ea8e7d1eea2f316377787d01d8eb95fba9179c08cf04200");
            result.Add("el", "cfc7de2a0d10702ed3acd3bc6c99253cbcb0a82b31aaeb8c0c4e4b2cae15c87c6feddc746c2fd4afff74bd12f1fc1ab216fa3730fc88b0b42d2081ffa711de3a");
            result.Add("en-GB", "9d6b6b10142e8540cca56e39ad36c9d58a25a8b297c4761151f63735ad7c16973e429da6778a28e961df346d7170d57be4f769759541e3179c285c6cb12136bb");
            result.Add("en-US", "00960781f145a996d9d4fe825d138e8c4ccca3d7baa6604f6eff9375cffddcc379d7bce66a50b5b50cabd136dfa74d6997c7b7e48be8d29394da1750be024a32");
            result.Add("en-ZA", "8fb9f7fb2e5a41dc23ad5133290d1725be680b61d79f4fea196282977b5cbd477f7b600ccd798b8fbd36898a785d98f843cf9340f5bbccb896e118adc6e31f2e");
            result.Add("eo", "10831a23e29ae2357c216277a560235a0eaf9c8324e6c2775a8e5cff1f64a99ebcdbde54f23adc6980e73f0c8c4814f7128f9cadda2c0a92832d042475e0cb21");
            result.Add("es-AR", "7f0504d0395264eb6e80794e2440f0c431608cd40051c61076634ed3a0c544b70c195a2cb0c4d10a656d649658b0fac835359e464c5262df549dee8d1901e222");
            result.Add("es-CL", "90f679f6256c1ea35bc8039ab93fd49d4cf88b1cbe020fc4323286a1a0d40dc4324c6c3d61bdfdf1a48c68b0ddebf9586e24427838b12bdc4b05c37faf646a72");
            result.Add("es-ES", "ead6d8fb7ebbe9c3fd3bf198202b3c151d4f0b1e6dfcaea95031cdb0c2172961bca29380f3c8704b940b53513eeac5f12fbd5cf38d63a281fe0950328670d2b2");
            result.Add("es-MX", "905b73362d0cf2fd62f82a64d0ed1e6fe00182ab9949386cd9a9310b85deaff34abc12142b28277364cb99b223ac8095a076e948728aee9ac9decee587a67b96");
            result.Add("et", "22ea4395990a5fd7ddb536f538f108a15f105818d276243dcc741acfb32a1f67451a61eb262d139a422da8f9d0efe93851aac1e616ecdc0126602bcba4f8cd93");
            result.Add("eu", "4374d0d41f9c5c82ce348770c99d768ec3d0dce75350ecccca0bc6f4331e9ec105a7ddb5afb6f498471de152d046bb3b5242084afb96b7cb4ec74a893b615537");
            result.Add("fa", "9dc88811bf6837125f17305c9360bfc122aa1889e70d53bddbc44110b3a15f2e1b1c96927792211381b3519550224c86ab6464714852bf8d7e08dd1f384cb94a");
            result.Add("ff", "8f2a2ffc6edbf446c98ef80a98bc0096c074182081f476f999bc2315bd0795cb6fd4eb9ff2912b5d861bf25a893b1afb314942ca820596bb2f12dc01bd64f8e4");
            result.Add("fi", "cab67795da8fa93d477a3c705b686957aa9f4014e0168c5812f12c871953e2b0bbb0bf4eacb5abb20af5189b7429fd817d912edc5dd0ac9e577a72d9dd21ec09");
            result.Add("fr", "d1b4f4dc5f4aaf943d9726b6727b3a3fee8ecb3db3cf9c16947efcd4f5d768adee29bf4ff832e72736b80e2d0c190226dfdcfb964d288767ce359c0d4380e9d6");
            result.Add("fy-NL", "fb31bea9385399d4fa55cb49668403ceb02faf5349b8d7ab83085ece3dc7b9ea40ac61fd590a65f02b494c93655b5e11cb79faa6b0a989c094141bbc532bbe31");
            result.Add("ga-IE", "3cba252eb0cd52a555e9561123ead0ddf6d16ecae0f992891b0b1045c2d89f07e3411e33e696e5289e539a8ba12ec7b3c4b7fa290ee04cc951e47492a2ba74e9");
            result.Add("gd", "479380f4755dda9e22377d65d145a9640df3f43b0bf326b0f4979e10bfa813a6653fa05219c3bb62a1b2bb6b492ba2e37d6bb1d166749fabae3069dd7ea3ebf7");
            result.Add("gl", "eb570a682e9271a01107765795414fe098db793399d097d0150abdb834ac1a8302273cb7586cc542b51c03e9fa5936e78cca2db3bb5b1f50ab2fdbb79204f8d2");
            result.Add("gn", "880a4988e1d06d29f26b7e1c114a9cd4ebc62580339583ab475d16caf4c5034e3b3b2eedddd69076d0999bc6f4aad84ae70a2ad16015e2a5bd44e5c9cb625d41");
            result.Add("gu-IN", "2e8da85f5e5d48d132f9c4908aed634b380c636248fac640aac3b9bf7d9c99ddfd7440e56d9d15dbaa870c54273ec5c287469bec4a3b8fdf09da6ae2278db22a");
            result.Add("he", "038f09c9b7f4e63785ab93185e9b1096dee867299ff70db63f03dca272f93952117ad5b196cc961435c72054928bc63145ba3ca48bfbba03a485625b185aa822");
            result.Add("hi-IN", "9de3704bb330981c89bf80419ac41df5f744b41c4f35299daca9c43b98b50e492440dba9e16f395a0a0bfecadcdaab08e579e39ca7f7ccc120964eb9ae605f46");
            result.Add("hr", "36e8dd5ef6176d14225072d1ba6741379b861b39f20455d408ad39595837c12beb866e9df78fdb66b4a3358c1e7cbb44308cf17a84b889ed520a057d1b624a1c");
            result.Add("hsb", "21b410c5f61936ea7ade5b6fe6eee989817e2dbe2f47903845170ec4d9dec0e58c9c4e749d6e1ded8760a28e9cfb150dafe05cfccc4b94274e29a6f6e44d8aa6");
            result.Add("hu", "2038ea8997df41905804d4aa6b98fa0d6bcacd771d6cb5e8a5be21fd5e517cb5867040bc026acc5de733d9145d788dcf5131a2ffb5b142236ec0df72e8126e6b");
            result.Add("hy-AM", "eda551e2f48ab9e8c4c3708566ca1497d3dbbf353a1e130a7475d399ef9d74a959865c86544803305a48aeb337e54c23efdad633510b3058a79875da7691e26f");
            result.Add("id", "daec5d00e748b606f8d7fe5c3ee4f347b9dade405add2d869088f147f5994194ca1f9e2327dcb67fc3a7c154661dc1eca5fe19fc2b0f77b7a4d7c84fada04153");
            result.Add("is", "f47b627cea6003520c2e53affd49583ac2c9a6993a2c4ee652fcfa0059e26023d9a7e2b4f305ceddd3ca531d90a3e8255b8b217eff341a5e085da02323d4d11b");
            result.Add("it", "185e502e18a466efe6b9a1ab3edb548d55dabf6358ea0402b1290910d31d48131ef8b7781cda9a5228992e19812fd70d6bd1c1f4b926031d6e186890a6e31ee5");
            result.Add("ja", "fb5a15eeff9dde2e482197412dd54519f84b6a626f88a5e9edf37c89fe72a26983ef66061a7f7e082967bf8d3d14b91989c9a62c856ccc100060fd103c6c94bf");
            result.Add("ka", "162684ca342297267f7cd8acf98ab1382ea10cc2a3577dba335eaa3e312dba1e6b644d9bed5f0fd6033edfaf600b4cec2992ab0bc4725ccb133ff7572163bfec");
            result.Add("kab", "7f7bca6a7a0d4e6a8d2477d56b92828a49bb7093dbbc940a6e8de8c912b7c4564f66bd5bcdb1c216a00362398962ca4e4e32fa1d2216e7d96480ec063870de77");
            result.Add("kk", "e2423c78b958b4a6a137b6d0ece888d7fffcba4d4677bc69a022e8fe8d6db8f79f6d26188066bef0b7599776e8905a6bf2a719889253ef71ca673b49af64e0d7");
            result.Add("km", "fabc8b02db5f9439777fc804da08068aa20ef01346533eccfb90424b4c07e19bd2f084c32a3766d9531c62bb600b7719740c8d54e2f0ccb8c6858f421f4ab04e");
            result.Add("kn", "67159f4d37fcc72ba9ca1bfda61a5f1b0c90e1d9f6fb16431c9cb9fdcd1db8e8cf0834718db5170f993584a88f92dd71dab93e33e620d68370f3667435527aaf");
            result.Add("ko", "d06a042b6fac5c44ce671bb2d57a348ecba03e4d51840bc6b28aae1ae0124221eca59b73695fecc7b4b3976c00dc018b6c6b283e601a5b52cff414393ac7ac99");
            result.Add("lij", "d1ef19f1bac1ed800c2548bd35ce4d718407fbd643dbfdfb416ab8aa997d11bbe34b95b3147a28b77b8e8251fe6bb888b4e15bd2a9794135c45598708f132df2");
            result.Add("lt", "beff1222652aab99c27363b4075780020e2091b8087e2e4b5621d0a819bbf1f724eaf106d061d5ebb5db41a6b25a1333113c855bef19449466a7c443ff5d7b44");
            result.Add("lv", "5dbe0213d7244e73c6017ff256fd24c3d980ac04cbf3c29cc833680a8608080fb96bf160113678b2feedef311ad56d0f3d9e9f7d0f3c618cf8d172228c631910");
            result.Add("mai", "bd7df5a87551d2bd5cd393a2fa7e4ac0e8e79a412f60ee25a9faa3e3cc93e92c0ff323e373017fa3934d2f462ed8536cc09e90aa26742f32f2936994b8c1ec36");
            result.Add("mk", "e810a4d5616cdba9bf940a2e2089a405692126a58119ab82db6797a05c6baa5026ca7c9aa7dd0e788584c77f1083c0f9a6dd8765ff4922247b656fee4c041957");
            result.Add("ml", "4040266a47294cce1c0cbca8076c2e55c2684390cd093f299888077937eee4ba60f61cefe821c0b1a48a6999018f06de6b45eebb4429ccc5f9db8fdeb3284dff");
            result.Add("mr", "5d75e02be253ee495e92f03250afecf6cc20b1719ee23f90ded8727723637029771d719ca44ba67c5a47f8e8b603838d620fef6d167dea1ce1f392013b885d20");
            result.Add("ms", "d8d73360dba58148f13b3dc0b627b1395db14e10cd3fc48434876bc4b79768509bd935c5b7bbf642ce26fa07c2d58710c4de853fb653ee67cf939c0879e6b701");
            result.Add("nb-NO", "682e122f22d4f10e50c370986381e2a321283fbdd1d617cbabe46920d913607a7e53d3cb7554ef654e5b1473c777ee87500fb6ecd8a1c3fce6222584c3e71757");
            result.Add("nl", "0da0c7b6fd867ea402759d147312e786ec37ac20eba1d06393386d94a6b91afb002510e1227877da563bafd077bcd0f76557cfc5d0776abce4df0da7ea47532d");
            result.Add("nn-NO", "b8131a11437fb4c24c027945a2a1970e7276aa6540c4eda53f3dbf01431f938b1db85407306a2fb5799d7abba324e066e98a3c794a2da2589a143ea894c48641");
            result.Add("or", "4f3109908298a96d5acf028c6f915af94ad70b03a672d74b65e0ce10a7be5437b82753a7edd9c19460f1f6864459aa9b00c54e8e43a4732af33fab1dbde31bd3");
            result.Add("pa-IN", "ea10cb53c40a7f9a7d11a622730f1dd3162a5181f13619cf0425f15106c98c7ed77b2df74f845e96a4f372ed8ead287e3a24a505d0f9d23fecd9d625f4b2d01f");
            result.Add("pl", "d9156aab1ba9f0f8069619e9de543e6a574db9c00af29664d80e238c9155c4320be743ab932e9c5a45f9ab5a5b243c8efbab3acfdf1f910fc60595173431f79f");
            result.Add("pt-BR", "3cb4db976f552de2aa83c055b44e801ba710410c7c47ca41009736606be0594a90e25f24e30668fa2ef735c3073df44cbd770d632db4aaa13799189f18ed3548");
            result.Add("pt-PT", "1fd05bd38586b7049fa64c233a5280dea992e87bf91924649cc74809d319f1b2b613959699c990909765c98ede0a1e57931259a500c95252f5efe9c08925900f");
            result.Add("rm", "32c386fa5ece6ceae1a8c838400df6dec90cd01b29c7487701e4faf1f088921f771466a535036c6bc55692e9dac02bac3a69ba8b6953388d578eb8b31dd08f3b");
            result.Add("ro", "b584c445bd6550e604248f59bc0e957e559611d96b65139e91d6ed85d377000b5abfcb7495eac8c56812e024c10ca0067f53e870b8abf800ac7eef37a9a1ac60");
            result.Add("ru", "b103e946f00828bc2f0a60dc09e48322dd01e95b9995dfe292abdc41db91faf6332d17689c676b977e79a563a8ae2815bbdab758d0d9f0001d74dce454358a72");
            result.Add("si", "074dd0446689348ba65f17086f8ea7a0a10e166b9970396cf8448bddb5ce414a4e3714c2ccd3c9acadef934cce622f65a17ea28ee2ef86b667f5c832ae56f270");
            result.Add("sk", "0765477954d909513a42e296ee59295d8d88600a576db838e7e2f0394bf866ef20bd18baf17fa34cde5e13563ae988b5ebbe8cdebb6cd3e198e82cbfcdf09497");
            result.Add("sl", "4c1eb1c02e6134a0070ed83234b895117f49120a7d4db9d0c3c2d28313a900fbfb12541abc46578ed9497d64b01d72c34daf94d2a7b1b895c244f2cdb668455d");
            result.Add("son", "79b30cda80bf2e64a69b5c0498d77e0164c07d16411a83912f96c4309085db919b8c9cdaf37a15f9f7e9c05a7c889cd3154906b2d7bbe07901b712a82d7fd761");
            result.Add("sq", "b00b5b770a234ac08450bbc984451e218f6de5e63b95241055ae815057fecb3653d1bc7bc3b715083c095f5a09e47766eab92aaf95413901bed03629288c3d3c");
            result.Add("sr", "e8001e35a514caeb6eae4176bafecdb522d8c9404578b3f131ffe90a638ee38c9cb40b7b577c39392844fb3934a168567a69ffcbba6d9d07cdf217c9f4dc86ce");
            result.Add("sv-SE", "87fe552476cbe0becf0342b864a4a6b59dc45d939c02c0036c5e773c6f2793594e3afd0b903ca0c71943b45401a80b69ee4e5bc09ebac32eb8410e62fd01b0bd");
            result.Add("ta", "db40ccf53c96544a71904930138a949dc86aaf48497d99ef4b5bb35ac9d61367b969aab8a5004febd43ee923fa1229313d1e254723948cecae06c053c7091673");
            result.Add("te", "9a3df2e07d399f2c0f69df03dc309ed4b03e24c997c2a8f8012a9fc148bbddaab19358408d64c09131919997af57147b5472ee2b386ea0d23e40258bf7e86926");
            result.Add("th", "4d0762deb70c9d8d4df87224ad8c192fee9aca022f14694ec7175016d9af27b800d312484445937f60a6fda630eeef8fac0e0fe7407bbb7c293b32d628d9d4b9");
            result.Add("tr", "f96775f4a6110ff5b4e219a3e31c2160039af5e0aea7ec044692492f9435e8658f6509419de53a6c4e11b1bf4a9c78ec33612ff7d9d5d4e74b9446de82f85222");
            result.Add("uk", "17fe0e9536d23127c26b9dfd2e9837d699dff0ddbcedb6315d0cc8f19bece26ba5dc7b4a27b42c2b89083706aad9074726ffcf6d17adfddd96672dc47d802f00");
            result.Add("uz", "7238748afd560595a1d3e33feadf6475486844efa2d98d3bb2bf37b74fdc89dd664060d181af94c60e4a32de187717a7ecc73ed33b2829dfef3e86293a7d2e61");
            result.Add("vi", "7bbba2e103980606dea575d5e3aa8b10b85628c6eac0755da04cf2bd4cd9c38056286175d135e7d02f6bdb233dbf95993363c625a4009b41d3649f64d9ed2689");
            result.Add("xh", "c91c788320f72fe14ce56f7a42eb0229f5a536457781730072cfd666860b4cee1d3a0baad501797220df4c6a0d30ac6d6da70858f8d47de259fb6495f229f393");
            result.Add("zh-CN", "df6b82ba532e8b46a113c09c9f842a784ba41f4e439d696dc7ae4ed0b41f6cc8660c5d7df4e43cfb4af0f503562005023140c66167d61083e639f3f75d9307b0");
            result.Add("zh-TW", "ae8e346f96f11e14fb7a051a8b8a781a57e53086aa1eae04281d5435c94a987bbd9bd2921dfcebcc87fd199630028d3b2ad5c411a4f64640f50f1a8e47ca5507");

            return result;
        }


        /// <summary>
        /// gets a dictionary with the known checksums for the installers (key: language, value: checksum)
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/52.3.0esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "3e4746d4eddfa037adf28cac3e03fcf374ea3a9665ff91ca6cf53bb723a12cf12adb5c6c1ca64967a52a87d58cebe4bca36a89e5e727f35d8e645c61ac529a0f");
            result.Add("af", "afe293b18c20e4488f1e05d0944f178870244e3e3bdfb922af01d864c8a0d6882937c1b2b1ff5ca5b3c1e498231f14bc342335372f64f69a535efa50958001c6");
            result.Add("an", "84ccd990fd0722b747952cbab38abf4571e18b19424abde035935d9841cbab6f8ecc875641a5c27656d392406ea786802065cd43104bc0b3048e4a81625db125");
            result.Add("ar", "ee4f7f8c8fdd35f94aec4967318bca0ca5de86c6e22b045b9abeb317929334c8443f2d6a09c7e4e6b11cf6347c47d031f46c1a9cbabeffa6a0bb9279dc25e6e6");
            result.Add("as", "1869d6185c80ca18a10d88edef5bc6775d7298495e2b012ee42a2d67e7ca3e8ced1532943eb378f8df3470524317ad9c9d2ae225c9ad767bd6f26388e93d0f7a");
            result.Add("ast", "93d9d3bfd0d41593025f69f8de50c60ad84fbd9dcc910f064257358855b6f0ee0f8077c382ff8ebf34586201902c8b48b00fe64fe9e35b0fa4347872df907707");
            result.Add("az", "76edc34943b574aa7a5618ddc8c29757ec63a76a5cf50b8beb6667e6abd0429bfedc22c0e6729fb83a4189e8e9fe34b0aacd74bed7ab87e099ec22ad912815e9");
            result.Add("bg", "8c87e96aa0e2d3c0a57aa2e5a65ef0268fd47bca32c3dc18a587b34ab941c5f0415ce953d00c82c2d05b2b98a585deaec90d08a4f7d38cab02708baaaf3bcbf8");
            result.Add("bn-BD", "e61f3dc35c7c7c7890e838c11994a653c061df50b7ce728a0751b05ee81f891b682548535ba56279dc5b20923ff1c06863ed0736c944911602e583bc62c65388");
            result.Add("bn-IN", "d46887b61a091afbacf647e7d3fe7e75a827a51390d421a38bf37298d99af8be991797ca7353bbaac6d1a8c9a0f2f03ca2a9369e73552ff2e91a728bd07266ee");
            result.Add("br", "2c2d7625ef9107bd0baa930977443cb9d74b2f2cab0dc48b2940f3ea294d5845db9b0c090008a8237ed3799b1cdccec5ae2fd8b02a7df7def0da2da9e8c2b431");
            result.Add("bs", "23a7500a7b8c49599cdc633669a2d6a7db963ec57159fb9c000e71bba6213974c77c5fee3d498f5c54ae95a99ef7d66f2c709fb038716c018f5c638da056ae45");
            result.Add("ca", "d18b0e820376258ca8507fdce7fc35e13974eec6bca07e55db400acf5f5f1b417aafa0c1270998188a1d753c83b0b655a70930be04d060c198656e3b897c6611");
            result.Add("cak", "84a5c2c57bd83d14f31d98c387717b2cab1efca85c50477ff96a5c469918961ca465f6ffbad89265158b3fa4490e7fd4e1f52db0a05dc29aac731346044c1f49");
            result.Add("cs", "f7eb570a893ead70e271cfc66b941e33f04cb66e3e4f994fda43513038e98843e441c4c9eda015af42f1fc88d5b7688cfc93e11be36cee0722199176aa0adce0");
            result.Add("cy", "b842c7c40baed4193aa7e8f8f4c14469c9ee5a0d1381f058c76117864da36e571474fb5b4eb17ed1e9a526bd690922dbf2d93ace25c77bf638c3f9d0ce5bd8a8");
            result.Add("da", "6a9da755a7ccea29871ce96afdc123ca5b45aac469015c4ee6f21150640a9068a38cfc2c81080adf97266d2ddc2bd6152aae11a32c6b98b83532d6558c2057e6");
            result.Add("de", "90d7963ff7a556c6d4f03496c722c2d67918ed0cddeb4ddc4ed5474f9b9be7f7597e9a2aa9b5484f5d9cb96efba72a51a4640042c4172e83f00c6c756fe86a6f");
            result.Add("dsb", "68ba082dd2193607e6213fb81fb14e8cd6e55e2d6b9c19cca15e2da08b2bdeecefcb18a0482e90d9c29a0a12f34bba9ab18ea1c98dbcff490d40efeeeb86957d");
            result.Add("el", "f49db0b933f977aa1e47992fc8dbc0b80fde01bb1a34c4c01de4253bc6a328049e6dfe4ab567c6bfd321e09171a49b8f6d7ffbf901f129e499e38454cef72a82");
            result.Add("en-GB", "1a2e9a5d20734957cf201c80bb6c3aa8b1ccef9a8f780e4d1f72211be674fa41791c2bd3846643172ae7593383f243f8f67b498a9c9f67a914622eb282aac00f");
            result.Add("en-US", "a3db6ad8d00dafbe96804a8a03845e77a7a2cbaeb39e6ce74e1bcab41bb962e0c9b7c5d67e8ad2b3bdc63d88576c3dccbaeea0a9c0e0e1263bc6bd91d235cebb");
            result.Add("en-ZA", "e1802fccd23028b4f50b49341ce718dec0d2e4d7af47fbf8a44e462cb705e87e1dcc389888b966c07ca83c2debc82c848c3f870d81f5f0192d2c578cabb3dfd9");
            result.Add("eo", "fe23ad720d7cfb9febc10e93396772ceb825b53df788fa632f2fc92adcbfbdd29e21e0649dcba5d94281928823f93e5f0013a7a493e911c819205737e86293bf");
            result.Add("es-AR", "1e9b774a778de8bdf7775799ab85fa9b96c0149062b3d8cebb60faf6a773c621c5b09b113bde0dc4b75578f707c5cf8327f1e3310379084fd7c164f717840700");
            result.Add("es-CL", "f59b7e7f01305366c404c609328cccfd27c3ee445ec0b741586e8710f6755397e8342c58a039a2581b0ef9faa15370ab68c9777021f6c171ba6cb8e07df6c742");
            result.Add("es-ES", "9fa00f767d988be76514755fcd3504f0dd89a9c45e0bb5ca030474820b7f1abaa88798eb632359ba2a93d6cf94d1ee3a50c150cec622816c15902a6ccf25cf53");
            result.Add("es-MX", "d82beb4aaf3078abf5e404b727e530af4f26f6b492227f30144c0499f5627ce81775752345b618e0ff26c6116b723ccfef4ce7da54fb3c797dfeaf364bc99d47");
            result.Add("et", "42c9086f1d499dbbb865771b1e57ca6bf7117a5dd5d28b7bf32e18dc1da26791e6d3466af7983ad01b83b9d3f7c19aeba9b1754a25cca1219579dddaa2822d69");
            result.Add("eu", "241de117f31ce0a68f2d923459ab568dbed811b58109ac36c1439c04cf93d29763af064c2bd7f410b186195d9bf7f6a4c2c9fecbe82eddefa64b4f00bab7e8d9");
            result.Add("fa", "837bea01295e931cf9298625868b56e82edffd46830b867dfa41873f7a6a2cfe9fb57ece49f3b159c2108ff15a062c7a1a1eccc5ef412a30e62a830e8534a099");
            result.Add("ff", "7af37adc50e381fb4518d07b73f0e4e135d81092fb33239bf4a2f600963b35d17cdc56864b1eaabc5b48bf764a3fc59c89cfb62671380348f39aed3aadfd49cb");
            result.Add("fi", "7170606a24d19620d1d2517ba46e8a7f0f50f83882a2dca3089daaecd61df549e4d1246b0e318860087eabcf8bb0890ef0431ac8df5e7dcd5875bd3bb71d265b");
            result.Add("fr", "1519c0c5068e9544c5b23c3ca9654d64bb73971c568a8ade48d5b6f43260198d52b8ff32529a44966a09f39318f34c95c6ccaa127246663506327c5badfed6cb");
            result.Add("fy-NL", "4b6aa0039c9b894d46a6e94507d658c5f6b104400132debdd743282ace117f3500589f6d3303343dfd517626ffe9625e3d5a699c53443595629ce1de4506a535");
            result.Add("ga-IE", "2a1297626f56281df0cace0d096f5f631f23a30c091a5bf7d15b9623052834a68697c3661dcee724af61ef04bf8635b69df05469a1ed8d333a5d26e2f758aef2");
            result.Add("gd", "15945a5dc22c22b7f5595cd5e6ce551fcadf64002c22e6182a9f52df78f5a23a96a8c14fb98de20be54b4c70fcf1ba2578caaf21e0707ad68c6a62ecaacb4884");
            result.Add("gl", "1f402654fb3019c456df35caa09ec06acc7bc6126cb0a0e40df284a7a186bec16179ba0d7db7111a368b5ee9a29d434571e9ae043233b8110341df7c86317aed");
            result.Add("gn", "e0ab48eae5854969fa3e0e4235ab28bbc929cfc00a861be1c62b88f4365b0097ac13d724c9212e4611d55fcf5a40d41698373b77f4de8ba8f1355e4d87d6c96e");
            result.Add("gu-IN", "7fa09955e45351904c9dc7041d284a6fba7cddbebad37e68c8cd22084fea085e11dc8a22cda971baec5f6f0e51a96f86769e924652902f072ad27c9647287516");
            result.Add("he", "b7cba1d16a00cbdc295031f1b78b94867922d2138a7b49c070a76a78d7979181057cb80bc576b377dd096ae3d7b7431ee2690b1ad6bc98969288d1105bc47915");
            result.Add("hi-IN", "ae6401f696a6beab4b5627a0796f3e3e45b550834f5008a939d75d1b35b5bb1b048c3383904b3e4740468f8b89f2fe0fe18b2e2d4919876f868f1e9799adc618");
            result.Add("hr", "4479962d5daaa6295b9c55775539f3b8e481b62a4ea33b18d44e3260173f49132c55a174d5715ea3ee659b4d592d013e56c48cd452f7545e9f5aa940f1a054f0");
            result.Add("hsb", "2aa1c814ec3867eb093dced153b0eeada240d74661b211fbc2b70ce9a5e31cad841ddeccbe638dca959d371efcd3c1bdb57acd5ad61b088f2489e76a818c2ac6");
            result.Add("hu", "d05d74d071fc60b3445d19fb1c740deeffbd5ada7813e2a460a7c5b46800bd1798d65a03f5d2d9ed77cf48994361468f746db577797c444830a0cb4979d27d46");
            result.Add("hy-AM", "3be34368ab92a51585f3b0bf9d9baa05f81ffa85df893967e409b9ed34213bb7405fcc90b50030bac5fa9d8f7caeeee5f5915b1670c5a763e54d516fd953371d");
            result.Add("id", "2d2a90d05b9d919706642947efe71624115e721245c586ab529d59520fc7706b6802aca4488f1a0e6f373039d204026a6a7d2235acff4882f4813e487001fa00");
            result.Add("is", "269f9c44f476ea508ec0f96c363e357599bbb228e070adf8f1beb6a5ce6b6df8565d7847351949bf269e5abd062764baca4ed040523b0454156dc71d6d4957dd");
            result.Add("it", "cb312a558b7f9af976b5a7f6add5c9b3f35c28a34224cdc1088f9162df62e5972fd1428d719597cfc0e8fd738d210a270f56854d74f7c167cb7136011cfe8754");
            result.Add("ja", "4712b309cd403d1c6372949817704724f1bf8daaac443adc2847b12e4a8de1978744902bec8961625f35d5872e6b994dfe127ef7cfe1c6d67ca4b4a8ac17fd75");
            result.Add("ka", "eb527317ec6b2243bf529f51ede0bc98d097e57392dee882279538cb2851f55619d81160e29faefe23f31dcad00f98ad73caa7a276b93ff21ab6aaa7526a8b97");
            result.Add("kab", "241608ace57471cc5f1d81af9d1bb11f494361d7c1004178792a1da2473ac900e992ae68bde00078fa00af337a944a717491131d8f61401f6c230cd16ed4f3bc");
            result.Add("kk", "b815ce7648232264c573f99c63d90f458fe9689c68bfa4e22c60d63c5a2b5f04ab76b32ceb71d7f2fc87abf350539fc2934e011b61671da82bc7bfce6d88b19e");
            result.Add("km", "547f32e793974d0e26372554f13f501351d4c48916be2d8e54e52078b563d90a15afd18e02d8717511f207e235bce5f185b9b9195c77c2bb9388727125bca5f3");
            result.Add("kn", "3fac06200e0fc3c45623a677126385f0329c1ecddc743f6a4eb93b360090f9cc67a29487ccb1b2ccb480f3d759cc789aa91080ee476969d9ff7151d03b12e28a");
            result.Add("ko", "f4909fe02a01e9666c5e78f1e63626ba5984a4eff032111c782856430ef08d9e966a36bb8e91c934ac6fe959397b9b31e7f519f90ab5fa83d01f383f3105462a");
            result.Add("lij", "ce4a7d263b13d89b7e716b6a38c5819983d8148793db252d05c79e2df27803fc5f1183c41ff075dca2305472d6e58ace3f3cebbcd004a544216f58c52b9318d2");
            result.Add("lt", "d719b4d0a4162949045fb421689d141970157b0b25f16be585ccaeefd907eb9cb2042af1df50580b9ecccb30ebbf445699e48edebe4f0585d2141647e53e41e7");
            result.Add("lv", "274738a452c6cfb86b71303eb1aba9358e306f8eb6dd39fae3749452359f2adc01221a694887991532dd88e94ae893d3a28d9a5309bf6e116a3adba9529545f9");
            result.Add("mai", "8852e108f22dde133b28d48bee8abf5d0f4bcb93e96d9e2ce205c82a40e78e05483cfac3c526a0376f62c4fbfef9a8d8c692d005ac41e09000789f0d32764300");
            result.Add("mk", "cbfb103e64f340ba1ba8aec039e3c17ee1b17f503b1a0fea385ab20ff4b0e9482f7196226c7d635e4001378740c99309c7b746afa59690925d945ea678dcbdf9");
            result.Add("ml", "c6119f5748ec6ba2b9d44032cbe12ce0c74437091917002be54d9b6f33dcaf2f5c6b82e5c0a371000317c44f3e411d6ef4a7b87ca738c11867428c184168140a");
            result.Add("mr", "b9aaccaf59c795f5caafd9f6492cd1adaf77eb32726ad2e1dd33beba6d05119164975a13d99bd2987ed9b134733fb0d8b8b319db805e49ab8cd29aea4608010a");
            result.Add("ms", "724ddde86100adcc3f4fef1c93423026a31b9ed6e9bef22183def073a21c516efa7cc33cb1a3a27bdf42cf4a74a96dca5c334935fe13201c82d9b480b6f279e9");
            result.Add("nb-NO", "51412294ec8ec5569cb2b3a7e393e620e7bcafea1669f0f73b4b70ac0e0d405563237290965ea95c3561d29aa94f4b5778195ec90e40ad06525967b2326373bf");
            result.Add("nl", "7b5aedbba5590a8a3ba457de0e15e21f5561274c73357f0d5c4e210e719eac5e22be37b88c0a8ac6eb4de942e153973cc719dd717332293eba6fbec4be9b9617");
            result.Add("nn-NO", "138715122f2e2e2bfeea9c86b92753dadc0b110ecd9a44cda86f515be4a659c705eb53adc1c5c6c6b8e089c99ca3ce892d4c2b17b95a08db1c60d4aae1f7ee93");
            result.Add("or", "f1457827c5555d573c711f9f4d8ba59c3162d75f59d81db6b2bca16bfa1e41d726d3ba6b18711409a4abf6ae27203d54a943e1460aca938a6b09bcae02e99f13");
            result.Add("pa-IN", "4a79e1adb17961ded50cb81b019c28a4083d6c9e05062f538ec962f6ff433799b3b889f105c08e090d36d327b96535aef9470e8f9d2cce48a1fe4e1f9131624d");
            result.Add("pl", "9a543d18138bcd7f63062135bcd095bb3360255c3d7fb9696caebc98cc2bd3b70d126e7f62a5f07cb22a78f87d5265457b1e704be2bf07c375a7a7856bad3769");
            result.Add("pt-BR", "6312e9ec3f06ce1267f24d2717ff0c82b73fd9fcadd7c0e0a56a75e0a392e5c0c483b7e6e784582b52bb5025ff9533aaad86627cf4f7da88326662f8bc378da7");
            result.Add("pt-PT", "dbc3276586b05ba95d8e13366ee07c8c26c3a634067821989b757c1ca0397a7c82323529ad1e4537c3dbcbb5ee3a0233ea3176bdd4d5b2a07e03efef1cfa4fb8");
            result.Add("rm", "926aa9d91d2c0f8876a81cf27fc41b45f0f895409bf87033326f59cb609914fac8dd9e0f773e559af3ff55ece4d84abe827fc21a23018acc7f80025c4b668920");
            result.Add("ro", "ca801ec13adc8ad5cefb719f87b521859e51f4b1fba4733274a0035d996401da4ed0c47c596a908802d95f12bdd2482b021341f316f3a7f67da52a32c07d63af");
            result.Add("ru", "0beb2356d65f56fa176170bb38c0e7ba0b4805d0857e30c6ff6087af7f52833cba67cd8a665a9676d5480418e82a903cd2ed275fc30dd064621b1bd1c716cc22");
            result.Add("si", "88328fdafd5f719c7a76970faf1d890eb6f6977775830b5f9ad07ef06121021f7d7d88e9d1b3cc4572eff7f92667c793e4d239d7928a4c7379e650c1782d0e90");
            result.Add("sk", "acad8663f1d00cd5f5a92d98fbb4005a777e3ca9cf9ab5a65dc743ecea915d6d2610a76be68ec5936b68843fb608c96c698787fd1b487a7cb9e73b4bb2523261");
            result.Add("sl", "945fae54c1ae7cb1656193d4542f35aa74be7e37a63a6780859de097298409c7f16d971cbf799cde34673d9d9d64edcd2488e999726ec554d32266a10820e3c9");
            result.Add("son", "8e199149d0783f06594cf3ea706b3e9afe19541f84645bf572391a67a0abaf464ac94b9fe42a767abb9c0adc035615218f35c9c03b814ea986c87b7ce8215567");
            result.Add("sq", "1ff6780eb9f8fb590b705a796587fc233e399f65c3280aa0069e3e5ad50f9331b55897b040bfaae29e891b8f6da09b7394758a9f1bc51f52aba1d4ac6d66d60d");
            result.Add("sr", "1a4abdbea0cf675fd72da167e302619f2803ebbf1cd03bd06a79f0d317ef1e0dd72d72e8c1e69f31f7ddfb97f1fe89dfcad563626c79c8f7cfe4c28bd8aefa96");
            result.Add("sv-SE", "43bde3f38042ed298b54e3ac3304ead2d38f47cb334f83ce4779d93fd1e3b9b9dec38e541faa153b818deba7f025f813d73a9d113a10753e5ab84247800e88ef");
            result.Add("ta", "c98c8f307aaf388ef5067d42aff906e0b7583bdcebc70bd4434ff2e4673b86086b4c830b926458de68f00519b9d275bd6dccd34407266377798e3a70e3124dc4");
            result.Add("te", "912bad8bf79871dcd7052e62a2c1b38f410804036b96ac16d211f8a0467a5ced6a1d5edadae46febcb6a029355e1a42a15dca2c25ce87f5dda7930972ef09e1d");
            result.Add("th", "1e7c2d96eb17960eb7e6957a8ad40cbfdec12b6108917f5a056f0412cb875c8100eedbc33ec4ef24226119487889ecb84de329a70cd2354ff6f1be142fd716cb");
            result.Add("tr", "8f6405f9021cc2847e8e258a29da01384223be7b50c3d82d9e2082a6e96b93c40f6e1da05b43c3cece29efe1971ce83b7eac8b22200a8c898c89dae00213ee19");
            result.Add("uk", "fd974d84d7fe0ff3c2e5e1879aa1515410e0355d2b30c3f76ce352c637b2c8092c52be423884fca346c77414e5feb2f26f415a2ea337979312a8c061977931f0");
            result.Add("uz", "6e561e84bf5f890806cb6f3b379f7b1b6661c4d017ffe2ace5f36bb84dae4a37eeebc2955d764fc5f8ae39b8f37ef17843c3df1478c681164cea2f956f35ae7d");
            result.Add("vi", "84f4e598ef8a1c80273fa709e6a965aa38a9ae54a6f980336f3b9c5c0fe45d571011fde721f525b8fc1589d7ba1d6aaa52099e1a138e07e5c0ef7450ef3c2a0c");
            result.Add("xh", "521c0c35e94a63a0361280a2dfaece58cd423c15043905728eff2d553d5ab5242af41be399ebb4e481f383f8edae22662f6726fdf4fdbf42b34ace96b055d518");
            result.Add("zh-CN", "434866a38761e43b5d0139be593065305f94a751531f93f639ed42120720e609ed763d8436d0b3cac164dc8986f84426bd4cceb4af0075171934696e2f726be2");
            result.Add("zh-TW", "a90b216864a4307e0cc82df72fc1c0777137ca00a29d882987bcf83f6a7a4f4a81b26b3f6a94312ed61155281356ebec5bdb3daa8430f5d0d3778d584b1bba2b");

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
            const string knownVersion = "52.3.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                //32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    null,
                    "-ms -ma",
                    "C:\\Program Files\\Mozilla Firefox",
                    "C:\\Program Files (x86)\\Mozilla Firefox"),
                //64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    null,
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
