/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2026  Dirk Stolle

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
using System.Linq;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Firefox Developer Edition (i.e. aurora channel)
    /// </summary>
    public class FirefoxAurora : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxAurora class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox Aurora
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "151.0b2";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxAurora(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = knownChecksums32Bit()[langCode];
            checksum64Bit = knownChecksums64Bit()[langCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/151.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "6b75c9bca1b22c4d8e8a1c77f40f3a4cca1d1877646deaf292ccdcb4ff5e3e4cd8ae7d90325ebb614e0f39646733e6c679223f10c2fd773fd17ab511d49f628f" },
                { "af", "80af27e7f65b2dab73a765bdb58bf3bfc39727db3f746f965e5d9fb2474c84e70d0a8f1e5faad63e9d6292c25510c6e7a61b7319caee8e6685f9827c3945cb35" },
                { "an", "9dd3b9d303912cf5dfef546a16fbf9562f6aadb9ffc9c5e25701af3d91d7f3d690f2eeec4c364305a61ac7662517c77d516c02260c8e9fa4ab71125d872777b9" },
                { "ar", "5014e47f17d797062232d774f96de943459b7ec57c527c13cc6b7a1bf446bd7de142e7560f37f089fcff224269744b64fbca5dcfb48fd2d56b53c71476a810ee" },
                { "ast", "81dcfe05c6261ca179f8050e1f7af9c6716b97f17df9909be329fcda1874d2c39344968ab71375e2f0449bc855ca1e90f6df59fbe24eb87a48a557fb62a77180" },
                { "az", "2d963a1ac51cf038265ed014c161abdc1b62b39ba19ecbed1a9f0211feb9206348ed8f3eab2f3a71604a823aadf1f245794da9a00606f70aea3832585f8331b3" },
                { "be", "34cfe149e61bbba1a372c7e35ba344456aeaea185401d294833047387ff2ef64199c692c8f1f58a2a075408b0d2608f26e095d2412a5608bc2a0820cae35b33c" },
                { "bg", "88ea513d775203f4b3c7fca219ac115b8883f0201ff7428f5ff5bf46ceae603baaa3613c786fb31216db0660844417310e12626f4d2485f517493dd2eb069538" },
                { "bn", "044951fe76e48d045316c55e516842bb45cc5a5c0019526662c275c4532deb026c88ab2a63865d15c97c536c1382a0ecce6db2b237cb0567b95dc51966a24a89" },
                { "br", "2f27c191694b1a69cfce1d564b27004609f834cb5bed1eddcaf533c4de3bfa005e396404d29446955fa79b2fc4e85ccd4169dd94a6de7fb038695b45477338ac" },
                { "bs", "453ebc045e036b484d114f52c27295fe1814280be3a056bdaaf546f607d65eba8001d7b4ab8d1d83932f1610947c1687823d995ab118b222dca553a37949e7b4" },
                { "ca", "609b33420e5bf97daef23fcbb7abaea0ba0bca686aec230c1ed84d56e7da3986d4b894b5d7fb7b7b340d8354dd754239b465742e1d8bf1d388e4dc87900697f8" },
                { "cak", "77feb215e79b4003fd00341151b6d34d9c1b34d7fb8284c659ad7fbe2dfb9f4bac13a772a95b60f31daf4b94b6347a713d2a7c95fe2561e1a8a93bc4929c10b1" },
                { "cs", "32bac542ea949fc84ef350ea5ca6d3af90f1c2ace493f5189a3e8f0aec3609438182825f5e9e5e0302147ccd5fd5ef9ce7a8ae2fbbe1a9b90b66cffdc796b53a" },
                { "cy", "9fe24e215ce90c816ecc8673ccb1b768a3cd7f0c43fe97531f6ef3ee7dd9c3474aa24775f03dc13602d00d462ef091a4cb7271fd06dd596956f434e8231b632b" },
                { "da", "7a877fbaa89110cc09f91e2f48e4155a89ee08f821af0b53cc2280150583994aad6c6e7cf0df8ae22efb4c8fa547af287935d7c2facc6362851dca00411b214a" },
                { "de", "2a4dc516bedfa6ce18db8e9a4c827ef0f7072f8286ac797183aee13c7df3ed022343cacfef8ad54e9741ecc45753f2bc71194c357e9ba219df3489c40f75797b" },
                { "dsb", "05688140b6b9df1053c328c652edfaf87feb193382f06e074bf39fe9b853bb4b2a8a7b3a87992e5735b48fb599e1b20ce3d6fb89a647778931c6072c6fa4db3b" },
                { "el", "e83a86f5809dadebcfa4013d6e9a063ecefec1fc5e0982fbf72e8f5d0cf4f73e547827c2f84ae06e712412d916f339640d7a75399f40fd29c735f99378496122" },
                { "en-CA", "712f8dd49c7c869426d5fcedf0bd948f5096f4bc0524ec946a495e86a789a26b117a0a07e6bde6dd1c74e79db6129cdef4376f0051af982c1735aee4037cf448" },
                { "en-GB", "ba3264d0edf53442d59f1a6a93c9a6803414d461b89ffa04c9cf45f40454808a4362a24fb78cc835b75e5d0e8c1248cbedb0fd19358dc7c238c3333a26fb4a3d" },
                { "en-US", "4f640954b78b4b1a7580ddfbfb2a27a8e72af3dce8751986d41d8bf03f9b8c741c46ee831deae5f97208f6e3ab31530cc4c6616d28c8c9469a2dbc17bb45b633" },
                { "eo", "aae17118033202220ecc6476dc44e34411cf1813d467aa7db091cad0a8a9b3cc7bc09b39634860a9b13d32ead7a68f2a4ea29bc5c2d8346088a7df1a0c2515ff" },
                { "es-AR", "c076f83ed68b83cd04ebf7d7f46f3bbc4141f4e25f6ca64fb7f95005a8ebd372dad4dddd610e8ca48867499d81c422a2d194399e3a25167f2e34b6c84f0a49ea" },
                { "es-CL", "366fb481906bd20e49a5011833337bad6b9f8b5d3ee58797f5168d4dba2efff29c00918da53500afc04b4010add0d14c8d829c4f75b275f6a49194c5d23e9ef7" },
                { "es-ES", "0692b52687e5f86187880cbda322cab3bdfa0eea2110cc9e0d48525c4788f3684915a9b9389ed7161cf58dcf901adf9c22a1a8c471e449ad1193329401aea535" },
                { "es-MX", "7a0a309473303e8572eef1a9b77b672d2970649324d03cae010f261f41f8e62427e8a77d639b226f2dc9045cdb2705d50915f42f5d30c6d88c7bd19b5f1970ad" },
                { "et", "675835733c96255036b375001f96e495c197dc9f3be18d56c60a0795afcbefc7b07e059db14d1864ba2053e43279d73c2d6bd5cf0395cf0c0b9494a69bd6fabe" },
                { "eu", "7258dbaba17a3fbf2fb1ca9005fd5677fd680f24cc80e6310100d4d98cf512e8a927b07005970633e046f2ca2f28bd1178a92f27f83d265947250a10207cc1b7" },
                { "fa", "87969c456ab64e36219008c4930e706fd821b4c3361dff036e6c866b09b1403050d3303d8508abcdae91b8bfabbb0579aab30fa2c7516c8df4dfbd43e692c7a2" },
                { "ff", "c98bed9ba9b5a4cfecabec2627bd8dee435947c0fda029ce4ccf03c80b13a309d6e061826641fe471735f37f7d9cc83121aa4d4ed00d0c42300edd9b11a611c2" },
                { "fi", "fb59a9d9fac779249bb30ef02170dcfff31cd033faa31f3d55aa3cd3611c9513ac19134d742fc7650622f87b8969293bd7f63da749b6a611dde99f6fc29905e2" },
                { "fr", "d4844205500562d6ac1ee7f297a252cba02eb2ec897ab7ce14db2fd5234fd85da67eec774a185891f885b4336162dd6544281c4087e71320951070689e63fef0" },
                { "fur", "0fb4ac2d1a759c8de7240cfb097af7fa2ab4d62258f96fbf99e940db29dc606a3021b6b5f773bc1824924485daaefa00e38625afc7cda090c62d9e5673eb7743" },
                { "fy-NL", "61aab83cc160f2eb43de5ee1e309c487d1a923735fda97ae4c119d7b91d85cbf819f109bb4774539262774194861906836e9d03588d47c1ead86c7e074b0f4c8" },
                { "ga-IE", "1053335e227719126725aa2b119318bb5c045a29224aeee5f5f738b2909bddd82ba8210e0c7f7289dd1d317b1388b6fd9facb4ad23dc43e1cb01b35b34c52239" },
                { "gd", "fbecd57d9fe815843142bd95914c20446f2eb25935830808a667cbf3cb1e06d9821f7b1ac18062c2170b61cc82a5bfde6a31de1fee0612c6e29d64acae6bdb56" },
                { "gl", "b08b8e2e1e172b97ce0764ee6a96c2d687f5457134458cbcd0b50955e655600e53353a7eb23ace64f0a2e6dc2e54021b1cadba7af047f2e47d8b6c5d9ed60b66" },
                { "gn", "2891bd065f2b6b890212cb4b3e9b866f27802d98dd9a49047af831cdb15a160f426ee072a71e77b97109e7ccf294f465c20c1b10c34ead2188ee9f7d2affa42b" },
                { "gu-IN", "0dd64823d4afe303005a4d276bed0523eb4f4eb0e2a8c9578916398c1ebd2905ce253efdb9c7495e8311f8736aba219b2a1b073fb312278283c0e1c561fd0df0" },
                { "he", "0cb364efb5c91c97fa74a4546b5a40db93999c7c61894a4d30b19265f0290103deea4962c7bb0592ccdc6998081d226fff405a2de9bb18f48c1d37e53d8568bf" },
                { "hi-IN", "0ac3717eb7ae2400e537cc7bcda5221526cfca48712491d05b39521941852559d414ea0f56abd4f1eb51801f09d8a1fe248676afa4c021f3626feee6fcee0381" },
                { "hr", "de2074154a0dfee9d96637caefe0304b76367e78adcc3b6842cf0085dcae8b10e0832058f0cf0f355dc22b588e33719fb154c8436e2fa51f18904493b9d17b11" },
                { "hsb", "63278abf5e7a07d283687ad7f18e1d3d2c26c9af50a04f93335fc6ef35ea5422941a61a36f9e3c36634418f1ca0c599acea59ab96a9854b36f358a0f48be2e21" },
                { "hu", "a3ba385ae9e2a453046c610922f7789622b3e9cd7b4036090d156ed2badcb0e66b458c601d00321bb0b80fb39b58db101d3e4778de2c4fc4f000ec26f7e84d3a" },
                { "hy-AM", "46b30d94097185a12d39de17ba341318bcaaf7e62ddb61bd6908ba5f97ddaf4ab6d73c8142d60fd16a2cd1dd925567716f64f2938093ebb736e7868276559c55" },
                { "ia", "6e31498fefb42464364886c70162dd509a8a7677cc2a9a3aecb3c4fd9c115b3e2903b41b748cc50379477122a5c8b7f9071419df279a2a7bdc76327d631b2902" },
                { "id", "e683991d82000ab11dd4fcec12a9db46e14609a87ea2e342389dbccd2bb05c46b62a5afb3df2daaa41b3f6bf6bc19d73291fc629878e7f8c648d7d45cdadfaa4" },
                { "is", "4ef9c4bddb70e6565e3aea5d798d0cb844a32955a8b7f064de17e8d27459d261f347f22e1c101a9e6e5eaf296faf5af2c3d7516641d99651424b63d9fe99762e" },
                { "it", "f3808e22dd18edc01e5f2c66ac4d7a8b9fb95b95aa34269047744f664425251ec55be8c977ee6fd240ac4dd0c8b9e8d1ba523e8bc0bc8121ffe173c9b0dda19d" },
                { "ja", "591c23027c3e60ac0b6981792dac575ddc1e5021986c50a9616e6fa7c5932e08daf0c990ac72d04a56746fec7052511046297a70c042fce3512b09d69baacece" },
                { "ka", "0fe30e9e917d86b19463d9f8edb489e1077f4456682846782df42940be01bcc87b1705c6e12d68ca4f588f4c6f92ec9d9013addb552e6b488311d64702433a7c" },
                { "kab", "896ceb9156671472087ad7709505a27464dbbba74e21391e23f96f3eab9da23bba0dcbd1aac00f5aed04bc260a866bc9fae88831997b681531967bd674b319b2" },
                { "kk", "37ccea2d0b82388056e724f70ddc926669d972a9e659bbd035570c13cec910102e84a114f518eacb71a28fe76ca628d354a4c4cf638f1cbbb5b7c37d425e6944" },
                { "km", "69bcd024a44b1977a899bc4118ea24cc0f2d0139883e6bbefc27194801abb6a20caad2556c31e36b37f6c604b4d093a32178dbdb9abcc49903d37c3656ed8aec" },
                { "kn", "446f1799887c3e71c55de0c2db5f49df5db55433c0336109206a0dd8d70111887a031f3c602be667eb2f990f38920a59c6e1976bdcc5148020de45ace4f66051" },
                { "ko", "8ced87603e98df3c4ea13b452aff58f150cbe4907d72cc8fbe90251d415981286a86d0a34b023e74b0840274a2c85150d4ad2f76befcaa540eb5571542d3dd01" },
                { "lij", "d794c78a1343a798c8d56a09080bd87f093f01aa1260f23d69e68a5fadb74fafa4263d70a371e9fd881fffbca0e95e74d00c5ec16a04bc666adce9e529df7431" },
                { "lt", "5754ae42e8baffdcea20a3eaa5148768b8923e793e35a73b5ca9e1b43075adc40901d2fcb365c9847bf554ed75d30238b554fac88581255515fb415fabca2068" },
                { "lv", "0e2cb1ffc46b1b97cc0ab7815fc2197af5a78cadfd5be97e17b5843f4c4b5992ff4bcef421924b61779fa733d182f876f05df896cc103efc5f6a0a5a9f888708" },
                { "mk", "f2aaab068aca8684821c92ae82937b38ed66cfca0dd418c0f6b13997cf84909f02b2f9e444f3db2296334e11906bae11eb4c6eaadaffd343ea3bb5b003f08a5d" },
                { "mr", "22c0479bb635d45a1d88bc47915d5471aab891a785e8c59cf82fdce14e9880e0b746d4c48b0a75b6826862ec071d85dd39c11060469cfc1a96ba1ed5eb72d718" },
                { "ms", "1f19bf2a723204f4298fa235bd3a18fdd39ed1cb49f5564c503a9787c1c94003fa62d1d351e1bff43a7c51a21b2c7e7ac85dd6fe608ee6d1f031a77385701b4f" },
                { "my", "a35e91613ddf70e61731f616aa2ff6a9fe9e536e2c8d116f4093a65be18bd5ff62a4c4602ed34fe753acb957fed33d94e781aff853104e3e677a929bb0804332" },
                { "nb-NO", "41f7283dc9491955bc7e88eef676f4727dda765e7b9e255401418e21171cba1fdd45a040a970bc1291a99159144ee532f387e7dba266839b4a694b222e2ec0c3" },
                { "ne-NP", "f20f474a75db8869d08da087df0180e6c6b3ebf1e3d5a459b82ca8951e72aad2eee779e6f255737380eeeb907ae494d34c0a04addaf552968a249a1a2cc041e7" },
                { "nl", "c94113b68037aefe8b1fba2ea26057ef8c9e40f7a610fe43becf1a4651d6b994908dce3d119a7e4f75758707d077f4e4a9cec436f3c850be38f00bddd2846a3b" },
                { "nn-NO", "1a8d0456a287290808615e42b4fff226a31b06774303fad06a257a8e42087e44c7aa6c78429ebdee97afbb0d2b58ab963f9cce70bee34c453274a8db61727b3c" },
                { "oc", "a4be408ddadf9a898119d6832ad33cbf6cb473d3ec00b3abf28ea46a9e42c81a28b5224ee4c06c466be9c000a1af0ad90b7dba15f13f56562f078d2f1a744be2" },
                { "pa-IN", "ae536084ca05a0c06466f8e03d9d229d765a22f7fe6f01835b601a3c2045e663681d8c85803d8af16894d71a05c842a29bfc57b60e32444ed0b9622c3d2c5c06" },
                { "pl", "094b6b8cc0653ad4339b6dca149d50449d0d701ffd91792c47bedeb96bcb526c212fd9b2663de9ac26a4ddd5338c64509ac8fa22db21e1bcd788cfbbe7c9a181" },
                { "pt-BR", "f54b46f03e1bc3d911d51f1854cc1d6533acd31ea31e53f844c3c9aecacab90e1d61a271aff1169f3f6d6e001d6f8d271d46278755f446b0be047dc3633de42a" },
                { "pt-PT", "9dabaeb0e6077ff5357487021c02691c6d1e90561cb1db0185ecffeca3a83cf7264b98b4c0839b8802016cd0b1f5b55f606fd9c2f8f643c916e91484b5d5fcc2" },
                { "rm", "a5a312865e5191c557a5287132bb258be67aae18a5beaaddaa6ff7559fef1af0c4fee3e6fd622451fb4f5c7e074948fc8605faf25d2a337386539951c3d5993e" },
                { "ro", "82733d4d28c09f192be3f3f4f73b94b5a70e97683a75f87bde75d249c0bcb82cc421e42fa9b89b811cb63e4936a388f556ccda33babc68609cec463034528989" },
                { "ru", "a7a0d3515a5a96a0b4f06a0c993ba2c95fc1f8b9a64132da69e974d14ad9019c3db849b5c4dc718ee7b50983820328f95ba7cd16aafe03879f84e1e0b2d94eaf" },
                { "sat", "cdad69cb1cf1f45ef64bd43338ad1bf5b8c94244d9ec248e2e46218960c8cdeef9a125c74ad3d14af14d6d34395c91efa57ee3b6c2e7c294d2921ba749cbdd29" },
                { "sc", "5100daa63159009db820dda33a5f66655abd5c5cf921003ad16cb456c3e340764e0bd7b559373a9b3be1ebae4bf7642f09161d2c24c6c5396619657e36ff1b81" },
                { "sco", "63f2db3e35b6be4aa4723c4e755ca1e2caac25afc60601005133bef15a153b048aeea600565f4d548b35c4bd362624c05261a807e535366351ff195b17016628" },
                { "si", "b144f1fb02cade3dad6a06a82abc75dde182dc1be86c7148ecd9c62c665344c6a8fa0b2a5b29d6dce475e6937cd82fcb0f61b504e76486014f063fd4ba8f1690" },
                { "sk", "f6512f25b24c3767ae89e9b00785ab855952fb52c980f9a65fbbd37f37ca6ae75ccaa3e36e1955ef2b5c3856dba318d48f322909e148c5b875f4d6a41bf7075d" },
                { "skr", "b244b2de116013f6a15488eb2163babe0499dd12c4180aac2a5dceaa3da6e7596657210e3c504570848b3d556b82bb10f32bc2028ac425c6ab34f8958f9f8013" },
                { "sl", "9dd859171544560ff6b6d6fb5ecd81a2ec68f528a4d171e80318d4302f95ef3e0c07ddcfbe3a71ab30d483c91067977ea6d0f3309a1e741b298e8af554b7db26" },
                { "son", "df5a879adc3116d7ce5dc534ce800f13e663e860991a26854814fe0cb58ab605ddd01ef62ef3b18927adb973a368b1bd40eaf63b0871e46c421ed483b50a745f" },
                { "sq", "b703ea75ec970105d8216cab18e22e14cfe70efe4b8ad3a70f74f374273d29b40fea3ebcdb26264e2a7e6142696f1b5dc305156d64916093eb945d546eef00c7" },
                { "sr", "aa115e8c748157bf5968ee189ceeaea1e9040682a93ab6044405f8d943adad352f596afa702979010be60462e6105a88a9030b59aa9dfa9e2c9e7236f03f861c" },
                { "sv-SE", "bce84e97b510c19d2521a21c0435d62edee27ea7f5395025ff8cc066c9acdec5acbef30944062b64b1d0d94df027d85e3b78167c2880482cedc6c48e7e3f644f" },
                { "szl", "afc47ec1087dc4961cbc957bdec481704de0001c61ac7698e8967c0512998a56a412188e41cdfecf6e5ed6fc6e0479c4c0a812c73414bcb92002aa15f69aa2ae" },
                { "ta", "6a24e215a4706304732b68eec62a4b16cacf6b157bfe023f45ad77e0ddfa13a0ebee9066f6ef5fa7fc941be9c0de8825bebaa325484d9c689deb0a30a419d608" },
                { "te", "3693272e20fea550cb10b5ce69a3e78b0c08aa88cd68c564b391bf74521c53375f1e1b859a3753bfdfe7643e2e01e387943368037b899f0f34231751466cfc44" },
                { "tg", "d3f1ef1c65ffbb858474281dc123936dbf20bffeb83ba8898c889d5eb169fd2bab456a6e8350b21e167c5de65880baec9408062f0ca38ffd2aa5566b7d89e0a3" },
                { "th", "b1468bf24614b34897bbb2a86fcfccb594e23f767575a357a6e26e4a7b16d2c48faee218a566581a6ee2ad4ec5f34dd7417a2cff32686ef0efcaac60953bd16d" },
                { "tl", "9677272e631bc1a777f2e168044614c7a70c0322718a902667dad6a2a4234fc999dbdd890886cd3e40bdb485ca34a752823669ab5d65355ba9a7a2712ff4eb6f" },
                { "tr", "e7f83893690dd00396dcbab37a48b1697a4764388a155e26587c4c3b1263e60916ac1e715867d661b6289172b1001edb450fe78480ed84dc5d76c6a8d681aa3c" },
                { "trs", "4f528009260452ddfe83b7977623818f9fe1eb36e87bd5abdbebaccc08da506c41e0fb315ab8bd7f79c1f7126ac78da9651751e110257caa98b7845f7ddc35e0" },
                { "uk", "d5840ccdf6ba7ba62aa7435a9805cdf2d1f52c4da5bc16139eafbe3557c128d2351f714a01ec397395f4bba0c45db2f8d4b62729a46a6937f50a22f9a1b45308" },
                { "ur", "5c66fa4125371e07ef5e0c9cb2a541a2f51333e77346720b8f78013d92e610682bb0af20c3b29ea55d376d63b7d5ef895b643b33bd048b0c966ab95b090508c1" },
                { "uz", "fe2386754f75e23f52b97d773d59a92309e76cec8819fce4ba99791451fb905207350268ed837097ad311ec7f6c205ec40b5424c59c26b8a9f5e86b30cdafa20" },
                { "vi", "b96b354b39b4108aee4322878963712b58bfac4bd18c6686945dcf469d72557a3ad83a3e28bd226cfae59f95ba10a72d9a4f2c88e17e7c8d0d323d20014f1c8c" },
                { "xh", "fdfa8231c62a06f294581bf0c9f551ef1ab75572e2e3d5a9196a836f815ccfe76aee2a66eb881f48e3666c053de88b77d392c21d4c0112967692792d06ee7b53" },
                { "zh-CN", "d5e08b811a0165bc3048ed2b6d7a3904d64b8d7093f6f8ea775a10d64cb8b7e5d405cbd1bc1fd6ca7d9be7004842c5d8b1062c774f9ef012b1219e47ca9d9917" },
                { "zh-TW", "64df0f436ad6106c9106e9df4473b9bc8bcc88cd38aae4c2a8ceae8987e40c4c6bcc0b14ce75a78e2f9c4531f8cb5d415020fa6fc4657cecd53959de6d8d62df" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/151.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "8049e7cd63f8f0c00ce08a828813289cd744eca69ea5549f6586506098623ed3dfb7e1c5ce363ad58f204edb14b8752306e8bc05ef8f867a5b88c6f0419e3e4a" },
                { "af", "b3b332faf25f1ec43ed20460c1cbe31338850024e915ea5a6179d2f26f352725833997ab40d7f82e98375ef8c1492aac12b815193c1a8bb3fab8bb7b7bbea19c" },
                { "an", "2cc1fabc6df105dec38351f81b1f38fcebb6674e325bcf6645e37040ee3f2aacf0157257caaccc7a7605ddd7b71407d003388bb0e0e6b5f964aa9b2205f1b42f" },
                { "ar", "f4605f2fe267d05d6bdedbeb2739d95fa304180215e7dfb052d2bea2aacc36af419fd94b35bfbc12b63b199d9f02a8fb2d8fb7363466de6c0e0939ed676992b4" },
                { "ast", "7610e423410c5f837083d3fd3e9e2cefddbb70e92ade16c2ed52e0f623e6960af7610f2e1374ae947bbef46704a239690adbc497c666aca9ca7d43cb736a53db" },
                { "az", "963a3d1b50e0b6091ff3d4cd02e4b2b1b0079f2d70389d9ffc56a0e9bde0614f32d46507a7b8249d3617cc6e042f10ec94c85afd114ba73e50d057741c0f1146" },
                { "be", "a8738f829fdab6fb758a78c8cb686e83d06e98cdcda9b1913f1f069530296dd24c0ec1a16148c0a305ecfa65681d59e4d4795c0020c8e7d1c36249a782c4fd11" },
                { "bg", "4b08300741c6d5a0c0f3213578a9ab976eb5f393ff1033a64ded708da60a03853ce200c0b9b2a50b3a825948d8b4c577d98173e7050210ed13627ea9064e5042" },
                { "bn", "d49a254153950612d9e021340312ae7584fbbaded5c69b3eb34b2676b530093514afeac3902ed0c2d9179202cc568ff71617c03295e1781d7a3ddcb6d483ef61" },
                { "br", "a21bd5495afcc6853e69df2df3a8d6405ecc30d4470a75eff36f13db231bfaca49478844f1cfbd9a257fd38dee2e093465ea809f08fbfb30634945f8cd03c9e4" },
                { "bs", "3c15d88434314f2fdd932158f24c987b7e8e4220b5bd8f3cb5a3ba224f38d68dc957f90d7bf81057e4215e968b4d0e24f9d12df66f86d270fc07f21ebac94c70" },
                { "ca", "7891f8499e748397ec5ca34304c05c410cb70fbab5f6c2378cd9d12aa6015abe9452b2457ba66ac588257decdebb8b1be82ae3870f84e30d9a026b68be61b9bb" },
                { "cak", "50d4636bf4bf9e70c510c27874271b520f1b0721548144566cbbb9a71e0c14549a780cb5ad8900dfe223fc46e3349bc30ae7b3077771b75254755732ca83b9dc" },
                { "cs", "7d1b654059fed9f18823278e94062ce61b55165eacc3bdcd4f4a6629335def50fa0c4592951dc950620a10f7f8b77cce5f9b084e0fd049668f3beb3d85794656" },
                { "cy", "3992d3c8493c9c1b04d21da5b3ceea577c13011fc79ec5e23d56339a2424bc0ebb459e9690570d2ef2ed13ca77315d746cbea1e6640a0548932687d6c4e4354c" },
                { "da", "020d303c713ebe13b0954a306b507e09a2a732e4386b7f8c74c60a2718b92a2895348bbf17d962ad164e31933a406550dcf3d61d2d007e9f4a5f07a36c8778f7" },
                { "de", "dd439103dd30fb2f62e8eebc2d45ce52b1cffc182928aadc1bf26d22c54386aa376845ed0db560ad8b925505c965ad6c601fd711756767474f08bdac91343154" },
                { "dsb", "885e80233b5eea98e7e09e051a7dd021bd096abeed9e39e87371a1a79f1a20ef4d89244aa2f1a198e3a00966df3f8ce159cd3d79d19d71501c5c74f9bb7f3cb3" },
                { "el", "e11ef46f1a0f72dca188e257cc5605b1fea478c0ac37c0cdbe6d40ffbb88afdabc5dd4aa6efd5fd1ca36f42b8755f44986cf131ea16cc3126bc85d20f9627472" },
                { "en-CA", "015517119019be3511aeb434cf9f6edb6a79a154d2d9c40fad9bdb566ac9c9d5ba6014d47813e6f0a6131640a8945479758a686d8bc2f44fe0b6a60a6f6b91ab" },
                { "en-GB", "6e7a5422fc2808909aa0aef5d06983137ecbd8592e664e8874b05fa0ed6ad33a008875cdcd8e4553d7703494c97e3e338643b79697ae0e083cb9d51bcd3c3c50" },
                { "en-US", "7b1d58b54850492ad33ba6dc32818d3c2fd7e8879f00e721cc3c53262fd67133e2e6683171d68946f022b12792b799ec732605f2ca87ee52f876165dda055556" },
                { "eo", "57037885ca62bb1318d858ddd8ffaa247ae9c94960fa95f4ffcdf8a293d9610132f7a2c7914881669581164ce9dda44918d8c5aaa5d44e8ac7258804f6f2e8e2" },
                { "es-AR", "933111dbd9d6ed5266246f7f712433ac75b21e6d2dea231d61dc28c83ead91a468e048f0c6c0199943f6a55a21cf74d352f4b7c0eb2859ef973395e63cf9928d" },
                { "es-CL", "4753d6baef927380f81a7f14aa63385611654fa90c1d8fd7d71f36ec3d0293728c1ee1ecd352011da5761b7c727da19c8d1fe87f00e7f1aa87cffe37d3dc0b7e" },
                { "es-ES", "5989e658fa5172d4726ca3600a49678adc161da444f93c2d2ef105ab189b861e6e1edd09b63148f351cd184b81cbfc21ab2d42719e58d3a3833c2bb50bf61157" },
                { "es-MX", "91468fd37cb4e155d7fe7f1b1011bb6f592fc62933bec6d4dede54a64a8d8aa1959ba68976adaef576320ab03121492e28d12c74bf79c937016b8306084dcee2" },
                { "et", "d1d0aec96ab8dfc83524bb20f1721dfd0cc885fb1d13a1a6783cd6137197cd7416fa2c91a05bd9f8ac81550b35e897f6043c476abf6d2c2263677ba622f18b2f" },
                { "eu", "c5e4859815ff1ab3fb606ff6348597cd7dce7a8147d7d8728b555c7c09964d381191bc9ea31fa64e68863100d29f264b26f5c6ad3c7133ec30d6bcfeee19ac91" },
                { "fa", "ea11d549d2055514e04a4959d04ff79d78d9e5f40cad9c610e6a1eaed7331aad83c5946c05004e598e8b8b03138f1be954d35b53a007a3be024fcaa39d286b4a" },
                { "ff", "3ea6bd753841e592c6c58728505521431eceb0e9675f65ea8e285ef653fac661d0ec4110447cbb2ba99c8425dfe3f572f382095d648612c9f19111f4a470a9af" },
                { "fi", "94c18fe53d0b5bc246a202120d200e81011a4dc5147121007b304353b7493e26d02c88ece052cb7c65c93508bf523511e78eee79fd34208053cb84cf0439995d" },
                { "fr", "6686628999721cec3cd20560ebb251593fc4688b97d49a0d28628beae0cb4da8be6191a53447ed5af71df1301ea701daee5ceefc528bda7678591faaeec0d226" },
                { "fur", "974ef28b43173148d319eef7024ede037ceac6bb2d9e8e15afa034241dd67da859fc483dc2fbe28e1dfe5b51191d44879228741528615f434dd9a8ddd629aba5" },
                { "fy-NL", "eb16a6979da8b3c191aa897961b9dd9685c1da354d6106936f43212133ac595ff0c92363d1395fbc848f5cec23cc537d86e0b9e9ca1670f37c268f9aae42282b" },
                { "ga-IE", "bd36b3625b11f5f1e99f84faa622461d94dad3fa0ca63fe7636c14224622ecd98c21a3fb52f7a746efde1c0bfd8fd8b134465b9d1b3ec7e15b54666cd2cb387a" },
                { "gd", "5e4cd3d02aab70ba93b5e9abb97a35dba282bb625e1ce36fd666a4e41873175c522cc2e347a6a5d203675ac46d0f209ccf6c076dcd31f37eaf84640c207e4d95" },
                { "gl", "74d037100d1632149c0188042907c783fb3d303dc9cd9c0723cdfd3ab178c57da465a0a5913dc1cdf92ed999a22beaa8c1c2fefa782a0ecc3cc47969277c867d" },
                { "gn", "a1a511a091e5ca30e3f64101b67e6516dfc3f535c05b594b3a13e14ca144b5c62b09653b0b46d510731043c04cf9e4c6344f01209c1eba19ed6587b080a5d618" },
                { "gu-IN", "a9add27f8d2cf068989e162786b9eccb1f5f55c826d2ac51d3094e53c3df6df5a61d64da822c0a67088078781d1d6b12b5378f15e4e4616576101c60211d2686" },
                { "he", "eb22cc425c9b37835caca3c2cf113d6af08d117eb5c2a224646b1bb52cfda07ff9ec9de9338b65e94687a79e4c2b86445f8bd48da54d2c7fa6193a433a59a0b1" },
                { "hi-IN", "6d0535ab698cfb475bf8afd822b1574009a83a234de071336111f1122a01428a0e71adb4f3cd69e3917f133950736a47cd52b3beebb1b0f54cc6483f05988fa3" },
                { "hr", "708e56e83f2abf43abf0c6ea639aa926dbf4ff0554123233386078ad0afa33b294bbe370edbe403352d5a65b90730652a5260e44f7a3914d620e8edf3d299321" },
                { "hsb", "1f9cded7fd5090eb88d33eb3d94618b6b252e1661e4ecb340e20b9f5ae54187f2d49ba13a011646db634357c8ad80c786c152027eb894a1bf7be14898f65f8e4" },
                { "hu", "a9b86c39a1a8ec3c62bfe3a59e87b9a1ad00cb0b568dcc1d2ba350836517daf347500f37a47f6950345aa7dc5bb0186384999cc28bf524b8f440a04f51805088" },
                { "hy-AM", "f40ed39f62536246d12953e682c2eaa3b8493b0cd4d8d7443f855003de282f4f75a0ab8a22dab5005415c19416255903e39463374c7fe127d74f4c0782592941" },
                { "ia", "ab9712fdcd9f1ad7650a9d8c65b5847133a10ec852763c8e7990e75a0cd2c27fe4924958717a9b8b4b75bf6ee3eb29fccb98034678714c067a44ad6b2f750b0d" },
                { "id", "9f4439f8ffdd6b999113240a36f25be08fb464808b6c7cdf489f46185e18a78b1cd32946334bcacee244e04607f2791266abd126bbf35a2274d08f97cc0be5b3" },
                { "is", "9a29869e1402fc1b44f58a0798fa40cab7cd2b9b1d67037a17a4a7b1ec5a85899e1672d599f863f38e6e6a2a69cabb250a3fe086f86a1dcac82639e12a308810" },
                { "it", "25db8e79bb98f6ed8faecc592a14b8c4397cd9e8868d273581d69b22528fb5beb0d3d08543b26b97a48c0866a2da4b90a29708ec548e5372845db838ad6f3628" },
                { "ja", "9e35218542ab4795632f83f06c64b97d22ee27485925d67a3ff9f0379ebdb05267a4fc34c1760eb769cf2e3cbdb65df47aedd9ad4de3bd0f9c7dafa67e2bfd7b" },
                { "ka", "919db3d61e721b49c6a5bfd7ee1ed039b8044c2cd07bb3f337d51ca58859dddc4284bc086e458b18e779a548a5a0c6d2a45db0c120142621b7d536778046d83d" },
                { "kab", "bf0d3c3b0fe20b0997139e3d33ecc43f23de440fa279912969133f1c1974f2f5d316e4409291ab47ee80703807d872a48ae0d4c5b810a5383d6e284d6ebe8e04" },
                { "kk", "b603911f5ca95701a76bd13c634114be51aec31b00103faa749aa1b4e503f80ce529bfd29b8ccb88e04aaedbf2da995bcbe6563ee9bebda071ce52ba4222103b" },
                { "km", "55411ce5429ed07d18a737034d73b8f789a6b8a342d88a2769f3e96d43938ce5ea6845bcf8fc1253e93281396ac21cf2ee8d589c48c3b04aaba933a594ae176d" },
                { "kn", "9cb432206befae36794193f6e028ca1ff5eb7a044733f3671855ffcc19c2f88f3f21d0f197e409c2ecdf1d120e7e841a591733ad964d374db735e57716aff679" },
                { "ko", "2e5c5326ec4aa6ac6046319fc5f13699d228f97b933d4606e81bcc741ddaa5b5d86df7c0083fc0ce60c20a42d50572fb360316adf0567e562761de0afc150f45" },
                { "lij", "3c0b3695029c63f3632bc0a8d2f03729dc1fec6d3dfc9adddbf8e442dbd47a56f1c851f4ebcde91d636e07eb762dcada18d34ba0477cb0e4f50fa2e834d608dc" },
                { "lt", "7fa5a3dc15cb879ea686d4c8c59b6fb99d4f8f099489bec12c5d30200db8588626652cd53aecad1274203746d897c3fd3f0346b920e59ab248bac72bcfa758e3" },
                { "lv", "587b97a6df92b0af901a307aa0464d52f561b508f321125949f85599da15e93869f384f8d470dd84359439c24446e85f29d2020ac2c5562e5e673aefbff5332a" },
                { "mk", "dee6045fb30edd0861ff0521c8272b42ace60c16b45321fdf0cdc59eb0e8c8b903c5d02f8f438d259a83676ba26fa42094479020bfca0a5b6ba3b965f7abfeed" },
                { "mr", "d68f4806e9945ab16bac460fddfc1e6ac7dea6df20dfa6b55202fff056c1f11ba240ed787c5c6b98819254e4081134a2098caa76b86eaca3ea609a912a59ed6a" },
                { "ms", "c773ac32c9d9c7e995c6336ddac2aa0e817bdcf8b6bce2d4a7ace2367cb1e4ab07498a6a76668073f71907fbb6afc7cc277a5ad1ef33174057800c8d994c0d1a" },
                { "my", "a58395912f0affb8a0ab1ccceca394be21242ab5c5ab7fd78dbcfe9b064d33f7c228228479f0c5405ccc1b181fceb072dffcd0cc618d77d3eb8da8ff445458a8" },
                { "nb-NO", "eddc48b681de90312964e9b1f037006ad4292b4aa18a14c6ba479e59abe72fc142196164544adcc0c7485b45d1545dd02b3c8b6e1def310d833e6b380fa775d1" },
                { "ne-NP", "b8292c9f4ea416b0edeb36a05883abaf2225636a5b48e7205eefff9399adc089b8655913cc7da4d195046f58e2cf7e11d9812f1a2a759355c075a2897fee9fd5" },
                { "nl", "44720075595efa0912b58af001df69b25fc03d605d752893836309fcc2973b3fb082a4567e436cb6418f0bd22d35ca65c3f09d310303a5663ccea8f4bf6d6c31" },
                { "nn-NO", "ebc8032825d2db7df1e94a4980892c0dcbd5712acd28d8486f7e56b86e87711eb85e84235677c1650dafe4fc7be828274873291d410876ef18aa835004256b04" },
                { "oc", "29a044d6263f5eb1aeb86e5cbbda58009266fcc13b416708c3e26960e64b2de062dbabe2d5fb1214f6201f9b31dae36098ae1b5f2db8a2e9a7f4170652554372" },
                { "pa-IN", "aacf8af514a71a99fc78ce2842fb16723573ede132620a0b3e1e111f9c1c72db9b49833916e5d0f575c06f2fcc83377fbd94ccbf4b61f9e35f6b2bb9f4ae9f69" },
                { "pl", "5fca30931b012bfdf3e73741180626f8edb84971d0902866573c2e1a9221223a05aadb971065b8cafe91f4778b0f86eac2ae00a0f497befde807f47eb91efbcf" },
                { "pt-BR", "d5f7f859c41aedb6b6881790042bae9599959fe567a76ade1d5aed61a7c09e15450cda7af359c16341252b8d32fc97373e31b67e87d2c65fd12d6e46eeb254d4" },
                { "pt-PT", "9484706a67b4f63388a1501bec6d1397a8e0ab8b9ef039625d979029bdb8c46b622494e687ee7cd2665e59c7b254c23c70e982d9963888b0539188cd556ea266" },
                { "rm", "4aa6d8f23c993cdc79cfcd6a0080f6de4c547f9e625a5e681ce75ece03eb4e1026aede505b4133e3752324b2c3ee7de508f81fdf05031600ab4b0efd8caaee5f" },
                { "ro", "f44a59895907e6e58bd8d538c95f2ffc911f68292d314f8d7a43e0b4efb6e6beef02ed9a4d6c2333298c2a23120cf87ded5b81edc478ffd9c2db64a411d0d767" },
                { "ru", "5c1ed365110d968fe5867485dc28c23a41c790b072ef36aeef28275601081386aca7f64a4299f2053309a65d6d9aacbfdb5638efe20eace5a5dc3f4be0695960" },
                { "sat", "aa8a6e4052ad59526285768eda5a1a5303ac1fc680f7cb303ea3f8f92fb54fbb2c0891a23576cf419ab8ea33475a30ec6f937bbf7217167aedd24d37f4827e58" },
                { "sc", "00707698f9d8bdb72a34eaabbfab9cc57eef26b4430f58e13917dd94743afb96f416158b0a53e78aff5c93f48a999d1dbdf353e20a21ac5d1159b5eb465a77e1" },
                { "sco", "9d215c6af8afc33fc4685ae8b6f3e583d71e06fcc980375037b4a8f433ae77bbd52053069c75cdad329305c76c7e503585bcc2bc6a2dbe5dd38eb026a44eb088" },
                { "si", "48f4cbc9f3f306cb6f8a31687a3ca8f1725bd29dc9cd154168538e04053266ce2724075a8614a9ba400487579fd59bb9d9fc61c052ba588a75e32b9b85456dfb" },
                { "sk", "ca87421578e5e57f282baca90ba1f3bdc69d5713b23fc7adac0077559d86ae4adefb4cb432c4459c189bf8c9a3e64f3aca1f7d30196ab54fec8c86108a1063ba" },
                { "skr", "df6a46efbbff6768b61a9a4ecad61e7d54f7f7fe8af0eda5b73898bfd7045edf1d4bd2b6efa45affe2a6fe1505407b27e4d98841cf5f26ebbbad51c6050286cb" },
                { "sl", "836c4f04cfeec14bad96c3e57632276979f2c5eabef033d1af5bc504cc684929250a1ce9f397b4b2c9b78d94e681dd40f3f282c02923936ed9575bbed0402167" },
                { "son", "eb37784c90e4eeb168efab0267e3ce040ae421c7a5a28f75072b41e2f158d79c5a6be369413ce5485e1e6138be2bf7c12b16e496645627fc1bb3946640d074ac" },
                { "sq", "bd002096fe9bd8f079e7e4a5d21f48b3e7b3b3f75fa5b7fdecb2f892f18c844d58d842f63568d19c59accd7f7e0bdd66f005b12787d029bb33b885febf62e55a" },
                { "sr", "0bef05e54c64c6ed06a16c14f06c3a0b76d16e1f4db34aa3b91d1ae2536d18e8c379f522784f8526d24396d046d6827d39b9e8fc0d694df0e53c443a44a5650b" },
                { "sv-SE", "7283c5629bcfa4ebf14c8aabbe348908152fc558d520afbdc9ec2b17c59e17748d4a0de6c5e95d361cc34b4431d92f1beb0c009c31c2df13d1aa6b487570df56" },
                { "szl", "86eac1217879bef6e1e372168b47d93466fbb5b04c202452e5d0013f3ea78975f72f9f1592c1ffaf1732c6b4bb5325262022bef0bf2afcc421a2e2a5b088d4c8" },
                { "ta", "5c9a553d689450325671e0270a488184c8f75bf92b47ab314ad2ad7c74e91a56d8a837693837e931d973dfa5441c7578f5692dedcf6d86e6d8acfe397bc7e2f9" },
                { "te", "6b46812f545e5342bf9b0c2b93223930c339a17d16ee267c4b94c100a3e8c39d3de4d7286a6bf9b96bdde546c04f41bcb616c2587dbb21a8c009429764cf85f7" },
                { "tg", "a24c0fe24e0f610d4d98924f1e001203ec6a2718b16d3f6c8889ed39be852fe5811cc0da5fa7a0b6356e931a0ee8d1b6d795537aea3ef88321ed09c0b426ef4c" },
                { "th", "912fcf990bfd8e9fab4c1bdeab0845782582f584eb29ce1f2e9b2f1a08c1f8ea8dd33405841a1d44fdf319cc683603381c287fa80c4b5e8373f15dbefd998c2e" },
                { "tl", "11a5bf9c9513666f7562eb863b1b36cade5842b6f399bd7b988dd0963c0308f8d52fe555867813572ea7e7a31053a40817809937d6f20b06062b42e8d0e8c931" },
                { "tr", "e136be5e179ae7d3605b947ece5fb0161d013c72840087127ee313e8ab6456f7ab10645332f465239c541117f7cc62ab1887923a00dc1e0d9eadbfe60caa3bc7" },
                { "trs", "74dad0e6121034ebc30d86b59609d37be7072f9754820bbd1216332396dd6dbc01465531813ddec6516a63d889941cbdb00ca1348c70df799b01b37d1c5f736f" },
                { "uk", "e08b489598eb559a90cf252b2900c3c7b20283da13b16bc1e647475784c1015add2fb122f679a771178fe565acbc0812f109a0e6b20526b26bca7d51ff82e1bf" },
                { "ur", "df062d154919c2cb40a336f46133bf60f31a3ef1dda6fd3c4a2b69bd758e4fcbba66d03ec7818fd19282893fd5071796392fe792473352dba504663ea33d4a24" },
                { "uz", "15eb80647dae56962a28c361c00c95f836e1c65933661c4703fd0ff66269dc70ec625ca8bf4f3db0cd8e1f9da676786ec568fe1c27d7d8e1f2eae2afb28cb36b" },
                { "vi", "1973defad2a9100623c8d7bd3b0f0150d6e16e17de92388d85c5cd801a6f3b261d569c42973b889fd31181223f3c605bd40701e79a0e7deffd166d2ccb9f2044" },
                { "xh", "3a10deb5e651171e282d6b08150a19cc66c674e83109c4955fc49608723ad9e962966dc6aba600da323b136dbd6971d97a489735c9cb0b0064bf5fd615e60731" },
                { "zh-CN", "b7980643465901668cb895c14e249a2c32c76f47abc666a780b17e6c960fc66d3503a481b11740e45829a394fc0426193e863fe43913e06db4381c587eb65dfb" },
                { "zh-TW", "489004114634eb00317413ed9df80083d3f11dfda1a1930ea661ebbbec47e77486b3e2bbbf7eaa1c73ff0a56975e63a1f1ac64907629190d1ddf1bb3a74612f3" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            return knownChecksums32Bit().Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma")
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["firefox-aurora", "firefox-aurora-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox Developer Edition.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public static string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                htmlContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                return null;
            }

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            var versions = new List<QuartetAurora>();
            var regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
            MatchCollection matches = regEx.Matches(htmlContent);
            foreach (Match match in matches)
            {
                if (match.Success)
                {
                    versions.Add(new QuartetAurora(match.Groups[1].Value));
                }
            } // foreach
            versions.Sort();
            if (versions.Count > 0)
            {
                return versions[^1].full();
            }
            else
                return null;
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/devedition/releases/60.0b9/SHA512SUMS
             * Common lines look like
             * "7d2caf5e18....2aa76f2  win64/en-GB/Firefox Setup 60.0b9.exe"
             */

            logger.Debug("Determining newest checksums of Firefox Developer Edition (" + languageCode + ")...");
            string sha512SumsContent;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                var client = HttpClientProvider.Provide();
                try
                {
                    var task = client.GetStringAsync(url);
                    task.Wait();
                    sha512SumsContent = task.Result;
                    if (newerVersion == currentVersion)
                    {
                        checksumsText = sha512SumsContent;
                    }
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer"
                        + " version of Firefox Developer Edition (" + languageCode + "): " + ex.Message);
                    return null;
                }
            } // else
            if (newerVersion == currentVersion)
            {
                if (cs64 == null || cs32 == null)
                {
                    fillChecksumDictionaries();
                }
                if (cs64 != null && cs32 != null
                    && cs32.TryGetValue(languageCode, out string hash32)
                    && cs64.TryGetValue(languageCode, out string hash64))
                {
                    return [hash32, hash64];
                }
            }
            var sums = new List<string>(2);
            foreach (var bits in new string[] { "32", "64" })
            {
                // look for line with the correct data
                var reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value[..128]);
            } // foreach
            // return list as array
            return [.. sums];
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private static void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32-bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = [];
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64-bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = [];
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value[..128]);
                    }
                }
            }
        }


        /// <summary>
        /// Determines whether the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
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
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return [];
        }


        /// <summary>
        /// language code for the Firefox Developer Edition version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32-bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64-bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
