﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2025  Dirk Stolle

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
        private const string currentVersion = "141.0b1";


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
            // https://ftp.mozilla.org/pub/devedition/releases/141.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "4fbc9bcd76f9f3a284f8cab5f34249fbb7eb5a643451415cdd50be9503ac6f6bb13f01c6ebfe232041ac3c92c8308a1300cb4bb2b0a6af2792c41f65aa779495" },
                { "af", "ddf038eef002aa9f3a40631494db25e3196dcee17c74a0a21a95b2d46987c96eb0c8e83e53982fcbea07713934f9e6d0272873a180d6d5c76a8e42d9d7f2f836" },
                { "an", "45c23ddc09c16b523c83b4b0f34285ad4ddb6d32cd5bb302a9c19a633ae6f2391546a737d328ed1ba644fb16673a2cc4a0a2022121d07dac3cb8695332d8742a" },
                { "ar", "9ecefa524ce05d489bb2c43f8882e8d56787b65ef142e05608fd2eae3cd7243ba183a7b8ca66bc96d1590d3c185a9ddd8ee918d947ff6e9d1335b895fc899883" },
                { "ast", "31286dc1e417071cdcf2c01731ed72f96f67c199d7a92ffff12d01cac4cf0fd7e210150b2239b0c051e8479009e5c0327119e8dae097f940141f8f0d97b08b3d" },
                { "az", "5b41a6ff2f7bdab858bf42424e542895cfb616ad5e961723e1b04dc1cb410a87e2180cf92b2c5fc7ce65dfb640fa2239838006ef126d5e5aafa8facc85a76252" },
                { "be", "8aa849a292c34ab1a8a50ce445136d7b72d46fd8325b12a5565719e4448ed413a1b8634dd33ad7f2f157a5af039965b3251aa7e17c30e34ddbd9c9addcca4d20" },
                { "bg", "979739849dddbb4bd9cddc0549a8bef00e911b5ad81d03d4fe450cb12ec7e736bdaa1953fd1269805490cc1fc133d7550b10d60b89fab33c9f46fe571cc5bc26" },
                { "bn", "a9fc0c8714ab4447748f367a89bfa43e276394b05dfdca56140061e04c891e7cfbdfe06769dc7133db1b52a153ee7d79601eda1b7e9274f9cab1c5fa4872a725" },
                { "br", "dfb96d5d7c0d7bb3467b1d8a3aa61894c2092230cc9709948e9729c09ae89055a00411ca7367f08d227789080d0bdfd07286466c448873fcf22556d1d6e44ede" },
                { "bs", "70f80c298a1e67de03dd515782d7557c9df1079c6ae491cab0962452361ad49cb8c2c1ceb8e9a466beda44b23e80c8bdb53e44d61e50703ffe593e92ac70efdc" },
                { "ca", "27409f07746b403e13bb4cffcd792d67f77670d7568d2498d4e6c4da6e32ba8f8c8fae833c3995b46b890f86647f8b7c536e4b1759fbab5daff49dac42790358" },
                { "cak", "c334ca857ea623793db2a5b3b8c6ddbb38ca091b8f47fc4bdfdd5aad1de0ae0b517ee0efaced7e154fa80a8bbb65df5b9859b24de8e2c4056aa45efb4da6da7c" },
                { "cs", "61b3dcb771b7a8977e7c153eea0aa85d14474f01c4b3b38055b3914c853b7edd1240fc082b0d1ef486d07518b7a01e86843116969b9a5283dd765069a41677bb" },
                { "cy", "ed619cd31c03f46aeff7bd62991856236082508dae02aa74e13f6213d9a2acd9338d94136b5a0367d482f17592acd25b1710f37076427520a4073961dc7bc142" },
                { "da", "cd471bc8487a2a9c4cf5d58fc1dbf1583cc45370c9722d6585db1e99d89b7d2f89f5ae02bacf9f66d4971322e45762d71b3c23d24c8cfdad936701170f6946c1" },
                { "de", "7db9fe28b704ef3298816a68612d916cc4419114eb30c2a68f99dbbc2e41ea1eb841e24adece917a5af9d85cdaa966142c8b6bdea276ba3f22a0df15bcb3c151" },
                { "dsb", "1b21682cad28c2d5e7891ccc607e36a09bf5192e600ec64c912cafb0789288c80e693d3677706779fe98719f85d427ca092bbbce6945064d5637b0dd2765ec9e" },
                { "el", "1968609ab480cf68bc825d81ade25fa50092ce5d5c2f90dfc280e91bd77073ccbd2d3a8c1fcfa89f346264ac5f18b6143f53874aba9fbd9ebd77ba5631eaf683" },
                { "en-CA", "30a1ec70597eca27e240a87bccdf297dc99ca33c0d6bee05976ece1db7de2e003fb88a7875b44eccf7ef1b824f5034f0af7078c5b5bddc72b1ffe87ac9665f9d" },
                { "en-GB", "e8d8ae02bd5b4e72672beedde41d109ab377f1bc076a7368769a7a356da4290f531ca9e66548259afb530bdfb25e42535fe3e417491902bf759511e3fb5ee4fa" },
                { "en-US", "0c34935d24b37370139ebacb9cc94422b59c4c18f6bcc968a040bd2a4fd778e15bbdaa0ed09fe634e591370b8616efeffed2096a4cc1d1b8a0da3bce6d846823" },
                { "eo", "c3f1f1551e37f428dcf4617cc738fcd2eb3ca2bd9c300b0836dcd1e72fe9c225abbb9d923c5b6968b8bedbb1fe36eac453d0cb8b39c338ad53959f8979241b60" },
                { "es-AR", "736db230bad60b576a069b87d9b37e08e7539e6de1981082b1975bed820e029a40431e69f02d32b31c2bb516f5429a104d18294f366314ef01887dac482918cd" },
                { "es-CL", "4cbb754a7dd966bfbd304e312f3ca23d6aadd79da3ec20f6aef958a6a3e7efb357088988e9ad3386b7b280a25791c8d4eefecefc85c4cb7108eeb08199991e6d" },
                { "es-ES", "0df33e6b72a5487295ea15d13738b7b9fbf2829e81373af381b957d7bd7caf2c50881e0868dc3c06957ec4d8c6b9a37e014b50a03765a48c6c3a4e15cead9b26" },
                { "es-MX", "07cc3bf54be42ee4ab9172d96650a105d5826ebeeba96bafb33f1d157fa3f8dd47908c7e5e7f959a5f29e2898bc3b6250c3120d6c844415e58132b659e254af0" },
                { "et", "c0c7b00f9ae3bb2e8fcbef635f113d2d4ea18f1ed425de62ec87217f3bfa689f5b341745067b5b8dee2ca2f0126daef536bc25a977906ecc67790017f3c4d2ef" },
                { "eu", "96c86cbd06219bc92b24d011f032cbf3d54011d91e2eaf6e8594a508087f8d42220d75cc0e362885284c0d87635f2ad492ff3f8a46f141957eb0ef72b4d787dd" },
                { "fa", "376bf0d28a47158de65c1cae6bae76325e827023763693b2fa6bc82fb9125978ef7477b95fcbba348639c2ff75b5cc75374f8e1ef139d5f251cb56d9d7ea84f9" },
                { "ff", "ea3ca1280be70d15808edc9c5639b423d40ff0a6a0976f5e2434c2f599f31630424547aa764aa905b38d01fe4bd78ed31f82122617b32d91bafdffb1f773c652" },
                { "fi", "8d534e8d5aa5ab34018b9a2055a98fe9aca216ea895d8d98eb9c8fd6f59dd9f7e0beeab6de15c4132f5b7326a1ed6c2121e27fef90e1bacf5bca1eee957b5db6" },
                { "fr", "293d7e094bb591c6982a82a8810877a4467d476adb4bcd66830f668d897bf550b46d252f3fbaf2c99184e0bc6a03640475b745803fd2bfb28d1c3eb518ee30d3" },
                { "fur", "509ba8145ff6e32230043dff52d60ddda1945494b696e4b321806df682353df14ad64252ee8ed6914543c04be5a77f06a00e2f2518fd87d3125ad4c22e3867ef" },
                { "fy-NL", "42662404fb9a0aa9bbb4903f4feee72dd9444df1c6190774cc5ab81dc68187ce0cfc3fe4b14ff28bc51d1379f0d4f48adab53eeca09aef5e9f70b99852820791" },
                { "ga-IE", "7563a325d43970a6422c9203f9fb0732268a9cdc5cc5f686528e71e6c87fd0508ab5d1d21834aaac429fd30f6eeaea833e29dafbf1fede8e4338872215158fe8" },
                { "gd", "b774a549a6c174f97265310e28a8667f7436136c3df85b0ab351f692ee57cb154e3312fbd7815b889a567c7d9f401bcfca351e6a83ecb9a495c7b8d328e2c7fe" },
                { "gl", "452daee8e101ce5e1028bf973c9f583d09805ab3b5fea547d399e67ce3b3809263195b4c6c13a2a12a2458c9ed62eae0c8579c26de9a41add57237bf873ca5c2" },
                { "gn", "4e79da33b5a09f37f40bcc3d17aabb7d1158b6cfce320732bf96d3235cdd28884d1444b6e17d5397942dbc8fe2521a7aa101287f04d836a55c1ad801d5fbcefd" },
                { "gu-IN", "584d63f6c50897329c5742b7b50ae85698167f477ba9021b14f3305176ff3e6bbf44f2d28e40129c337a336390210bf05c4d2f8b77fd5d15b61f34225120ebbf" },
                { "he", "e83c68be05568e35a202f789b119dbecd17b3f431616a92aca7cc416e7a470a9cb882487e604dcbed8ca0200014ec02f64e5651632a39a825d0007060170f325" },
                { "hi-IN", "03dffb50f7984226a7a343ebe65d8f38870383a7ac41fe16250f08ddfa14c8202edb0987c777856c9da521dd8d8cdaa65ed06866210fb706aea61a2b6cf3e205" },
                { "hr", "dbe570be9069c4e24e0bd399a39fb60ef32d7d9b28b7487c0ec823ccb05aefac60e7211854ee53361cff04c97964ef6722144bb3ff7a034f2a0c508b4f552d1c" },
                { "hsb", "fed8928d4f944e0c70e5d1a0422ce4ca7df2a3f0da13cba883e0022583d268a7de9d37d715844c72e971a33949bb1f31fbaf48a945a395d49065413e8f08bd97" },
                { "hu", "1617656973ced73898db563b60528ad2a5c6bef4275df7a0d0e1726854f44eecba62922fd9ed4312aa9ffc49e36a54dc0df9155bbf234723ffd8230f436beeca" },
                { "hy-AM", "ebb53b95644e67b8218a71780ed1ef20b29f8b07127fa962a658aa11f195c0470be89564c848f87dad7811cc536e51fbb398eb0009a0486f66dd8fd7b2612a9d" },
                { "ia", "ffebe6305107ed72075b0dbcbeb5391f8308cf5e4fe758ba25dca51d94a12705ca3871ea48050e925edd83c8927a0683e3a3ffecee85dc07b84f188d364e62c6" },
                { "id", "aabec7f4a0ca48c19be5aeb1ecf2b4defab3eef64935bde59bdb03e655fc6d939eeb4911ad8139f16e5790e63e2e4275cdb037a7e1db969242684e015ff2d8e7" },
                { "is", "959582c75b8243afb70788a896cb24c1a2bac04b54b7f55898df86d45406162bac30de5662da923baa7a19191dfb9ce6695bd3c869e1dfe067f6faf794bc925b" },
                { "it", "e0ad6341b118fe259d4f3503ecc627a4eff6c99ebc21ace168f58e34be6750a282a8f5b92989ef3040471143f24102f16bbedc4a1019393dcf032864dbc32cea" },
                { "ja", "1cf55d2599f8d49554988d48aef051dc86f0deaa243fc03514fa6b1fba9e31525a1c52e5ea41087e2b7b0953d2e261354637c56c8e2267a0ec6645081cc29081" },
                { "ka", "3a306beebed080283f89f7437b871a407e18dbbef6ca1eb4a0b5300dc0fb5a1696e071c4ff1f4a58eda782491f01af65fd8504898f37ad901f548755ac68ae76" },
                { "kab", "a080a35fcdec98c9355560c96375dab347571a8b2254ccdcb719c27d937ed46d49a05fcc4cda02d9fb1b7443d001321d60f2778865a75da25e39236d4736d777" },
                { "kk", "576ae5841f21fb69a6feca2db920583f7677f987c7674f2b7a57937da07f773d6625f5db67bd9b02df93bab347e91c018f29cdfb7307b740a5a140c228761a92" },
                { "km", "853c2ba0218e0e88a58477c6d051929b677b8f0c53f27b9e37d35b0766ee7794f300f28b8a68200ec6a2db6bfbcbd6d31938b82295b2a0bae1c5ca15f9ec1f7e" },
                { "kn", "1ed056922274fda58091f7ad784164f1f01d6500184350ecb973d46e5adb37dc3af753c5a3d22fd3c3ea4e9bd044191e7c5247c7f5232cc969e56a7191c7cb40" },
                { "ko", "7e8792a2cf0bd9aef997040226eb29665537cc7fe1022e3a48ae594d0cba0ac084f60a20dcb777ee9535ebe593dd480089e29b4d3e2b5ed7ff1dc5ce46b975ca" },
                { "lij", "8006cc7f0d962c97ded7974a91b7bf6378c531bb68a67d1a38cc6ce414f59534402538a6713f35d8d1f0132dc7569f27ecd819ed4a42d9789e192459327730ab" },
                { "lt", "7c69c99c00c373fcb80bac791a07a13195f5506326e06e1de632f5333e5515d853cd940f1c60a40a8987b0362760a41ccd77d7a26e70002280ba7e34f968c3da" },
                { "lv", "4c0ce02eade7d02c74271217602302bb5b88ba3d58bcb6216a96ee42c44642c7dd40d6aec33011dc25266eb00a060eb6fd075ba775cb2a5901e6d0bf2c16acca" },
                { "mk", "a47fabe8d7f8496abdfc0d72e8a48b53de13bbb3aa708bb9e68c9ff4b828c3ff8df7e05b408f36837fcd5899480cade98b2f7088d4e1bb9d409d466a582c658b" },
                { "mr", "77b154c85a592ba3252b8ffbaefe2ccfc40f0a4584439a1526f5df1f995e25635e5d127a2afc6df2b7f0b1c8adb203f94601962dcd5069e7fb52d3e0ceeef551" },
                { "ms", "b73d692a56b81944a9d124df2c19edbd8ac6940d4fc9eaef2467b171a59e79a12251c8e7fb5f21b84096fe2b6e060d64a0b515c45e2d9dd01f3a55f688f56de6" },
                { "my", "2ee6371690ebb86a522c175441ef20b894e582761fa0c34d2116c0e6f3949ec260f66593bcb20fdd5c8ed0aca87211a0a5c909d56b672ceef55c8069f31da3ac" },
                { "nb-NO", "0ed17402f5427baa78df3b69af86553929ac8dc994f89d56451ac0f4592aed67e9e9e84da8cf2067a578c934822da3e4e06d263a0d79762752dab2c21c693b95" },
                { "ne-NP", "80c8dab2b616aa0aa3472ea38d9834b2afa7620d350b14f298aa9a6a568968730d15f75891697b61a664dd014f7bc90d60de8c99f6bc672b4b359dc4cf1e52bc" },
                { "nl", "7b89095371f684deba40b0848b446e0f4eddd39399251571c20b25fd5522efe9561a949ccc6930b0a209af6f60137f532cf4461e1b47852e8d82ac20180b5bc1" },
                { "nn-NO", "a52928f637dbdc5029a4b29bee2cd89c743ece35e89ceb48507533d9f96b23881ce2be6f8058c49db5bc208ca268eda2b41e0bd17f9be81cd12a5b24be0e77c8" },
                { "oc", "a5f7cd5ef8f34f2bf944d8df21e6687e01d31237007c6e157192f601747bacd6e9c77da38a8384edfe84c5027941b6e970b7f02e2d828565aaeb2e036715a18b" },
                { "pa-IN", "b224b375340bb4d2400b23cb9647ed2fe604ecbdd76e5f38f789ac7af9632b5e50d4a6adb5b378c486e6bacbd8e01090ac42927167760074e6cef39862d804d4" },
                { "pl", "ed7d81056046267d64b10f030e0e15d140ae2567b63713e723d87c67eaa94390086afad8d7b0dcac2c2c9403fe9b1b9e083ed6c810ad182ee9aa70ca28ffb00b" },
                { "pt-BR", "d8028215ba63246e174ba579a62c720584a141ae983f6110b397d6461933cf43ab1cc516da9276e40e7023311028374b7d04f6457983173e787a8c84319bb15a" },
                { "pt-PT", "85b50889e1f43c1cb65a51608c1ab01253aeee59698efe12676ec7c1333e448680a7db0111273ae82539f60bff98aa53d8737912c419783a1983ef69f1b0632c" },
                { "rm", "9ed0b586980172bfe6ba37ae891fe3fc2a6e5032901e31d5bc0f93f6dd5d33a85252f595c17d5416cd07d937d6d7d4f282fa7c7249fc0707a83158ef900bb4e2" },
                { "ro", "7141c2caa4eb6bd298638d63a5f0ccb223325cfaf9ba3bbe097287ad7c694c5bd138eb418e17e5be1befb807ce84c1afd6b0a8e37589b45e266c767e066ada09" },
                { "ru", "734db02fc7cfdb75383d5e796caffbbe7c1ab16f57c1ef3dbdb3fd673a9435070bc5cb9d660ae759b9cae8a0ed83a7b397f774ed252547a7ac8ec662fa970e24" },
                { "sat", "9470f5b2c656dc75266dde26d75747d3b2b5d679b8bb409f0c15e09c382d899c28e186bd52cbcd3540121adcd93d4de34e6763d189b9e1e6b3da805dd1fb6f5e" },
                { "sc", "8226471bf9658075c1ae4fcfde7acbc509507774e49deaf4a79dc0f44c31198895042000c96066cb1a2baaa2bc53be69feb6a2ea6b94eb50d1a4093b002d4d70" },
                { "sco", "7f32c887cd2f08f598637b5686223130775ed6948594a0ff3d253a68fa3b4ff3613d0d08428e26f9af579f309be37aefa44484696e1bfa4e9700483f553c7e7a" },
                { "si", "960ff1886b788a098460fc1ad04c2a36d80faa411b731d61d51a8af23acb8dd97bfafc3caa1a5d296a0a4c6b99795e49ec717a0884471a64d4710d612e32dbb5" },
                { "sk", "64692bfebc33f61a3302c8449c703a8dd96474c0df52a0b97236c3315c84de8c38b7ecc829850f45450be333a4106fb7a12715fb36613c5228bf2ed587511b6e" },
                { "skr", "316674a0468e78d45d4cde41981646a4791ba3bc93475d6633cd4a940fd729a7e99286fb861d02bb78faae6eef41552b9cdb3f6bea7307fffaf7fb24402f4087" },
                { "sl", "bf3a15b3c71411f7a0f1c4fe31ef217a1056d68917b130009abe35a372b4bd5871458092b168d49b1ceade59dd3d409c822cc85165c67894e5bd2e9c20655183" },
                { "son", "4dc03f2e864c409376f2cce4fe379002ae2b6a8b2163054fc3cc83d135bae528ee4938e41f2e946acbfe2875567298968eb53fbae4c6db14f0be6abf7dffd225" },
                { "sq", "3d261db503d7f949d4a790c6197e8b73236caa28f1a252536c1f717b5c42216bdc1f9f43bb1840cb16974aab82d06a2a1981ae1f4dd9fdd737c07ef923a25800" },
                { "sr", "98e8b5d2b3bc14b693e67b7aa7e0e9c592c10ea5ecb519aceebecbed0a160a96404358fa672d2d6206afcac19a2610d4e15ca70ea05cc4e5f4e3bb68e5e5f640" },
                { "sv-SE", "eb70886a6d0ac4fad13796299edb2b9b682f9b0679ee6d2121b6b1fae85a91532ca275d8d91d6ad762ac9697f90b0221c522b52f57ca2a5201f879fc5b727040" },
                { "szl", "2c1d18edce9d32b44e0f865d4d23016dc28ede931d480cb325e2e6e122b31e4df3490e582a6b8feeb1ce8867a58e8a6c26892ce96ebb1845f0c8860c71cc5074" },
                { "ta", "1b8250c89bda9f42ab0e57438c28982b840b7bcfa0da667a23ea64b5f55e1f5d0817ebe864526b18a351330cd745b6be2141460cb55de0e0a7c5c49170402fb5" },
                { "te", "72e1b1ba8213d8fd3d3ad74eea051d4975628d60490e129d9db79b5b7d9f607a38fc77e08ea4f5475838e09fac25d2a1c5597bd548143b1eb6435709ef330a30" },
                { "tg", "2f8080b297c44f8106a97a79c137456b382df495b192ff2bb49bd913d58fc4a2a1f051864f73e4e183b2f927b3b1045b8a8809983e4e4255d3a3a70ea2cc0271" },
                { "th", "1ebbac1c0ea9175f806cabfb916d433f61dae4f9859759c19092b1e9d4646b04702e347ef6808dce005f3282fb0c48dc99e429bdae38f3a823ea1998eaf0b826" },
                { "tl", "c2399f4edce7aeef8220425cba04818129bb803c40320da85c4ee70a3b2ca3b8de700f2200bf5fd16c3926e637abb131d087376d1da8cd51dac834495c4672df" },
                { "tr", "b5576232438495d660c6d6d45bbae7c3ede3011f69b06a75223e942b09d2d69beb01991bf825fb25d8c551956ae9b2d7e7b2adec88556e5ce4718d9bcc4e5251" },
                { "trs", "4ca2a1190a30add82d8f6fdc1b67f42d70dc21c19f65f91ee513fa77bad973721a189447c6f4e8004489f2aa85524f2d4c2c045c0c62a6b624736cf453774757" },
                { "uk", "1eb38dc81c7335745c823140562ca75e8b58023f305e9db8c1afabfb776ebe15c1a117fe2012cfd85608392457d31e107a0e239eaff961e4cd4f784913b9b126" },
                { "ur", "a2bf5ee7277d598fcdd212ebcb45ffe6c8f358760dd17cde3e15cc16b1843e5939e29dfe38d8b58b59bc554e29b8716e2e93ac26ae6558cc13dd06e2891baf58" },
                { "uz", "69a916b97ff14af6cbc5eeef52fef20104b24d626ea2dcc05e1c1ead7979069e81bdf00a8c27a5386ac02c143a10f864bd36b26265227e2d7a412235b8130a23" },
                { "vi", "71b4740d129fb03d4eb166d1e2e39f7ab64565ca1cdd51195e3e70f64fdf23dba5e7ac90815b85039ef4d78c2ac195a854726767aa47206f870519706359f399" },
                { "xh", "cb672a9ed11cbfe7e69dc1a524ca48db94b14af6d4c84ea6a322226d039f9a021a247d19de46de2125db702aeaafe74691f74b0f33eb9d20be55ba504712b34b" },
                { "zh-CN", "deeaef58bb818ce42871e066103105b32f1154daa1fc9b4ba757560a9dc5da31399be02631cf16630ddd6451649f3a324dee86d1ce206c33b33e658091dfd4a6" },
                { "zh-TW", "59eab906f985b9fbaaf0f7b556163968db2a919847d9b9eac86f50412e942bbc23a4ba8767da80e889b465bfbbcf25984bc643a54a5e95dc6006e28d1cca4d3b" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/141.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "cb9a9c468571215ee7678a45a1e0562780e454739b74923817a7028702f9b47ff1782a2c47183d9f8dfbe500e936217f0ef147d69d9f8d1b9521cd3b6bea5460" },
                { "af", "fb4e4141b191978afc2ee41b00a4107d195a8e28151545e6a546854cd0dd1535b612d9670dee499634e04181b02c5b7e89377d5eb3a7442dd1c5dc403e69659c" },
                { "an", "06801d51c66147f2de739db0c1768052be685e2cee90817ec2f1b22d47186fcb32d848a7f3a8d528ac20913aa9405b47c08001e8bc5c066db32066ea041f857b" },
                { "ar", "281e5da9a4c96070e7fdab00e7e6d5ef134a22cb97c0950bf880aedd342d32acd1ba439adb441f75b5515bcad4edf9bf2d7dabeda393b06bea00aa3d6772e70d" },
                { "ast", "218c0d21dc8819f2dc0ba0a49ca73d897ece0ca8e6f3d52cbb129d61c3b89ff7343ef20ce3b6e3fe757da11ed3430669c04a1eaabc9a1c4e5385161d142f7e8b" },
                { "az", "42de1443c402802bf916775746f4e3f04a7eb4d8429da6e5d07b3fe104607a8237864c49de36dbeaa6368f63492b35aafaf7a15d1686392095b94627d4f1cea7" },
                { "be", "1d1f04115c64fc5240e31bb478e51aaaea83503e1f149756a840add83cd0e60b0d20fd4459fb8423f8037dba1550efc322725fbb534b0635ebc8576b3b28e7fd" },
                { "bg", "04118733afbd7ca5e44eba7b5bef8cc09689ccdf8f26b0ea3d507ff672f3a06ac29f499395811a60a726a8a27ae86d012dc68b5fc392afd1baad4b7830fc7f86" },
                { "bn", "012cade75d880ac30ccf44ec1c4f5d913a740b600c543a4ffd94e70d49ed14658bcb6e4c3b8104001fab5c573d856a731729b0d5fcaddb3e4ed6e39fca52bd7f" },
                { "br", "d3055e86c2ba12976e2caef918f7c48973a1f72d2ba71f539e44d25f3e20db3437584d7155d2961ca9e2aedefd55550eb1f420cb108b35a83727ca6edb4af948" },
                { "bs", "144cd1da0b7d53a8a5ce41913534efee40a981f05e656e476d9adddc8670b9a8f112f347bf5ebde7f93ec44e6cd7420cf4dccebd4d66fd90543b33f1c4192c3f" },
                { "ca", "edd1aa21c666682f9e3e4a6ce839a4494c99d3b6f49b54d5ab3cda341dcba149a27afa2782a23a180574815395f6bd7f9c895ed5012969b91550b1061d08f90a" },
                { "cak", "f40692e1c9417892da05c7df64b91a3a277360d3ad4a8ec8b7975fcb6545d89bca88940c5151148abd8593683423293ed8537cbb631ea6e254e228b10c15a52f" },
                { "cs", "38cfa23f42f2d0ebf4e70c3bd3c93f56bd8922f08d611247190ad772636dc6902601d0d052cbbe69c16415487202e39adfc20b06de6a3804fb23652fd66c3386" },
                { "cy", "49279cb33cdd8c099f503e1f23218ee2082dfd31d4bd238fe69b6a608eac6f9c2bc2494adf989e01a981981dcec4f4185515a1a2ad93b28d2a2ab4195d882bb1" },
                { "da", "3de5fb300dc69827888052f524e7f87c2b09ec56be8aa5a4ba6a3290b0be367a8b2f35419a607a729ddc14b7426b8e3b24df1ecb2b96f02f18a64ba10880292c" },
                { "de", "f4d9d6d35824d98bbe329103dabcfe3e2be8bc9866c280f055c7b91c69275ed3105e70f65be326719eb215529e6ef9aeeb162d9cbcfaf0ec4e193721d010e242" },
                { "dsb", "bed490c695e1165f4db21eb68368d97915fe790b8ea32f68be86e6fcccfac2abe76af6b3233fd033a30cfcc25f5d2c1390f7bd98f003e7a796941f9095acba19" },
                { "el", "b5022b6c1b8bef1716c822a1ef827b4ea85bce58b308834507e868fd367a9ed189bc6b5c7f5291a120bf416cfcd0d94d4c129d33136290b009e73af0b98cf212" },
                { "en-CA", "0da7d6588c9ae04b78a98d92ee6f79b5c5129c37de059739bf2ec0d5e4d809055ace9905ca0590053755e94a1cd27cc1914ebf35193bef3c098ceed5969fa826" },
                { "en-GB", "f3e309610cf3d59f07d9c7469f80f74bb2f27bb961f8b8da7c117475609ad761f69fda859b94868e98929d950548288c8cd49701aecf46e9755a134161b94483" },
                { "en-US", "6db146f4734daefc909ce605e64bffe1866ddf57c6879879f9d4bb59f6749a1cf1d2fbb828263447cc79a09c34ea229e9e1a3cecc1b1fa95c7faec69a5f225b9" },
                { "eo", "5dd786caa86751bb61f9696126d2c145f84b3bc104b6d38668636b3e959cdde23e5ae31bd0f5daeaa64c1ae94997606aac0befb4e9e0719fc70cb9f87c1e7832" },
                { "es-AR", "0573c94d343b218dc475a22cd3d22548895acd7c733c307fe4adf9f7fd6c70ce8a3de8e358fe160d9f9c0005fc90d44c880ed599bef6e38cc6347c4a02c87518" },
                { "es-CL", "4f0d21aa4a1b201d0f027ae0b18c82008161ec4a8337bc7a81a93df1d6c4674257dc0e276addfb383d43e6a3898e8c22ffe9e3cbfa736d81a4d5967971783d8f" },
                { "es-ES", "912bc18bf1b7fb325e2c0cdb22d48250053e69967fd0667b3249e8109ea8ce3332c3d330c80f3f13f119503db94be27843d3799877539194f13853f7e56478b3" },
                { "es-MX", "e466bbef5fae3c515f37ba4f530d3d7ac12b8daff138c07e41b80b0ac4fd83ed2cb799f8969bafd56cd653864c68fbef37f8bb60d20d25444d10fde6fa1ba13e" },
                { "et", "0c4d6281fbe766a9f6d299875d1fd7e29fb7b8877173041bc8d790937392484354ac7d082176081de419f057c032fcb1a712c2b2b6399f0fbbb931bd92c053b7" },
                { "eu", "1f5699e77f4133ea2e4d8db6410d1c5cd238cf1c58997b8f594062457b844638e4172818098ab45221e0af649498747fdb0647b2488584d680282429d45dde2d" },
                { "fa", "098df19855effe3b78598ff1246298d8d64bd6aed4d1ec829b01236ee58c0353aa3c11a8406df9de5b9744a0cdd77f4d5b74048960370905eb19ca2fe2159f69" },
                { "ff", "caaa2a0137a1784d233308bcbeb7105503b6b5b911a52c157366ac84abaf138c55837ba0e2cf08b4d11b7a33dbad5097d7c0140178b1591331a4e9a2553cb245" },
                { "fi", "ed218db5e74ea73ef0671c03685682d03f9eb2bb2865e1e150ea6f8e2f9aea323de14e09cfe3accc8a07edec5e7b7520f09c08b74752e828ae2de349b9b89b18" },
                { "fr", "de7c8fb1df8b828c39d1a4bfe50aa042f9bf6185e33acf7f200ae4b6211e7ef744fb991f801272c8763e9a55f73955a70a7d4051f78a8c6b85c5bc017a6782f9" },
                { "fur", "f41b687980271bc2a3d2e60bbd66c254cdd5447cb2132a3764390f71be4ec6e20d36a7a727aad4a547d87374799a0b59631b3de340eadcb5c90a424e648b3b05" },
                { "fy-NL", "64211ea7f1ad2bd38ad97f190c3b5fc9ba4bd866df12207aa3d822e033d8085caa97cb22a7e06e818ca59e4295be56162a97e0f34603cb23c9d10b66ab259cf7" },
                { "ga-IE", "1f64f8067d49dbf5186413d870fe11a6b2ce4bd9a538ef5e97cd9e979d5b1f99b80f5081741c2fa9988d2e8370415d1bc3b0e702149c57797e6a30a9703e3dac" },
                { "gd", "c9a159f1d919774f1bb4e227a2b1156804ecc45f7dfe5b9de04a30515d2b42beb19d72f89251a4f77bf0129df16036f46b7dbdf099f38cb982f9ca3bd9172458" },
                { "gl", "834cd5f16cd0f46bb674c7b23f1fb131896a0c6e317e09b99126c519101b5fce0b21a7fba9ed8966f7a286d871d9814556ec972ca51d256b3fccc1c6637edaab" },
                { "gn", "bd4c6542eb5a2dfc804e4a8c9b09c0f50f335e021205f746e9c6c7825ab2c60a63da8acdeb09fbaf887ecbbb7a82e05f1ac859e07b5675bcb218004b7f27a435" },
                { "gu-IN", "28da68eebdb0225f91fd59b6d0e294def5a4568afd33d465293ec7c001fca59d5e7eb9f939446df1a48bba7439c359da162067fe64ced3848009918dad6f69ea" },
                { "he", "f4374d88edae9bd29d4d5d80a03e6ebd774c591131cec8be6c8c30b94455f2ed96c45a561336d35011dcf51d589a9546902d30d23da411f2222b84f31125bf75" },
                { "hi-IN", "7dc4b9410077362e4b4bf589634b9a0234dd796a54ff45a29f912382332b4959cbffb6a5276cec4bc4ca0645b1df56312492a78f6729b39fd8718673e3cc73cf" },
                { "hr", "101a5cc23801461ac3c13912917d8c0281a1d72ac4f47dcf91fe8fb195be67397cb91967c4cd4c4a6cb7dd45ceee3dfbcd811ae0762af9f77cbc6f8d584b8050" },
                { "hsb", "982591558a6ca4c8b8bb6e4d2ba1aa30c0d0a94714ea2d1002b953675e7622a976504f7ccb540c37e3ed63b8000a53f1c2a42f617f920ea62614919b2f241c7a" },
                { "hu", "6d0d2e44051ff353230271c58447d3e9f0c055e57f519d0015020b98c838934af23527cd8eb91c942c96efba23329e4bdf4fa860e8782c9ceed30059cfe7f66c" },
                { "hy-AM", "afcf89ca85ffda243fc58c2cad5c654983f6104899b9c983ee617783b32ef737d1d4c3d82a1ab61d9ce95f0a97213f2a7a841120da673d2998080429f469b2c0" },
                { "ia", "08c8be30c366190c466aa3b5b4e2f16b029160f6f4327a8da52d61a869f82f15a5d991065aea16689cc2fba2a99b778b8cf4bf1e67ada200da61f9d883aac2a1" },
                { "id", "ca8b8602038c2f9f1f26dccbad5cd98f789b204e925156b4123ecbfd457d1c8fdcb926603ace9ecb86dcf761abe6c3580f3448ade7147164f288f665287e1908" },
                { "is", "6709fce956576bf4a09a497e9b7830082bac66cc61d835968a6f597953d38531f3a795d29e77f8f6013f911b8efb06909c789cc4c47fa310cb9e059537f06604" },
                { "it", "4bdf9c55c69609d7aa52866792a27d0b18820155f06955492cec30abcd9b06d5316399c13694432b5d25dac791178cca414da8b5830158bfe3ff101d8ba37131" },
                { "ja", "242c2e44f5467a1a1cc647839e2f4c8099380cf6b2256d1bd5d4e8cf5dce84f1946d3c62176b0be113b029f2163ec35c881826357a86f2a2fdb356ebc1e8e962" },
                { "ka", "a64ac3251b461f1bdea4c6c7d75b9042765c1b08181a4bfdb510151492a9ccc46456f6656e3db52c8cc22ba29463a9fe9fa17e788d57e41f3ae6f222e90cdc54" },
                { "kab", "522db76cab993db14ef7ea225b6b81e3e5b66de6175bfd52d1efa4c8ad69e7067bbeab19fd17e8ab402e22590f54ba1c0768d9bbb9ba968b25f509c42048b060" },
                { "kk", "18bc982914ba2713675757354614b423cdbd94a617a94a6f03bf477a2148bf228e293ec83fad01be8d43c5e78418f7543c2e3f87e6bb155a58a55ebdd3d7d787" },
                { "km", "542da90f9b7660dd270a06082d1d2436185f49d5db44f1cb6b00244b78bbc0ddb0f2f976d672095aa01ba3f7e44965879b3347b7761d7a73dc5c3c414247ee50" },
                { "kn", "ce37508ac629e3ab4c445ba35182199b7eb0765bd9b50a0e87325cdf0f1c70998946a7bd9182e4d3b22d08bb31ec16c0a2db8e67c328cad4c3abc30ad01166fd" },
                { "ko", "8d09d7beed63a72562379509c3946cbaa03bc1efe8b22111b58a3d5517b95414e84eff051df951ae446283427a51933a43796bfe21eb4a3ffbb8deef05dc37c5" },
                { "lij", "f99c8d529313513f7c706cf2d9fb77ae3ba71d3e9174de1a6bc3d7128f03d7497fc1719a8aa3cc9b6661234b008d15289b6f1b71a1f4156669ce72135e987c32" },
                { "lt", "237206a6203c2247dda9ba2eb4d995afb6c3bb9838e85b3f4fc0171e00cc8a997b191322f0703ef59dc5ad5f37e22b9fd52d4dc4457a030f38161d379d3bb3c2" },
                { "lv", "17a8acacbadf8cc44ec507883c1d1aa399ad756b1c17d2ad152b1422b9b56074a488cd15ed652799909ec0d518a63fce237347f67f4c5146e4b9fc293f610b7b" },
                { "mk", "946d79acf3e8adcc55bfb0368fe720126ff790178a0ffd1a226343589524cc7cf6b65556f3981b01185e95c91dd2f16eea8754ddae013b563d18c0f98080ca61" },
                { "mr", "7edaea19a91b846c475d1a4df88ae5e98f22e6fc573dfadd7206be4938d149c33c09a8fb998b027331040c2177f7a5167671207674f009f7824ee6cfa34a2417" },
                { "ms", "fce9a69c9cd507281217d2cf7e50fd02cb5c704cf69ec87ddc890f5b09be80aa655d9bae31ac6d1684297f9be263e08d604aacb86b2c7b8ed586021deb8c1f02" },
                { "my", "7701affe7af045ec1c177026633f90260735742feee6b45818e1213c011ba81094dd225e853dbea43e8d527f0c62bc94e99448f4f169cb105f05e45fafb0ee63" },
                { "nb-NO", "c5c93408e856dd6a43ce787c9245ee8343129fd0d005fbe34e5ae0f3dcde85ba0787daf90ad7e3121782d5f960ea8e191bd684bf5669871ad72fda47dce0aeba" },
                { "ne-NP", "370563d25baef7fb7b803ba41fe393db3aaff17e9377d465e3ecf21d8844e98cbe835d27fa532dfdae9dbf3c23e568a1bd0e44d661f145b479e209117cd15d62" },
                { "nl", "7806c578324ec9148874fa1ee4e02d8861330faa06ec532ea49ef581b8e612f1edaf6c246e6fb51e2db232763bd7521f05c1172728efc85ef493b914a1722fdd" },
                { "nn-NO", "166419297f24693b425de66d47862efcb45d1b7ff74e78c8c301b43b55d43ea624b088791e4cfb86cf0bccc3b8142e96bc2879622064b3c4ecee610d782f37b3" },
                { "oc", "92eb99d3c2841366e8790408480aa4b0cb0ebe1aa161af69142df33854a3749518979924bb07a18e193775a970adec31d26c0a9327fc3745658edd72a584a412" },
                { "pa-IN", "0965587a214d979d0371631e194f8de8c1f0b2f9a46f40fdab00304ddd89159d8e2ea076e8c681fdc513d8e3bf6eea6b580dca05dfb4160eef28fe85a1b1e0ed" },
                { "pl", "a51a91569b0623fad51b36a72d56269d680909511aea29d187c59cfa7ce624e7853e2063a799ba2722b1ef7c338b41938d674ddb71d627857046300c7d7616ac" },
                { "pt-BR", "93e023df7b41beeb5bdfd1d3940d35f13c7e12a1296579979b3c7e71f8d28ecdbec4a3f295e96a055083946a03a96de3c67a28f7553a50a5b8a97df69ad292c4" },
                { "pt-PT", "6902e30446e6008094186e9e355cbcb7116a4d5786dab98d18b7f698640580eb4696c3bad3e43e328c48ca3c2d7e92bfb0b7dd1840ea16eea00cab8caeb72fe4" },
                { "rm", "d6cd28cf58254df811283a4b37f3c3dc8112b1648ed11d77b83562b32dca44974137ecd77c87169345751c2560b0a3209d0633d8493233c8ea46ce89f9120e85" },
                { "ro", "c9989f587b4d282cdc7c86d0e51425ab9025be99535a3319c380e6b883767438c44385e510bd93a5b8d20f47bcb1ffc93c1176962ad06d13cab04c8ad464018c" },
                { "ru", "5e320bef3d708cac01eed142424b7f66fb5fa4a9bb23312a7aa03c3630add4d098ba823afb313203cba8e80d3d8352b5dcda7b7c64dca20f6130498845c0e452" },
                { "sat", "11d978953a677cab8f33f5a316fb87151c1c4bbd7bc0a134bc34d2076f78c800decf45ac1b5e596502ccc7d321119b9ec3087ca9952dd8f4871be36af03d941a" },
                { "sc", "b30d544f00063b0e00309660e5f674ac3e703b7b4b2fe87cb94442f671e25e0c5e439c502b6254d222af30b4331ab89995d4f0ec1f554d2ff0ec13c44d651231" },
                { "sco", "bc78f3c36b7b2aa138c18f576a49b89709a52f06d6900f069c8a2e5685fb28c6bfba0032bfa1f1eb0443af1ec1a31fa8531d5a53f7c973d7dc9e8e61506ce1db" },
                { "si", "79699bac06bfdfdf1db4cb8d997b3c1c0d9d8022618bc655d34396839b5a7ef42b0bfa1723e74449374614cc78c31d5498f4fd8249538c125215307cd7c4c5ac" },
                { "sk", "be4b84a09c1e26777f43b9a721000e676cb4f1a7bfc7ba5edcd25bba5f9b0ef556d4bdebbe1d937ce90be117ba110a2b7266ea650962cbce746b139281b055eb" },
                { "skr", "6ebc49a931bae72e3938ba0c942a866e056af196f234b3abe85fcf3ef046e8cb3d9fc9fee18c603a08bef4f5b853b14cd779e32b4303ddcc2f009f6d19907b33" },
                { "sl", "ac4a855a3055699ff97823a7bcc6ebe9157f1362e75b1b197d791ab339b824acd187febfa3d946857f39ff5ae0a7ec7967563d0abb1302e5555d07b4e9b1932a" },
                { "son", "0c4502d492a48af204080759bae16ae072c36213b0ae31bd8e2088485c96d3178a7752ffb96c12f2fb0418ae9b18c2c06749b842dcc60e1f67d98b4620d49ca1" },
                { "sq", "9f63752627d17c0afe48c06c0e809b6dc420195d833b8585f87e34e6fb9ff4929f3eb0f559a2fd065de57388f8dc864d9401fd95ddba24562c6db1ba87912d58" },
                { "sr", "a9084c4a075b3ec44d536b6b00bc9be4dedc39b884d39c06defab6f199134560374a3b66f57bbe418bf11fb3493723ed241b0a2d040d10397ffa4dcfe2ca8611" },
                { "sv-SE", "1d5c621ec97601ebafcb7d6a652ad09e008087b2c25fc8b63e06024c7bf4ce3c2dddb29aa2bcd8a2966508262602ea357eae0a85b7db3a8aa8a75a22238a40ac" },
                { "szl", "c838ab2e440bf2ef5cb6710bac5ff0b951caceecd17d325c11aee74b200ab3cca0b2ef830e31da3df69fde889b11a37b6917b87963d0a58f29942c34fdc27012" },
                { "ta", "450310588ce46a8136496ee34449b1982985d4f4c2af1b245e44ae22b63a38eeda500fa4b69a57357527440e9277db0a5e27ec2fa273535ee569d7491385849a" },
                { "te", "42769d526912bc364487751ce0f0e0b45ddfd63c898da934feddc53c369e52c56eab60c7bb5afaf9c7e2bf2d5c07bcf20ee61aff206754b1b2c1b507551598ab" },
                { "tg", "06d467aa1687e089b0f6bf019836462ff56349832370288680307c757b894a0532b83bc90cc6664a198f3549af159e79c0a6196a3bc8f129bba24fd6bcbfb3f1" },
                { "th", "2ded9a73f2127e0f418b4294fc600ee8d1335912c1e9724d322d601b1dc52fca80b12c2f099da4cf5da45d31c7973929d21fb94cceca0f5a4695ce4bcc2dbdd5" },
                { "tl", "d0db7435563c28135a90bdef7a835729d8502f992de2cfb66c54b558aca8d7caff9280d4b3ba42f86874fd7f939325d4de4e2c19a3d8196dba82a16b74f95865" },
                { "tr", "e41536e3b7cad8a76e5284e131c0c7d550154c6f197afe4588b161bcd7bff3dc5f11924d5088d926ce6b5411a228695c9798db0ebcecfdd7eb7347ecc9c9179a" },
                { "trs", "ba114efe57230380e104c1188cd12035fd725bce587bf3dd66aa175a7d87615ec3b000cb4adb38252ffa77610dcb3c3a93fc2a8414c682a2facea2e0276f714c" },
                { "uk", "a86ff56b740ade17326a92e3bac2a17744661820bf386aa010d063b648ed8999cfaa410d9cbcba7117bc516f9f6e14a38ae8e46b68118a4b0d94ae7c702c9e8e" },
                { "ur", "ad4e7a94dd4dd0c03aebacfa722621c9d4de18e8f394ddc49c5791da30f256ecca80a4d5c3bd5660d9e569c3314c55de00eddb693081747e9267e67e4f8cacae" },
                { "uz", "e724cf345645fb3cc65ee417ddabe4fe5433cfff75cb8b0787b6ab8dbec156204fb181a2354142867b999566a5a5d993273689a6d9a186e44d67eab16ca2beb0" },
                { "vi", "851891ee5ea317c0993e2c518389056a312306274c12431c54b01aef92cf9cce992ab40f164be342cbd53604b2b25eaa3a24823195d47296f2dd5d21a8cbe026" },
                { "xh", "3a447a0124ac4ed751ecf3adfa5dd81771e96eea7b7affdb28218548eed42a52ca5c356ac08973b08c7fe4b51f6ca90af78421cec04c24b402bdf41f95be2ba8" },
                { "zh-CN", "6963345faf788a1887f6577665856b5c80069453bffd763a2c48a90b7635c6ef43b3f233deafdb8ac628e2b856a74d0ece26e0edfea1ce67c213208dd97fd0b6" },
                { "zh-TW", "c5142ae4ead3f8fd17e3c2c1f01cb50fe0a614d785d3b1d27e81ffe1f9751a30320bfc562c649b65fa65de7e8e38d05e1a3077f5335d772a14bb79b6c8188c8a" }
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
