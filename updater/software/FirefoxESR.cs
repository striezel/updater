/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

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
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "128.7.0";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.TryGetValue(languageCode, out checksum32Bit) || !d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.7.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "1644acd6188a636ec748f3bd91181999eebc841f258b33fa2df17844eac39f894bed3389acdded1b86539d29fd9ff1421d19abe0e53c81472851746a571c8397" },
                { "af", "0ff68f6a55f3ce86e336778152c6e878d380be8c563f593481d4e3d6b126a4064a982960dab378622dab722500b8c71a8e240a6f1d0e70e1041f9113efd88204" },
                { "an", "2d0288cbdf228b6bd967115411f04e083523fc9fac630af586a2670b22a6bdb4aafb09877d53269ce468d10bdcf2dbf7a62e4670d2cfd560183daad4e5d11c2a" },
                { "ar", "9db6ffff1b3ac4f489171ee0458658a2e4d0ac7700550623c341c6526f629265950a896a600e59509d97f690bf67609851d2b6c5229cea3e7d14b62d0d88ceeb" },
                { "ast", "a38036be28d460bd0a24a7d43be099f8feb7f8227ccbce3446ec1a4c823f61d403089f04b6575314fcd1b321bfe6e066b2d87f581af06d6b93cc21141b48c028" },
                { "az", "e9e814439e2376d4474d5c224e0b7235d2cbd22603d02dfc22eaa209355c10b2f6085e2ad8dfc80c15a245978e9630855e31cf768e19321ec8e54a3b2761ee48" },
                { "be", "9e1eb33a464b1920a615be67f5d9e0c0b426b5436ed88bd1cad40430a7c6010fd36c183e6cd3f712d09a9bbd06da020c0f9592c1d0c50157dbe42155c107efdf" },
                { "bg", "67b80a7bbcce9220840a0109e7537d3d788a6c79545b9b23b309811c17093fb2f22aa9e4d97779e32f6438c621374a50e263b31dc6c002ad19e9b94895912556" },
                { "bn", "907981b21598d841b8789947fbf29baf8ef4e1ceab9dce5e77927bbf4ec38e38ca64b7ca0c4a142c35b3508c9cbd409fefb665acc9aaf7762e3e1f30f60bd440" },
                { "br", "afe203cea3511708b816d163de739b94741d09ab0fbe6ba7bbf84f8d16b5a0822b2bc0735e31458986f1dafa9f9836b470024a840a65e3543d5b6956a1a29c8d" },
                { "bs", "33e507f69f519026b59276f14f4caeecb20adf1605fdab3b5c90265f10cd83f2c24a7c63e130241cfcd9cb6466d8d4e73a584a507476c539c3d2759a2bc750a4" },
                { "ca", "bba08b64cceb412f11646f16942e3c2710b8e6fd0542c1165d02499549ef71faf6921c05df7600bc00ee2b43df3123431907b8c2cf9027ae31792bcc5a6ceec5" },
                { "cak", "841483d4aeed5017e8e51ad5d2b6118ce49bda468e75c1ec516af98a9e1f055b5cb684e8618d490fb975af9dec23d0ab4bc20fff0a2add30d043b1de6df4600f" },
                { "cs", "7575e0c9f4a785bac5d7992608ee1100114fc3373f173b05e983b0947e2a6a73379b8758164841ffeb4ad02333fbe1df2464c83f9ad8a651bce644655c95c9ab" },
                { "cy", "ceebf1cf18e666697ab489cfd1a89cbdb114c119772ff3b9696e8c007b07808400dd4584870cfb3295c100bb959ae662d3976810bd1846e4505ed9f869265bd4" },
                { "da", "aa97ef047d099b87d1d8fe1b82de22f14ecea3a5b13cdab2096eb82906679d67dd5d0a2869b515423a4793fc190d736da8523c8750fea79f9fe0da40d9276815" },
                { "de", "e3bf86c654814f802159d318944704bbad5d6a7e8e0533dc17d33fea00031d3bdc9fa2c4368e8894aaf768c380ca22855c9d97b20fe5ac5ef3a65953fc0ee546" },
                { "dsb", "5d3c862370ce2d0091ac9c0864076206a5b25a72a868629e12a64e37981191a1f4233e6d0b92875b49f16c676eacdfdc6ba7ead276bce989c064e4d1c3ac9cc8" },
                { "el", "2e0c827981453fc3807af95eb5a71696c234b6acec47574092c2f8359ca53c13e0cd8a5a3b07363c0ab87633c4f1bbb035180c3f9941a91fe67763eacb212e4d" },
                { "en-CA", "c8d8d661d6424d7f63c1e54b6a11c41d6a6285ea6a5a39919ed365cb93bd4fef723790834e8cdfc0d535b99164be62622efd586063ac51b443e94f868b13dd16" },
                { "en-GB", "2ed069e64a992521a2ae17d69d1ee84da2e538c119377fe3c4f4d8c45c05c9f9b3d66f07b63fc73229524ce433e7faee9e27bba12439c4319270061a94b63738" },
                { "en-US", "2b45e8657c25eaf565abf3f3496545ee18d0f3597ba1dae45019d4d2c7a83bf0f087c613ac6eafa51e70c11786896e53a4359f479c35538d66675ce4995dce72" },
                { "eo", "137fa07f7f847af9dcf13f1f282bc7c80297f9a9f636b933222f5a53172ec77a788de2069a746bfbe5af4ee5a03d84b5daee649590ab044e94ff4194bb841441" },
                { "es-AR", "300e4cc5459483035c50b8007c7717e8d48ff7209c42183b53e48ba34aeb52d465db8dd1693e7f01a86dfc273d5576361ed6493c2725a290ede020e9112954e9" },
                { "es-CL", "dc4f894ed3ef237e52b299ea54e5dfe85d3cbcc60eae71d11f442a5a86aeed945bb04ba10a87d0332acbc2587a727b284f81f79405f7eb28d68bfee09e105358" },
                { "es-ES", "ddc73bbcb8a7cdef86f1d8c4496110ca8848e797f6ad301a0616cd69de2da1ce13fd53533f095dcb4145dbbfbff78b7b7c3f1dca07877337aa949bc34358f04c" },
                { "es-MX", "4c862896fefcedecfaa2e4f2e0278b885b36e8e364c8e09e5bbb0b58fc3e520836fc932ad9b69e29355fa06f256de9ee8519f3c96491ff822f2679594117cc2d" },
                { "et", "c250a02893647fdedc25a22decd2b8d71d4611b79875cf01184ac512f610a71f424ffda5c9e4d116723529c76bd070834164ce3cc9b13c5d2d5fd3853f20e448" },
                { "eu", "760915e4bf832723a696ca671ca901e489ac4af58e008c31bc19c62b84ce7a487d2029c952bce608434271b56dd944cf37b28578b205f36a98cac6da0a9dc5b5" },
                { "fa", "ccf27374124838ce5f6b7be2d2d8a64b3d9dcd92342415aaf837ab81df19859fe9ebc4d33a122a821b3cd9fe7cb9ca68f763f928e80af93f69688b3c0203b191" },
                { "ff", "9f49d170a07b415838c324f4a1f5b61c7ece72cf2dcebbf209a88c39fa2837338f619109cf541cb680374233b676bb9240fd6aae4187a1995239b7c640c689ba" },
                { "fi", "f6195b156accab8f96b81de20326cb4d2c8a19f57f4851c9f7e6c06674ca89759996b3bc043313c85b93b1788bc6239b4b69e0a39cd1eed504375d812dcb5a2b" },
                { "fr", "1a10a13467252aa35cb764c1d3464e0d619bb33caf75150880da72222a6fda30674fce432d4ec52313547809d276bc3792a7327896f5909b21e8317bdf2df280" },
                { "fur", "536fd3f1ddbff11062148788dc036dbf55d61f6b2d74b62f869260bf344177447631af491c4ec807899362d22e09f39ca1b4c61fbeb3d21c891cb8951e8229c1" },
                { "fy-NL", "2431557d920a561734d3054e54fca9a3ea38f62153f5b4215c887bc0b02faf1ad0180c10a079daebe4485d6f7cc137a46bddd0054af29d6b8be8feac4306053e" },
                { "ga-IE", "cfb23a962101ca2737a0c4fc9ce5bb5d92e397a34082a054f423a14712d2e389d3b4149638c004ebf1258265bb94ad45d89e2ea15042c5e8b48132f802aa14dc" },
                { "gd", "f7db3b018be584ce7be1b0f52109de70d55aa7c0a618317c6d7d5f5f1d3b527e40f47266957db3c347e860bc35c05ae33f309831a62f2a5403a5045c379dace2" },
                { "gl", "4ac0cb4b337aa72690daf58221b431fc136b2698ce661dabc9e054b33c6b09acbab50d54a552aaf447fb0d69d96cbf1068a90021491ae5a3ad5d0cb11d4a21a6" },
                { "gn", "d0cb232f1a1213dc2b483d9107f000ac6ffd3fa02ba471f196f827328b005e0754b70cbca4568af9832c07199ce7e7472b77c3e5738f9cb953e8630ca5c87205" },
                { "gu-IN", "6397f050ce2dd81d9b6f5fff40d34f0d6e58ebcbd38deb568f5c781145dfc90f488a19bf365c90cb9bcd951614c89a0685e2b41c3709210e0ec6ac5153beefc5" },
                { "he", "e26fbbd4d95aed26fa2988877c3d00372cac359821544992a1c95d8f9db0f007f6c1340c49c553b2bd540f5a9a72018ed8b4db4988c60fb93c4390a02cd18880" },
                { "hi-IN", "075d1f6a1bb4af3d996bc847375ab0afaba52e62aeeb7c34d5b64d833760afc68f10ed76b96bef8a3a915964b2a604ec1bce1940fbce59378c1cbc2ff1236080" },
                { "hr", "1bf97dabf6fba72824b80f326e271f3af72682af16a5e385f70e14b152cf094266009e49944553c71edde0a825426099eb8caa631b9cbb3923eab50bccba10bc" },
                { "hsb", "39c9961b2e1f55490cd703fb02919abed93d41ac99df97c3e0bc5fc18146997a52ae09727cd88201c818ee85cf8d58cf30b4fd6f044c3318fcc7899cc59dbe6c" },
                { "hu", "089e1f2a2cb27188501e7b98fccdffb03a6c25a0897ff4682c742077c57d9c3373200e5f99539a7915d63bcaaf191738b2a5b9aac0dfd81ed05237e33c5e9fd2" },
                { "hy-AM", "b736f088431614030578c5307f1a4d1222daa0be29df42766beab636fd85c6be66eea67c12a9af8e019da3c92f98f5686bc32a72ead5af2658c0489d915b7732" },
                { "ia", "1c7162654c4adc80a9bd50fd743e1b0a16e89cd8edeb4645fed9c941ec05f534e66cba8a4bf5dbf31732f49bcf798ac4bbc4702c18987ae14e031e75a5599a85" },
                { "id", "3d01fcd38633770a8607756fef8fbc846c044b1d3a9fc2fb585b94464fb997e8490b0c2c0fcbb27214c3a95674314e007e29740ce453486a03d56e89f95c0230" },
                { "is", "83672d7a457eb8d52b4fe152e26d49e17a9e519c1f934453284cbe686152e432f116a5e0865b08cfba19c202dd09a65ceb8e9a527a0f9617f2e2f7635819c634" },
                { "it", "046eda0456146391808c73d7c08e489f790ec662c74a7f87d7b616d876ad0a2be967f8151d62430eafe0ac9043e188ee24ada97bd30f3cb4c4bf4d621f308853" },
                { "ja", "86e5b27e1d38d3fa27343f69a6441d39978b0d6f7be0d456b53e617323dd0c5cee74d6b274b24db67b0c897d1ad317e655c072f011435206cfa7cb15ec5e5767" },
                { "ka", "c358c17899d5e2ecbf985abce2c1e22f2e2a64d127e823b81d86ce4e152385e6877ab4e32a1eb5a09d561ffea4a6ee2d145fab977e0ec48f553ccad06cc92928" },
                { "kab", "ea76fcacb98138c6be11397b4141d85c4a4554b28e19659fae6c12e289f655cd2b4c07623b050e19479683cdaabe0a53b59b5da5d58644bb4a4507ca35dadda3" },
                { "kk", "d7c3ec5a818d4f2a209c1ab8f742fbd40daa1fc4298ee8af5afb34aba5ca4f5be0f188633c9df62aef2f24768c98e40cd7e3bfcb5c6f1ace8dcaffa46c0723fe" },
                { "km", "810b1d28c771ddac1d383e4bcd1be262ca438f1c8c371e235179d4dc31740eda32fec88a7caffe84cf16b00f59d33a5dbfab9c465374581bcafe9d57e8aacdd7" },
                { "kn", "d3cbf8da2e64a292b4499a268d8a18dd44cc76a0b56a95282692ec3c409c97e2f0a8cccb58323a28e5b33946d97e2687fa667d2063a836dff80a7d05354513da" },
                { "ko", "acbc47a9c9998d99cc3d53d615d77b0d983f073a65f82d64b37538fde74d1148f4aa049fd2afc033058079b8741cdd0b68ab051e304d5bfaa2f9ee5be4c559dc" },
                { "lij", "686cbd93881e67a1fe139fe9519a62b73a340b6b71caa83e29f728056e50ce19d7f6b4f14f12054e73ae7fb90f4f6ad85f21431c0401443e041553203577a14f" },
                { "lt", "4fb3b23b1efb4bd093c52fb1ece4bf8a27e8993a6afeb41433bd2f68f739dab6a7951a8703cdabab06f9f3bfdcfc6efad3d69a29740e14aae142ea6d0acc2623" },
                { "lv", "edf2964cf85633e102199d532acbb9fa1cdeb9ff70212349b217718d6f08ab46c80431a28df92f8dc15a33692be82b98040ea26e9d58ffac34f1ad8011352971" },
                { "mk", "1f63a1358d1289eec9f58285b987d4cbd02453fcdba60ccb2a70ae78b6fe4ba4209d52ba851862c12214e4d5a10aa654cc041403b78753f1395e6949ff84d3f5" },
                { "mr", "887d81de77750fb5055879532208e270f2cb66758e9ecd2366965f04c104a5dee388587c7df3795f34da98f50c90d5797a98552e847d1f6622b24df5ff497801" },
                { "ms", "923833deb65f4c734096a26bc150c0df2aab80a462db8034a06ad226dba9d6e2f3ac9fe2083685ace3867f7d9f580c4a0515b6864dfc82897567533734019421" },
                { "my", "d2a2aa879f32426986566d2e09414768a3762ab915e2d0192e51c51d09ed08a7e456b377e2d80c1f5142df2617a537797618a2cfea2926d2f8edec72a3e2afde" },
                { "nb-NO", "e348d7737a0482f8e42f6188e828c5640cc55bea44336d10a94b3c049b1870f48d24561c63914d0dae98359fd61eae01a90095ba4eb7478fe18076cc41633400" },
                { "ne-NP", "88ccf656ed586359acf060a4a6435dc0e0a1e18c6a939888ad2940cc9cb788eb12dca8f0d3f310ecc449040adc8e89fcc46e94ead824882ca2e46a3d7c68a03f" },
                { "nl", "d2fb748e9aac49092ebde4a5c77cb6259aef8f4f23b5ae136fe4032fd5574355b88419e6db3d147c81baf6483c5f44eb887146bba4e36449059e5f3898a31a1b" },
                { "nn-NO", "587ca2aec7314b29a7b9aa527a45fc51ed1ff4633d85e919e5f0e1818621ebbcc3195e90536b9b291400d673fc5459225a75400b282992c5bf2b8562e0153a40" },
                { "oc", "837f0959b3b39827960bd889fff08c626446ec66201af957390c166b9a5466129381d43efe40578fdc362c513a9ee5c4c29dc5484396a6aedc74fa77d117201f" },
                { "pa-IN", "4bf7df1df6d5574cacc49c0b67a86520becb8b76bb5f50156b98a52036379a191bf0e1fd6946d7ffbe425b91d168c972c1292c88def1f040047aed9c2e334493" },
                { "pl", "5a5c31c0f2571926cadd69d5b4153e94c57b31b44b59144c0bf51d002c383dd6d9dec78dff0fb32d76adadc6b639955f26a4c54dfd1d2a1b5553301db80042d6" },
                { "pt-BR", "e4170d20f1230518ab734cd4f5d032c0ad61fe9c7fcc206f49b499740016475858cc8277f6b58b014600adb9e577fbcca0b305d78bb0f4c4c6127f35dddd77bb" },
                { "pt-PT", "20b9a0a69a01db68107da56fcdef1e3f36dc512455623436ff32d38541fd3c7e87ace21017bca83767e90d21a51ddd19556ae29d3f5a6894dbcc3237054c90f8" },
                { "rm", "602dde17f2c4ae1c1f281b8dc1ac42b2f7f619de227cd199939c1c64acd8e9aea92d6a65eb3bd2c2a26ab8253d9021188dad997c1cf3fe08b7d6795eda9742c9" },
                { "ro", "a4c2fd72ec66dcf36dd41e66f3af8162aa25a27708cdd095e848b9641da38083c5647a7740fc8439c38e2f8f7cbb04af8dc8de5cb00db2601f2efde6f3f6a83a" },
                { "ru", "92b6a7c7cb7d5063f2c951f40e09df54d35d3e5cab2fe0ab373587d93f8b2c0ae8a40502275df713bdd6c988b8d5213eaa172bb5b2fa17ebce1ea18b6e863238" },
                { "sat", "ee090aa3df118ff78bac3627331da4cb268c2ad1fba1d79a4cdd27bca7f5142b9fae536ddc685d34066ec08497a3afdefb0751346c0dbcdc4fbc028b5fd4a0f7" },
                { "sc", "4caf2a28f7ef44b9c1fe820edca8e29b0b598f315b2be4aeea960e2c81f844dcc4a5f4e186d9108b80ad7f5ab76b65994816afe3a780b9fb3b139715664dc28e" },
                { "sco", "b4340c1ba4af67de3ef11e0a752f8e8cc7a57da72bc5a5609669f11ab047a34b78069e3dc10988a0b1e7c465eb3f2c51af7486b26ce703ace113a7033a6696c0" },
                { "si", "1a793a1824f5fc72faa4a62f8adc4ff55d6b2cde2fbcd8314eb568ff5a71b7177af2ff5d5016c7a1e4ee84b61a51a310c410f5da4895ce0cd54c342fd02a6345" },
                { "sk", "5ef3242536040afa83dcf96c11afe0cb81c03965da41c2adbf1a2dca205f39cd31e7f6ead825f743ab76a7ef54de81a6effccaada9c036106dd49c9dc90c6179" },
                { "skr", "4b403e18ab3e8281f653047e62716b527efd0a790869e6a40d8819b6b7fdf985dfe37de3f32ed416ef56557d8bb7e000c3b038f471272e7fe600de3a1f5d53bd" },
                { "sl", "89970ec630e628a3ba106da972b299d405bf4974c1088b99ea9a02193abdda5fe33f1082d5e091a261299a4e913717287a89babb26711c76bf53d71c1ea8be8f" },
                { "son", "a0da31c2fe9b4bdf5decdbb02e4f315145d65f0b23bf1970f4a77332402afe8dd35fe864379cc40f9432bd348162b674aaaf404f295bbef2ed07ef7cbb6cd6da" },
                { "sq", "6cb4643ea93b9dfe96615238aad44e08516ae004befad8d32d1dc8d120e8b61b82d754993e2e381031d57575e46bcf456b8f4dd415fb3fd48497dddd3827cecf" },
                { "sr", "712c4c743f2af57f291fe841bdb6582a141678ef37cc29f92979bb11cec74ba2d87bd05bb058ea330febd2312cec2d92beab4acfd03e3de8cc165708439cd478" },
                { "sv-SE", "a734da733d8a3f43b9093d6562002a3945931e44bba93ea528fe9e5f139df89371e38b9d680de41a84a83d4317a20b34821c108d016256aa487f97e1620bc7ed" },
                { "szl", "858b82cf4cd100c83e406cc90cb327a1a5d45fb5a9077f6ce9c7c10ee56c945c0b2625ce58714e1a37c717bb4c5a9aca294e8fd8051db488b140444b09cf3ff0" },
                { "ta", "69538a3ecd77cb9e1be9435fd70c8b3679cd6d980ef3f2b63731b2cbf5eb81ce001be7e54d2aceb9e4e79a69cb6c98c7b0f11c1daac4017b49ad87fcda995269" },
                { "te", "b7ced1de4df5db3e8ae15d4f247c9491f540b49453d11c7554a94061da25fa69a2243523e510c94571d22909243fb933fcd20cff0f0bd73c6664955d16ac4de0" },
                { "tg", "d345c180c42ba31eb4ac6b5b2f44895dbe8ed1018945c33dfa3be5cd1d7bb63923c5a397b7a921cd97035a440610a1901477afa5cc49521f04141f4129395d44" },
                { "th", "3891a18d0034ca945007dbbc950f376e52004d11f7a411570fce3bf75e44da1d15ee24603ed890f4bbb874f71c016c8f4232a01823e41c330d861e9e0a1cde36" },
                { "tl", "7ec51beb4b53c0e9ccf4f459bb708affad56d4cd87e1ae84976135f4f9ef0f411dce1adbf4cf6b7705ce7191abb879ec6b726e16a838ce8afd45bbee21c72dfb" },
                { "tr", "64d32e450d79901abb56bf4570f514c34e6eb36bd1d26c3bfafa01b43d67cc71187fc713c2d7568010b3fcae4f54483cc7f026e47b851db3ba6554e0b1908818" },
                { "trs", "a2b63dd6981efd1b04488171efd1cbd09da80322cf7852f73108a71afafb60fc100f19b2270ea660bd6e54e4da1cebe4e5cad674535bd5ee407cedbadc6583fe" },
                { "uk", "70ab409ffa624e027f44177e31c2f0d14e13174a99a5c1068fb4d8fb2b74af448d7fa0bcd4a220e05041320c45d27ae7ded594fcacefe1b6cdc80955fa5d2faf" },
                { "ur", "aaada1d1ded78de5906130c4b4a66f25b56b1b2c8f8dcfebcbbf087687b3972d967e81a131aeaaa6e50645e0ad8b32b831abcda33dedc25ab2d4f2afce60462b" },
                { "uz", "5ba4565d6d9e23d2fca1abd04e4a9719b74bc01b0fed55f96ba92d206bd9e0ad069ad6e32928a6adf4cb4ae9725df8370f167254bae12794d1bd3249e961afca" },
                { "vi", "1b51d2ac49b847fc53486315a6d3d898a6629757377a63774bf8c732aaea958d2e0a5ab366ff3bf1f2a197aba1e6ad4a230818ab6009811ce4ec61a7dd7887a9" },
                { "xh", "1c11acc87d49ff0c71d89ff920c78a39863e1ef532107f9024f31a9298b624fbfbb15002109492e9533b05c42ea79a664fd8f92b99f85a12f2695da6c5b3acaf" },
                { "zh-CN", "9acaf87da31b5f20a634acc9b76ec7da03f480dcc33226fca1a26de05342bffca6f7a6918ab106bbdd6e7041eac9f81d7d51fec0dfff764dc5f90c2342e11626" },
                { "zh-TW", "9f2e7ab60ebb9114a4e30c6b563f7e60d9b0e5a422ce85405ea7e83b8c966161df313a73a02d298e0bbbc297d3f8a15af9367ed62a37fe0656b310bd0c73fc63" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.7.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "33b6e031663a3610a1349dec2ed18e282e63f99fb0bf0bb3fd6017c1accb3201011ede2d7e22398a88fa0e9fa6f14b2e9e23036a7af1d846113bc3cd722762c7" },
                { "af", "3ea4ce5d9f1fdf2fb5b3175fd16a143f621b33c32a527b4a8be7e1bcd38c08c5b2d8d6b8b65631e8655c999d7aff4271d12f27dd49fdaf64486e4cff26f3e23d" },
                { "an", "f866532c36b5f5251fb197143b71fb4f562a12cb2df6a49fa9b5db93d676cb088d3a7ce76a04a416446e84788ce0ef89b95c9b59f6f077aa16465eb9997832a3" },
                { "ar", "eac6bde53301e422c44163593c0e71a8d5c5a0f97bab30148a53cdacbc96fbb24f8fcc8690f8ff4364f7c326e50389f5080b20e5b3ecc27efd32fcabf797976c" },
                { "ast", "33381f1d981b627acd83aaa7b01c32d2dd2e8e655f4d023d77b8f9a42fd56d787f46125beb35163c31fae929522c5ad5f85b9a2701cd9e91d1aff4c492f185a6" },
                { "az", "a0d0e6cce6f3b31cf5fe6c1f9ef1c23968d5b98daa0efed7e875e027a297b108a00ae9e2dc5282c1e25d29dce2036f2e843a857f199ee409bba5ac36907b7aa1" },
                { "be", "5209c9d238a9458634bc1450758788fc0ded8dffc921a145bb48dd66286f907c626b4ac370acbbf9d02753bf05e288a5ad0fa5e1ee80d3899ad4c6750afa69c2" },
                { "bg", "37769f74c915b67fe5c1c1129e0e6f0e206d6a9745e0d3b27fe5b6623566b251ac51f8e43db531bd63903961645ca22bfa1856cda8f433fc4175a16c333ae2dc" },
                { "bn", "53685326f826da6b7f34c7ed1661fcdf57cb0b2083a3e99f4584ea962cca3ca615e0d8278c386855b47e3723d5bd1eed1d0fd4495febbb3909012fda4f692982" },
                { "br", "ab66fd0471abd91f4c064df22fddcd2b13cd74b451d5db9c0e43e957823213fa621f649dcbcead0735b197ce1c46254bb7080c37453dd139d03efb774b07368c" },
                { "bs", "3de0586f766d1457f225bc08c53d90df0d26951abf815fb50bc9feba0f42ef05d16eed61693116b1aceefbb45c9c8e4fa01119d1039a196550f687ce2ebfbfdf" },
                { "ca", "8c01cd49fed491f48369ffea08fdab749fd0c1dc681e4e62c4078ebfc3d1d67ade77c0af5bf2c0d5457b7ecfeb3c30f4924005f3f8497ae952f9c089024fb453" },
                { "cak", "7d5cf267f3a4fdf4900e7fec91034f2cc9e5bbdb2859e8cf30ae51705518ce920d00cb5e12a9683427b13fae86ad0d5319385aa23d679cca0cfb020c529ddc2a" },
                { "cs", "d47f97b71e294e945c4c5b33bc06274b4cba1f5d0bc3ce7c0f69ab9d0e2b5f9950e42c5cc4906f89f7c4203ad15527c74eb1b49cb3b757ab5a2c442e08abc5a6" },
                { "cy", "586728c4846b9ec85c859870c2f2f575f446026dedc8becfeeda6cd049edd3ba136cffb47c6f0605d82df7dbc1d15e853e69bd77db3debf77299a930892fe34b" },
                { "da", "d37eb22805ab6e26d1ca17b4aad01a961e3fcc08daf6a9ed7efe6ca361fa9a385449b3fa0f3f96790fdf70b4fba4b242ac154df90fdf9b7d6b557c1fa056e543" },
                { "de", "2f52f126473c1a20bee07f3ac7ddd4b36c44d065c713aa718be435010efb68e69c2ae45df2dc1e24cb45b3c2c4a581e037491a0dc58fcf7c5022aa56b1bfc156" },
                { "dsb", "456bfb312984a6c5ca64f35aa6e091a4f52135ca65377ecefbdbfd13d903834758ffa4ffe189807a441902d714455059cf0b110c4d8cbfc68d4dc90b91560006" },
                { "el", "4a0e6a05c75a1b54a25cbd1c4e38f8b8e6dacd72ff70c689165748904acff27f1d1e28cfcbc7f4e20bc5ba6d06c435f2b995e49bc9634d380617cfc645be7c90" },
                { "en-CA", "576122dba62c852363f2c1e3868152774092a91605549b44da5e19ca3bdac6d0f8e9017c74e07cb5ea55297bca13a4ce71ae2f0043c4934d474c2c3615a5ddd4" },
                { "en-GB", "ea9d56613542cce8b47da175880ece3552fe652104a88367eb4ed2c5bdff7580888bd22afbb889f55e24e513ee1dd6146a8ab8238bc6b2c990fb28d105aba0fd" },
                { "en-US", "42198bee8d43b1e4c2bde6620fe18bbe31af92c9f863aa1340ccdd9b93d9e7ef18e15e4a81cbfe85f3439ac7199ecc5e03cca476f28396ffdd14810811bb4967" },
                { "eo", "2f5a2414497388a53305d476754ee5e681abd8ddc73ff13a5e8d8de0d1f965ef269b8dfa573193fe2c74a75aff5e8bfd88f5b0808069ab5826980d8271d3d852" },
                { "es-AR", "97d853e99b5f0be7d4f93d30184219dc1c967126dd8c3084bf1ae568100a193565146cf4eaf104ddbef069ca86fe64cb08fb9939200b23cd30e0f31d13b59bf3" },
                { "es-CL", "6ea7b3a93ad194449f27ed7bcbb242c143e658e71a47983dc0be093613e585b6cea128d4f320dd516e954ef09c8795e0a2feac84bb2e57bd6e14a975a096c13e" },
                { "es-ES", "7a1b34ad7fb9ee58ec97b891138263ae79c14eba1a558d610ac060e1c59f963bf594cdeffa9e9d8638bbe5ee4e1a4591e8c4dbbcea75099badf2470ee64dd0e3" },
                { "es-MX", "440d6f8295cddc57b7bc8fc2c805281942fed405844c63f21e92122b91b13fa7c591fb67b5c7f7bdc88865ec7bd755daac37937920a642249e3fced352adb579" },
                { "et", "e1a09f00830b6c30257e8c74b75c4c1123bf1b3b3e98eb09b34a40d7edb986cba4792aa778230bff6afcec5f6c12b820ff24f9718df6fd524356bb4509b305b8" },
                { "eu", "435b7bf8ea1a36ef04229f7ddbf41fd572eb35131a5835c46f2209cb53c7714b27f6a92ac88bf60f4a9e2ef8fe8e8cda061ead9fa84cf74b41f43331f0662a59" },
                { "fa", "e248920ebb510ba7cfcfb951976f02ae4d88fff5d326b015812c27e84001698b212d52a4573f766fb6481f7bffbbf0a8ec2f795fb3a2419592446c9ea9776b71" },
                { "ff", "0a33ac42f8dc6a980ad33c3aa6a805f62bd9a5ee8bd91c5286518bd22367bad443e58d08637a58557bc65da4b2d9a0ef45bfa7c020a5e7aac6cac6ab22e3d300" },
                { "fi", "598446dc42a9c63a127bc4972cc326feb6c7dbadee8efde4a3e5da216f349e6a739d6591f41013168ddc17b8fe61c11327dfb9d8a1974ce6c3668def264fa62e" },
                { "fr", "3f4120a1aacb64209d5b5917ef14a32e8a13133c61fceecb669f818b38d0dc31bf26b8bfe5d98f66d1bb42ecb02f0f325087a30a2f62b53fbf13ffb9f70cc074" },
                { "fur", "eb12237cdad69a7a64f04df37f92a1d97425ec9b0c7b6c5a16b8474e73d4f2879f75f9946d77187eae94a1a07ad1b911e1254baf3c565f17a8f2ab108a0cf4c5" },
                { "fy-NL", "75be2e63b612d81c8be93ae11c82753cc71092abf3b568be40ff87da3ca1fa31fb20c841edef111f5ea49923e1e0da1880e82df73a9b5c9ac570b5b88fbd2e8f" },
                { "ga-IE", "7c0182fcd3c02dbe102b746a2c8a3dfa9a0851d4352016c73fc690e0bd2bac8012d37deea5aca0d5d22689a8971c813791bb1628d2a9349e7168fd7e71fe353b" },
                { "gd", "37c5156e7a762e977b421f40d458c820df27fca34462211dfddb952706baf9214a32a9ba4bfe3db065175392c400d95c52d559b19927d802739c6c06c57db883" },
                { "gl", "6d88db50b2eca5c5c0f940ccb9ae46c28738bf4598a14bc6152b46c09b30922242133592e0e81806cd1e1a039d4e86ccb31ee1b9cf62796149307298e37af1cd" },
                { "gn", "fdf0e751c08b2e4c94b27b0510973b76056a44d1244de48ff9fff6356ed525d9504829a3a2426ab4d671bb7f171c8dceb27107825d01365f5d6990fe622fbfe6" },
                { "gu-IN", "bbe5bc49f40770e2dedd56633206ae4d3b317872c9c35ea9d69d7e2ee4418cf40b9ba7e43bd40797b28a86bc899ce8d76c822839f3bb82c6f0bcf7bc18e4da47" },
                { "he", "37355d76c8120859426d43907ef59528e35dfe9a63791a25a8715d868090b29b6d811beafc76ac73d38c4758ed71168ad71af95f0962a1126010a29a5b6c442c" },
                { "hi-IN", "6572bb467eb9d1c062e5e90f1e0a893034119b4d496053ccbb1b6f082fc28661dd1cf86b24855279c0382d511543a9b1539d56e87c5b1b2e2e857832ffb5c41d" },
                { "hr", "65234f2bc8fe410841430b9791485d1ecc24b1ac9834e80ee5001c2f21ab14e627a5aac140f639dd2bca3760f6c2f7422927ed3fd8e049b6c0e7f21434d4bae1" },
                { "hsb", "f7abdcefd01ec503504e47beb2e13db9c3fd6e9ed692281e7fd5f18729394a27b4f15ad1ed14910cba957538893f872da81587e711e1f553fa5e61ae03d60b3b" },
                { "hu", "893e209c5cee527083d5170858d02fc2cb0e4dd70364360677043d0c969304aa362b79b9ee17da100a881541837eab48bb627adba63434842737edd42099b8ab" },
                { "hy-AM", "72036844dd0ce6447fc0958ebe351f3e123ecc8eed42ecc2898964c96c89e6fb89101a959df47c184096cd7749de07f012881970a8597812abc1d4ff625dbb0f" },
                { "ia", "84d0e5d6db6aa95e7465ff06ff5276ffd59c1ce8220e03f4670ebced8f15fb1223a7c27f54d026639cb5ad535c2f8914bca8499ef0e5856f0c09c8cb66570a1c" },
                { "id", "ea88c45689b54fc71ce2b66cf2f248a5beb4fc081aba884b4b42aacbbfc60903481957bb840a128ad0b99103e1da2f0e90f62bb8244887bab79b2c338e95966c" },
                { "is", "f73f82a79e5845705c081d40e7e3bb034dd2e322f1792704ada97f75ca37aeba85426c87ea4e838567b04af99046fa5ea608657554c2526b015cbd7ea60a3e5d" },
                { "it", "0cf586746c36b24f4affe57d04e38e80298129eafbb974f82bb798780f18810c23f91e7bacfef8c0d568e2324f26a9889ae371145a4c60090f065aa824813765" },
                { "ja", "5889ce32987865668151e6393a42a894242d426075174fb9ea3432073df4322f56ccedd5f64af9b8d5f2acb501bd3a443ef58f74dfd1b7a7daf90d7b60e4a4ba" },
                { "ka", "210b57f26084dc1121dffc8a8e750b1be1d6e106543a88af598def07dba8304ecd72f28f74b2d0419a13b44bb24e6aa404bef676d5fa87a284fd08f3d78d5f76" },
                { "kab", "6bd6ab0e781eb1212b900f14a2691a853bcba40e78417bdaed1dbae62e530b2015a64771691f251e49cd8690e4173e84f245ceb7c64871ee7483b0e5492ff6f6" },
                { "kk", "03d968f5424248268bbac321d5cd3ef4d0bfd3419cee5b28f8f406e845c403e5600bd2debce125bba144accd61f840c7944ed886998e9fe9f702aaec1663283e" },
                { "km", "f9656ee34266527e1012b1c6e6279fbeda28e8a31700ddd060ed158f7e5a5c2b2b6705698551678171164f3ba3cacd5c76a4ef55e54e566173e7dc87a4506f8d" },
                { "kn", "0515f968b6bcc190cbd3fa78e1de0f8d5d44ebcb9a849ed4a1d704ae7275a59a761dc2f4caf1862771ae950091a1b0fd99e0ad58a4dc9b298d3ed0bbecf3b67f" },
                { "ko", "888e6b5ca8f89f242fb4a1e3e5a6de0094961db4c0da1cc80709de4708c8844afb1d760d6b22d158ace481d3c7a0ca3af3e6a6c33d51ad2df54fa04dacc46730" },
                { "lij", "e238ae37b778535b76a428175cfc038090ef83bdf6a7d93e788ddaaed1907c137c310ed92c5a87cb8eda6eeee5116aad36b7d05bdeb3b3f85275c39c46cc273f" },
                { "lt", "2789a68505823ae577fe59641c8eb724516413d9285e2678d6aa76d64cc6677fb3beed711bebcf796183dbe8f4a76c7ee75d3636e04f44cc5474120adea0f563" },
                { "lv", "9179fa9e03d179e1c12341aa98dff9d4d3016cdbf1f5b0c04c1f7b49966a978865a83015e809e331da039c3067c8493d5878840c8d8782766905de615e6a512e" },
                { "mk", "6d36ee4801102dcc46e339cbb0784c414339867d3f864b109b116fb9f278c81bb8135a561d843119f97549a824cbb585aac1eaac06fd0056440b57377a45d683" },
                { "mr", "b46eaa05be0fdac81ce78d63b27f8827e81764d06111e47b200037f129bec178ae4c98811e12e7393eb1a1c211520c3cf3a9b94404e702e5ff954bb288f6e7e1" },
                { "ms", "8d5607c8034a0ba910e87bbe4bb502fc58479b312d634966b883c2d2e28eb982998198368c1efe8c83d4e3a469935b4923dfc78dfed9faad565b84e9e6f0c491" },
                { "my", "36dabe18d3b2b3d0faa2a7c4a74fb4d1b50b2c6f984d1d9e154c9ba5888db16546cbde54e8a342b99dda5b59a8df0a23d2a555a296c72f5572a38aca312515c0" },
                { "nb-NO", "f51e9a5c004abcfe0f2d00c8b77c80f7b7ea5bd3957babf7c288c2ff3e6c82f044395efdb9efa29a607156747f7b169020f66258f2c95015a976dc04a76e5998" },
                { "ne-NP", "107dcdd55244508d5ffd2cdc0a603cddef65cba030e72cc21a7b4dec63728ce028e43ac3be96dd14554362b909604b71880d7aa8703852b88a6b6c1cb55732ba" },
                { "nl", "1d4f4a8ecf47bab5dfb772e6368e57ef1866dc94b152439e6edaf8c329803c7e55e379ba2b65bda9c606680ef2e9fb075cf9ba51ccee62dfb592823c06dd94c8" },
                { "nn-NO", "ce06808f467ef139f7195f43ce04d21de6b14d052d315cd1b148f47d03a1c0cff255d3ed083f7388598e477556e2c42b6ef55ace2a80ea088226612d4d9f17d2" },
                { "oc", "9d5617484170336bc65e2246fcd2eebadb97c4f7aeb92d25334a11d3744131962d4fd7b9c070753cb20ef26490e22e2ad7cbc757ff6717fdbf98a8bbbce459b3" },
                { "pa-IN", "dac8b2873b7ac72108a146ebab60f5fd2b020af514d7bf8161a8728522e421802228e949a34963102e2ec14a22b4457928a52f69db88f57b0dfb2d5bfb9e7e32" },
                { "pl", "6cfb5b61ea70621fcf01543be6450e9c313831a6cfce0fdb4e5b708e90a6a4e352c65a89f21c13b0ba884de39f514d1b15e1fd741e90a8b36d4df2f295acea2f" },
                { "pt-BR", "f5c749f83dfd20c7e4b3cd74fb60431299a7b3c8efc5ed51c618d66b1574b73b6348b4cb745a4a31f3ab4f2d8f15460d2f612d7478c3b2aee7ff3c4fd4bb83e6" },
                { "pt-PT", "0d6dfc875015a114cf2a0e037459afd36855122436d16ccb8ed3900dc6c5028a7da67afb79337f1d477183214b13654c5f80983d0dbd1a36e61a312873470346" },
                { "rm", "f6d5131e1e38646fad61c9d95d4f4fec46a17c672d5c70ea0bac9243870327e7d107204f8cf33834e0cfa27b3f5de4c3da7907a7719c485781bc11b73916a5b3" },
                { "ro", "d4d97038c9970f7302e893850c16627f0f92a2d42b6c37857e2a291badc1371295161c498ce4ad5c7bf63c4eb97537a0d2e2070f03e5f080fb02c6198d7d7bc5" },
                { "ru", "f9c52e14f078b1f1f24e70e88454c7e20aa8e6cc26b03f53941645db708da13bbd4064373827a26f1641018dbc75d6fce636a1a90bcb7d30939b300aeab5eebb" },
                { "sat", "8bf84364a5fecc7fdb936d2f8ccf3486a398edf086a64289102eb34181127e21ba68fca3e22ab1c3efd392f75a9c08dd1ca920fc722c68fd09dbfd6332687f4e" },
                { "sc", "42f3d9bc27cedf8130108f52abd518db8656dae1bcb82629358d4afdff9b7fc60481a63a902ec40de6408c5b901b1672976d16001d3fd0f27a052be749d871dd" },
                { "sco", "2d25e38b60989bd18b45afb3e96e3f8e25642088662e083b2dadeef0b52a478b01aac88af61f7097b6164e13f990a24ccb559f89e869b993a5e955fc5a2376a9" },
                { "si", "7b2e178a715b14506bd89841c41685e725160688591694ec6c6a390b996a78bd18dcfb75b9bfa05abe9f16a682b4a45d6c59c12273b70b1b39fa728e02c857af" },
                { "sk", "f73eee22cc4f9fe245bc47c643c86eca29230dd6e712e8465483706a8dd36df1de6eef9031554024d27584c4eb7ace6b3768c1daee8d9f216e61c66dba84907f" },
                { "skr", "1586fb616cd04d7102667d7794c229d496daf59b713c16673721b1ed471a02862ed1ba7c635126e26262d3de1da1608d67841971e0a0ab65dbd703012b4c50c1" },
                { "sl", "9073914556fe20d94ae83d3a57e9fb0c443a108d9ecd5dfca5a6d3a88d42006d7d28a012e73ee618dedfd8766c1f332ede7015b3988bf9962aae9d7c7d21c3e0" },
                { "son", "49d0341319262fa4762526561a91c182f85cb2f3d1f287a49ff95f5870d9bf450c87359f79737e7a14eec04b8cce230e81107ba7b5bb7bdbd921012fb4cb4c03" },
                { "sq", "e1d08e4c0cc6c6e03af2a2a0d78d7b63a374bb0f9b4e04fcc9fe07120e19cb0f7b2507889534f5610cff2f732557a9560fbe2f91d05e0bd580d11ba1f5192515" },
                { "sr", "9c27e6f3cbaf70a13bc7d0912f9f6780e1c53aac47d57644dda3d68acd1999f4eedd81e13dc6567ad7222bd10f5356a728018c2d3b9db8eb171ed93ca6a2580c" },
                { "sv-SE", "26de849c3df9e7f0fa1015aa97d061b6b03907a1f77f81e680d1051eda0a61c4e9867011c5e71a10245f78360c9edcee65d346e1f28bfdcf68dd34082ff209c7" },
                { "szl", "badb11730039fa4dbb4224d82320fa9ca0c458d6e9647b44185a2ed0115cda0bfd430d2c0c4ebcab976ecdb31b5d9566b3c8c0341e2239b233b5d3b317702507" },
                { "ta", "7b97af7deda265ba09448bbe032ba29c62289806fc9c68580973a7226fdb8cd5bfe9659e27355556cacbeb20c6e00c104d7e0a7dbfca7aab4fa676df94bdddcc" },
                { "te", "9fc5573ffc42423b3491878af160e377ab91cb37e874795fed11340391823d720682dacd9606fd04db353d48482d60372fad12ce16f15d57a93f568f1e0ad0cf" },
                { "tg", "dfd94d73626601c6dc436b2dccf15400575fd1f76d295d650b53e6520005f9ac3a9df3d8c101dd2637eee43600319ddf6ffe515f6395cfbdc2f872d9b7e905dd" },
                { "th", "0cb421872a2cbb93708815ba7a2aaf8484f4492e3a35b063f70e361a677562cb47200caba2c8f3801bda2d336eb78c33cc9372c07cfc489d16f2255dd51a754b" },
                { "tl", "f349878b874a9250426cf5008c8993d8924aaa192b66fd0cc12817f0a0dc4a248651224dfa22cc7f7dd68bae3f6113168febde8b0bd5f6550d02b66c9cf293b3" },
                { "tr", "de2bb285ef02a9f0f36def38347b5191d8603b6fb447ac9e82e520b94a9f78033e1d1c68a8d7680b1502de806df93bb06197a20a10f913e8146e5b1e8ac303de" },
                { "trs", "f95338b38cc6f4ff0d9dc3089b5cb80da7d2f50706c1f3a2cf37eabd74cadc1d32e66a95aa4d2adcbacf81d6b032d894f630582f58dcfdfaff47c5441da3eb17" },
                { "uk", "48a77b45411e026326192dc8e1212f6ff9dfc3e6cac50255ad67f0ee330a7a1a0b2fb09bbef7bf8311b2d549aab5b08573547da10cc3d2e22c5720cb94cdf281" },
                { "ur", "2b2e46cabd77382a4cffef566fab3c1bb160deec401f1543b4fcde8b7fc8178ea61851089ad750cd22e98c833d6383afc8820f1fabc21e726f2d3eec8e4758e3" },
                { "uz", "f16fbedbf404189f1142d70c1ba77861ee0f147cddcddd04c4f1dd8ed3124cd270b0e9ba7485b8982232047e49b1a5bc3c9badab74529a3f92a3193e13039d9d" },
                { "vi", "47255f181762c9ae9b5bb6e8e2aeb364c86d5201f06c47b470b8aac87ee058fc452a9a42ce193ed4e17d179bf816a12ac81ede9639ae92fe625eb50f2b9770cd" },
                { "xh", "e443873be773b436960f79636aacb760a79a35608a3c9a56afe712e7f97119181efadd2f697f9e58754e49a74ef01db48749d7b1c5ab578cacc8c43f33077ccc" },
                { "zh-CN", "67f5df8289cf816078b32907c7fa8a60d196b198bf909b3e16b691e7f1b050476548051be0ede1d03866ecb98fea525427ac376569107f1cb5676c9355a452f5" },
                { "zh-TW", "f2a0bca9e494bc5e7fe61cd0559f66f5d85694d57f3ff303e9de7033ad979feed5b3e1a991c0a7d5ebd9eaebeea3105509d492857ced5bbee44debecf0f31a22" }
            };
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
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
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
            return ["firefox-esr", "firefox-esr-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
            var handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false
            };
            var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            try
            {
                var task = client.SendAsync(new HttpRequestMessage(HttpMethod.Head, url));
                task.Wait();
                var response = task.Result;
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers.Location?.ToString();
                client = null;
                response = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                Triple current = new(matchVersion.Value);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }
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
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
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
            string sha512SumsContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                sha512SumsContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            // Firefox ESR can be updated, even while it is running, so there
            // is no need to list firefox.exe here.
            return [];
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
            logger.Info("Searching for newer version of Firefox ESR (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
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
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
