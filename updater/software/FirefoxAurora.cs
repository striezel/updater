/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024  Dirk Stolle

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
        private const string currentVersion = "133.0b6";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
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
            // https://ftp.mozilla.org/pub/devedition/releases/133.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "6f30d8bb649fd3116a0cd186abd5816c5df657b7d356a24a6fed54bd7f6b85c05eee43f47d0b6ce75b868d130489f46fff0a5d5ff733117a3a9ac6d58d6f7c2c" },
                { "af", "bf235f3648df863b796c7a4869e45a8cd579aac312c61e2f59b5ceacae3f17f54838c07d47af261ba8a615536ef11aaedb18385f835d2b7e231bcf397afbaf25" },
                { "an", "82ad564c04e6402bc61adde933665fb74e29f8e4af94242d1e2934106b6eba0d864453bf84e153cb359bd9a7a8bc62a2575a90f2e25aff2ec7f9b19dba339413" },
                { "ar", "11af9a3a563667222ed2c4709b3b932546b0efd2a0b672dd911313cafe46adc1a7360ef984084911c5a69c3148a22ec9b98a2579e18324e13f60d024dbca970f" },
                { "ast", "d5a8348ae8f2caab5a47640972f4250ad940d4caf3d7339ee22a296c3d34c60123d7f0bfe7d8478db7274bc1d829989d3a53522bee470cf001848cf9628b4b6b" },
                { "az", "a08fadeee827a07d74c8485fe29fd6fb039c1de3da4a4401c014f10621e16427dcfe0c9d1be0d1dd8d73a8d5dcbefdb8af7f41f75bcf0be60513f77c3858d23a" },
                { "be", "ce0ff2d2c35e7a37ab1d1c23692a5b1b73f15cc104a494709a3c505f0aa56a00b343f9e2225cdff9f9765983ef5e20aaf6f609af2e1d13efd3b17d953fb6241c" },
                { "bg", "57694968942f0b15d9865574c0141f12bcb287b752635ca033ad2b3d6adc18595680f0f203d6769e0ed56360882d398b3cd58866221cede93e6ba1a587361ed2" },
                { "bn", "3ffb577cc51d7f50f402f45d4b1f65c5978a4b4a6873d4d92b8f947df6221c0d91a5a91ba1c4d0d43090ba41ef5ff4f8c804d23dd4b233926cf4a5666486b7de" },
                { "br", "13521fbe5b80405cd0b248b3954b7ad58ac38770ea45381b7a204235231268e40a9b7d7ed38116d065a42002117e4c64f55a8d438ba9fd1416b7b28e1b4978cd" },
                { "bs", "db2bca910a175b33f6f0e8006128c6d9edc3ad564b6f15921c71ca4ce6b0a56ec123c5714980e6b55bd2b25473359e4cffd294ed875d0baa8245d9d8d702ac8a" },
                { "ca", "ba86ea803e8396534d7cfafb66846c1d09f8bd7686ad22593e141f58a2bfb7dcc2c7b9fbf0d9ec5a4dcb23605149ee4322788932eeb8cad74f31e416df5c1346" },
                { "cak", "0b5a547a32f473c10eee9c4a1b7de9494952d9259ae25ba218080a2e7c4080e64bf39c6cf54f3ca9e06a0097bfd1463fa7899ce887d677531a29e1e2409aa1b0" },
                { "cs", "ad6e36d2d5fc367aee57d6df2b3c11db43a05e4088ff306b738084ddc7d5990a076fc2bee00564f33c94880134c5e8484b91c83a0b9a22fb558baf869ff49dba" },
                { "cy", "f99e55bc6eb5972daa45cdbcd7a3ac395a18d8f5d6bec7dff4994461df0a240b572f260c62a6cd363d847c183cee46a84f3d0faf31cf57880fa5ee39320e826e" },
                { "da", "16e7c91c9e3b3c5e1590cf1e37b693c9c72032daf9590a4d3a8ccf5c13078ea1816fc93ba70c02980eed35e0fb36b0d27f377ddc3b43ab1b72b562a7588dec2e" },
                { "de", "e106060cf0cf492dba04f0b5b0cb48a623fc4a633e536f9a7959d578dca90e7fc749c19d6e716d2f15dfed8c872779d268695f341cfe0ad18eb559363fa5c25a" },
                { "dsb", "f351f6b50d9ce7d6e25ba53520618dcad89771e122ebfa6d17a4ac4ff9b7024f1d8b241c3e601ea07a480b02a0ddd02bc3eac67525fc8424a40434fd5a493cf1" },
                { "el", "a34fe46940af99e56c2293e4a01298b4924f04ee60bb605a2d95304ea174494d3229a488eeceae65f6ac503257563255c91a97ea18bdaa7bc363c61c90dc7fac" },
                { "en-CA", "e95972da1b758ce9eac542f154707231ef5615b10c3d1292bdd8a7904e1e4e8bff4c58dc3825789856495fb45b9791871a2494ea4212e78d8ca92e326cfc1aff" },
                { "en-GB", "1605b9e3717aaf532b7dd5458d63d2428dbcb84017d8105886f9d1852bb0d13f3c70295faa8c6f66b8792c953296e24702a75f5b8fcd0c15c74c2fda3b8196cc" },
                { "en-US", "de7610cedccc75dd22e62c1671246a5ce4fe0a5318f31b075fb6479fa62b7a3cde13549379dacbec2e97d67aebf481a9ce117e29290394d5d2fee42de9d7d348" },
                { "eo", "f05a004f9cc1bed4a09246bd9baefc7b33c6681b379b9c2de3bec0ad1d066ff4c30b96bec49258dccec72a4145d0dd57dff4f6c33b2190bb05bccaaa01024cfe" },
                { "es-AR", "54b17a376857d5981a3155b5e0a06c856a8c6d3777e1b417b8d1cf3deb2f330900b45a79f88360bd8f57951e50fbdb7c300ff6d39063643d15bfb0a0b57b3f49" },
                { "es-CL", "610572583fb8bfac999145bc038a2a50926abc02736f07627d363810023017ca5de2e15b4361a9226fc57007e63a2c74c07a14f511747c32718b5d616165fe0b" },
                { "es-ES", "5ea3325c90a13ee06ac8161b874731e44d19b3c2f7db7735a1186ea0b04ee56ada30a070edc9f102b2fb41543666c50159c4053d2d9ad1e7116a13b03b124e12" },
                { "es-MX", "c2f1f05ab0b86e50dcc1a25e8d548d5b942864149a7987367dcae5df3ea6002c27c8c33703fe98568a2295fc11de1badccab04b2f67311a6bb9d94c473941f7a" },
                { "et", "0e23a900fb466f7c6d057d816a22f47b67207b4092685386e01f7ab178492cd348a83c2298274b838b42960f996d0826ffeb8fd307c049e77d94d477a415f802" },
                { "eu", "5971d4249e758c4552d6dd11c204befd68bb1be92aa8d8e768787ca5cf87ffb489405285a761d9f91b2e631b444a471b4d9b540579c1e0119024276068543e0a" },
                { "fa", "0a0c0b42a46bb650886a1a97977a4255195400ce3ce1ea7e239cbe56ffc7b7cc86a7bc0f98d97622a9156556b9b93fb57164e4844af998b626c2801e5807ff40" },
                { "ff", "75dca0458d779ae3c67147633d583050db4cc416613f81e4c1f45e9ac633bba7b68d24863ad87146f44d83dfa96aafa1901eb9d7ccd2d61b8b953cdbe8c3367d" },
                { "fi", "10ce877a2780d32b5b204599c53ff26bfac0ca374c2a2be0219302418022c0c2254cb88fba6c58baa2778183629b824e357ec1b0dc9308d0459b151a039ec256" },
                { "fr", "83eb640b38626f1b61266ce7306153b3e8e8f97d3233311efda48ebcb5e3213dd3cc2d643cc348bf97d96a791e4f421e4c984b5019f896d624f711fbd6f83e49" },
                { "fur", "74eadea3754edfb18a94776212f7f03b90d18d6b076acd1212b16b20769ac253fb4f7d87bf852e6e1c4d4f6db76012d029fe26c1c44d5852bcf6d46a142a340d" },
                { "fy-NL", "0597ac8a157263041ff9ae4d4b7f8998460855bf195b724ff83ec1561b95bc36849adb55d9efb535d80bc3127433891b2421d1392c120042cdbdefe39ee76f57" },
                { "ga-IE", "7daca7f3b7805b7e38103a61d639156b6ca450cfa9340c448518098ceecd7c2f9949af974dd3c5b1c61fd83696d92ee199bf8e68bd65fcbdcbb8d4dcc5edd20a" },
                { "gd", "9eb4c9da2e0a7a35683c4d96c55a62e3e63987d852816b19d3abfb50a3cfb4a6edac5af3a66b6256838646d554bd127c996fc844a4f147198386e371b9911de6" },
                { "gl", "40b008135d11d0a5143245bf474cf281f7efac46c0c32d0f97687dd2c110dd4473f2e66443645f3ab236b4cdabc8b81cb4b9422593978f88cea47720c257a5fd" },
                { "gn", "c0650d0068dfadb2904195e176c87c48f343763213f5f04b8b326cf5e6a6dea6f8a1f70801b12b96f029f209e64dc23f8d1ea94ac43fbd35220c5e4118ad1747" },
                { "gu-IN", "e18b1c7140d988100c22aa74b35c7558b536a3a8a106b7f4d0e26c34ff0ed1f7463c5a8ffc7246c0e0446b085a2a125e2ef03b426163b226bcab2dca31763937" },
                { "he", "a51e9b8209c5e38cc251430a074200eefc950a1e8031aa7b8ca2c5ab5f7e82698eea58c0cc41b6d4ad581f85b98af5510130d2318c6704ca7e4c2372c923ab11" },
                { "hi-IN", "ff2e2d51691177e3263dcb44dd31d773c748de810edb093d9fa2232cfbcb2fd34d278f23bb97e147674ddebaaac425fcc3317ea6cfe4fafc7dfbc99af672bb70" },
                { "hr", "c45043ad17302cb13065c9edcad3a9fb1a8ae3a284db75afd48009536f9d7080d3995d8a94f8b060a5577e8511791011fd62ab007d404d738de203e68b88b1e4" },
                { "hsb", "415ef9687b20996a18d4fa55124a2db8327899656e14ec9b1f5b55601c594ca089c47a4291a2cb9340f700558f3aa842c1575c1d86180f7899d1514c11f8b74f" },
                { "hu", "4942c44fc1f0eeaed54cf99af2e281941929b34193bc88d9a32418d01cda5f2d100c942a3e22b5173c86b81582fe612a26d512aa215f03bbad48f472b2c2fb80" },
                { "hy-AM", "001dcc8d03e1e5aeee65b9e80c8a32d1d497f615910ccad8fa3335d3c13f8f841310519d363bfec0187bccf50ae5fd2717c0cd4e20df6f724b3fabb3ce951f26" },
                { "ia", "b252dbd50edc8650b1e6cca08309ad898d37796550d77e34476ba7c6c71f9d1c7c370843f8f20bfb94c9d90fdf66b0bd92661910f32f0d152187a721b2c09235" },
                { "id", "c9b8b663ea69d912fd9fa0206ec107a984c6349ed7a827342d841c36be27895675d27899e3bec633cc8a79236b996af9351b4bc6d7714d017b1917bd7b994fa3" },
                { "is", "ae765d8caaec42669eff27e5e215dc3e361ea6dbde161ed3a7089141a23c5d4c3968585bce513d67363e6bd65a70b9acdf33b9886058e9e1317d5f4ac2608678" },
                { "it", "279077660c823a3b7259cacbb196e4a440c4609cb455e17d8480c2152a010a1eaee795cf2bc8f68a1e68db7e97c224433fb8361a2a83ed058d1ab5828e572cfe" },
                { "ja", "4b15eb15cdd9e25fefaa4d7bcedcbb9bc79d57f12eb3a23e35269dccebd02362e3bcfa16bbf6a72ae6b388dec3cbcd5d71b3438e85e4746a47e329ec77b8b57a" },
                { "ka", "fe832f29d05337c02563db922d4e2966c295bf082f49a6fc1b2bddb06da69912c8c08843fdc5b195ce67bcbe951afd1e043678781bc79e6763a9aecc1fc2dabc" },
                { "kab", "0fa5c4c22099af1b9897d002b9934b99dc4a8f2361c685e70a8bbe1fba66ccaf796bc07925e824b1a5061b7d9cb908949dc63f4faddda423a29f12c2eb23ae0c" },
                { "kk", "c14ac85bc5ff9f3447170801f5eb174277dca7aa38111255d862cc865210bce38c274d9ed22afeb9155251b3d5c6a4969ee644ec25b713b380cb47dc90acf83b" },
                { "km", "b0906813f8d2b700400262b9f35d548da61cf9193b5a6234ef960c561771c8334bd52a25d9ae8d6f6b713f8def632b47a1bf8aad6ac35b5461254b84998b332c" },
                { "kn", "a555da012e76f4265d0aa1b72dc5a4f279c66c9a027fa206d2c447c919fd2ca715c5c0de86119946c8f50ad7664c7763e8d2405862dbf25453f022555fafe549" },
                { "ko", "3a71bb24fa959594e4c05f05424dff8c3470674cdeb7e3679f6d317369e9f534e5fb0dfa3e66da67daa2583d0c14b5b66b58cfe18968e455250508c430a1cc29" },
                { "lij", "556a542a1f15469148170703c4820a7d69f91378822b850be8a2eee730f2374e62cb6cb46d4ddf011d42330afbaac255c29cd620a42311e3b094c59a3e01c0f3" },
                { "lt", "987c388811fbbd699628b959e5e451dc0beb0536a3b9e24124247cce4f01499b6cd03121ca710cf13d3c970b881480359a717d38491fb9278181ca6bfda267be" },
                { "lv", "4b165553a090317e8439485902f57f6abd73d54ecd7b1c771e0c5cda6445cf0a4c57685de929ac4add4ef305bfcf6613b0deeace96d121890aff3bac992961c5" },
                { "mk", "3d4cd05a86c4597002e2cdb74bdb63599e6a32345b398f229f31846321baf214a6a19fee7cf6c840932533640cfa9e1ee03b7b6b373d4a6b7de490ee7f4820e0" },
                { "mr", "2eaa0b566c6d91b21ec065e694c09d0a134d5d3539f25802c2f890bdaad80d670f6950620399580cbd6be23a498fb15656cb0118c361770e5f32fa33bcfc734d" },
                { "ms", "49c18c9454eec32d0ff9f1a7bee66fc2bd2965842e4366a1da5e2c38c0ede875d27800c808892c8da413d72c3d5bca33c40dc7c552b809820058057e5b074ed4" },
                { "my", "4daa91998d184cb0452a34b6bbf4eda5aa7e485548a8283dd3366fce892722748e09e674f5cf089e270668136ce5bc6c15f2a504083cbd56ede295f101e6053b" },
                { "nb-NO", "a1741b1049249d8ab218719f711571b6ec851edda9adaefe8094ff263af81007256004f2865255ef53abb39752febb21b92443872a330df5a42540d9546a101e" },
                { "ne-NP", "546def1014faf5a9131ff35731a82b5d40cbf95235c58438bbaf55b2e05dc9141d17015b99cc8b80f92845ae748791eff94117d068e1e956a18936dfe037ac53" },
                { "nl", "c553584bc5b8b4fc229ef6c8e6e0277a061ac37c995bcb49ffb0dc67530198bba9f41549eac2553dd4b716461ac0523a7c9987645b4ffe6f48de3104e1590e2f" },
                { "nn-NO", "013be386ed76858db10bc656ac58d70533690f2f20a4f3a7608315ec7f278631b0dff38fdbb2274c8671bbda60b1c3d66d07f43b642d4833ca5ea4c2575a00b6" },
                { "oc", "b93bfe647e7804da0389aa4bb2fd3304fa7e46b266ee0467e3e902db4469dd0b7b5a5c6c2c620dded9fc382f7b5690ed910a5e62c9e198a86734ee29bd5fc424" },
                { "pa-IN", "126bf8f5ca81e50d4acd22531654f0b53cd6a2ee9c9df11620ad726c29a5803c57bb233c3bbab7e97054a7f8559307e17dfbce1fc595866ab716368657d99827" },
                { "pl", "26fc7891c4174a2d630657533047f8f677994bcfd275dc95c663e580ee1527ac4f93e6e2cdf05c1365e93b25615cf8541af7dd7671844c6e4b0d52f5002e9079" },
                { "pt-BR", "6611a60cce5d17141402a7c05835cd4ff986b83a65956ac7cbe4b117e0c93fa507eb14d515c2678b5da889ac6cb3fc2e4cc48cee9e3a6a966708b54fa295a4e7" },
                { "pt-PT", "59b98b20bb2afea76f4d1031f952180a02223e48d6f243864ad307a5173d7d1e3c6a954ced526b77045f2fd1fbac434dbbbc9e81b87b1e1a5ef59885f9261f95" },
                { "rm", "e1a7fd2b03e306f27933801e91a243093509dd785870f68b981d7f0ef97a160d0f47592ae15cf741755f91627a53ef2b479d95fef00eeabfbd0bf55bed387ba8" },
                { "ro", "d17994265fbba81f0ae62b31fb5ad6dd44c29d1de5d71bf16addd458380cd3127a2626b02496f18c7642c234b83456de15739062ee8fc9022e8fa72bf59b03a3" },
                { "ru", "8d1269b24a85eb9275ebd1f2bd54b389523e3a1a382317d36fa8f5bceaa448886418360778718efb2a8f1a09d1e5b335aacddb18cb408dc89aec9caf08935018" },
                { "sat", "fa91edd096de87a0aef8a13fabf07eaf8d4c483c5699fdcd8be2e827590268cd09b3f0af0c1d5d323163ab0a6788dd1e4850bfbeaf59a7a4f35404479fa5fe70" },
                { "sc", "de8d9c506d8f2b6c426af780c3133ef37d7aae69244bb0479b205398b169d80008745c2e9ed541bf01d95a3c21c5f6a3fb4455974886172f32756425c41d58fb" },
                { "sco", "69d3bc0efe78729b9a1817f20659e1ada703f9ca358b30698caf32c85202d12c6dc5feaf9ea3a3f1fee14381980e70a7ec32fb4a30ae9edcadcb841475a14fab" },
                { "si", "2b20312973ce46f55532f3ecd9da671d5c43717acf1ca309450c38867d754161becb0f71f92299346b488351dbb2f4acaab105b324c6a8ca419a7263b83f8777" },
                { "sk", "5cbc5a802f1b5952ff012effe54256668b7190f7850b9f2d1563b8305ed4cf2bf9cf00d13d2a810668fcf4bb62ab33bb20061d5744af28321885a71c2391efcc" },
                { "skr", "43e250040e933a8bfd49e602cca8714430ecc5aef0ef06ad771a5483220b0917e63917d647c60ebea07fc62a36a6f620c58c9385895e7f4455ec7543490be9cc" },
                { "sl", "761ada1ea697e3aa27269897240b90ed2306d6e849ded85b6814e9e53843ca74fa7a32ee1b2f0b6157366d4610d558d5ec6cb5368282773cf3e0570edbdc5d8c" },
                { "son", "3aae1184d7f947c542103e2f9ee5b02b0ac0abcf8a3a39078a4ad5bba69cc589dc393879000517c90f4b2dda788c45136d7c5b88a44c85a1140c9805ffde26c2" },
                { "sq", "8ab46db381dbcb07ff3fee6e36d8d5194ae864db32e04bca68f23a874088b69be09c3e64f76198e6345866c090620826f3b957945d5ff6a44829aacade63c009" },
                { "sr", "e90a3984b0d399e50d41e708b194e4bbd027ab2b54e3d36eebca65d51cf435f6ebf9b8473999fb0f8069ad28d7392046d89c1b34b7d0801583be4afd4cd91353" },
                { "sv-SE", "841522ff7c0b6a533fb2527f5947fc533b072df32253257b494ba2438658ef0537367933763c518dac56131b2e169f7ffbe7cdfa473f36131bf4afc9022d64b7" },
                { "szl", "f0a44878d3e9505c1d4511f5da410d2ea67af4c20bf0b3a9ee7f034fb10b0764e4c2d4d76dbb04ddf3b13b38b9915097e725ea90e9c08e24a55296780334eeb7" },
                { "ta", "fc9cc7fde5c99e7c538ab5b0bd24970e484b2ef87630ca53fa4ece7898b12ae573b144c33e4f283dff47b54bbc93f161099d94f7c6c70076bdaec7ad10bfc7b0" },
                { "te", "a5eef814100fa32b685ef427042a70f78e455ec40cfe1dc0af163d4a98c13a7e9bb9273a9a77f534576205126a2757b19a683d5aab48495f7927db9db6b5ab49" },
                { "tg", "de19e4c709227b65dbc7c9d0923f24227d3bd69c73afc02a41a5e175cda6c61bafcf8abe4786cc8125ccc941932a396b87abb27e288b1fb0c3705756b8f86c7e" },
                { "th", "45f9cb73eea87b05bac52be4d764ea5d9f8fb98f4d428391e805257502462768f4a941f371f6fbd2950b9b8a149cf5e35e351ad6698de20f11d641de92d803e7" },
                { "tl", "332f714ef193f8dc96cf56b4bc755caac6d7eab3fd2588ce8b4167e6047434aac4282953ec1b68432d5e7c6321505ef30195e8244ebb0defd99616803664367d" },
                { "tr", "a9708f8df2d13201e1e8a0cef8db76c3aa5069e133f41f2d5e59a2c05212b8a557f7c2f620c489386fd3e6d5d358c4aed6cba2b8c04a8b98a141835d1e712f4b" },
                { "trs", "dcb2c0ba64daca60bb50983ae03f1807881e15596956b37f382e118cd20f3b737b1b9b928c78e9e8c17f844fb67cca412aac1ca20f6cc07face69d6e4d46c998" },
                { "uk", "f2306b7ea8d89f4b1a46e87f47638c143e9b73faa7129ac860089154bf97c7fc7a2bc7dd2f52644ad351448ac59693abeb94e1f40c45c57f9453eb58761635fa" },
                { "ur", "adbb00e4402c0fff0e4c447ddae93cf596be0723c84e6355fb12a4620e292f2e073b76b0fe091df3897f12eeafb71b86c3e4cb35d2f4f1697116837c0255065d" },
                { "uz", "935e9883171048fae6ab0d963f935edb6ae8b599750b84c0c68e898421490a4a6e011d5e175bec61d33ff141c383cfbef2c2f5064aa08ff054a551e649953872" },
                { "vi", "a5cc5070a0d42cbc9d60226ecfcb0cae4742f6d9b44653ad5e757c816a8f00eaa87b62e1caca063444255759f9f98a89e81bdccf97e3cdd8ad65a40abc15809e" },
                { "xh", "c5be8aedbed020dc55a0126a427e1847ec5ce78977082899b2f52c3a43e2c92b187a5061879c791729bdd0c4acc035ab2424ab30602e25b30bf60072a947cf03" },
                { "zh-CN", "37f1558509b00630bbafbb8c294e01f47e31a8693b6be166520cd33a434a1b3e6628b9a327196a950ff1e11435379a720ae3c196300819642e66d63dd5b3ee79" },
                { "zh-TW", "957c515efe118f74a372446510c70fafc7e12d469d0a6f0be5fc462a19a30f4ecfc6d3a4e7a8a97b7b1690a7d8e0e97d64b3ed5893112c9a17d6e6fbf2e5d4b7" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/133.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "50a0bb51f0aa4c1a92b8058884d2532026f51710f143a618992378b3ed1c66683eba69165ac2d71d7e847ec0279b3eb95efdb745d447a7f4e01d20c8df660ae4" },
                { "af", "db0dfccb64ef92613b016282c5ec685da533167d5a140e13527ce15043a8ee54a333e6082dc930c75a3a27e19051e5dc5e372638f1526ba1db31a003b485b68b" },
                { "an", "6bde5223c2b846ba239a66db480b20922c63fed15a29d7b0756143c73663c23523339ad78dd0db4f6664eaab6453cd62581ab441e704e78324278a6e6659d9af" },
                { "ar", "8e0d7dc53b3b3d76f987404c543690174416d82a4704ec30d4f9a6b7851f2c675b24011619968d4f7928b54b8466970d6dd843766815aa487364010141becf96" },
                { "ast", "0bce4506efba85a0172b2c0c47f5a12ed907396b14f880f70179ab2a75219dd5953261b90f487f16e740644d2fb204df49d366bcc5e834a81b8080e2f1aedb3b" },
                { "az", "bc3d3470921169991d3a524080907dbd4f09013ac19e5f2066bad52044738a3778259f8293fd195b9a5758305907d228d7653f0cf27b6febe4116323489f2ff4" },
                { "be", "0d9a09100a4edeaf81254ea451ffe9bb7d52aecc3673989e7fa7f44500ffd0b9b985b7952d566aa663e24a2fb4bb5096b4f81a1b08aa3f5eec60296f101e820f" },
                { "bg", "bdfb1b6a14ff174653a2b5b2cc4e15ca40584825e97fa815b987afcc35518477566987e1ae85f95e50373f9f80611b47710276990d87c99ad5edecdbd921c61d" },
                { "bn", "b51b7abf69467b89007e306d7d028dae739106ec94e7d41457577363f875e5c2fe5e5940406ded1c7325057f2f114e384432d94b98d1437f48b0540c2a2e3e7f" },
                { "br", "432e5ecf1432fbe8adb79de025a9e3a1291291b4d3d811a3b36c4112da75960bfbeffa5f442b1f3955f1c086756620e6f39d524b1a10c6aaf99eb130f7ced0e5" },
                { "bs", "5ac0b565fb513c29e01ce918835aa689b9c57ae6fcd9f9a1c19bd0df36818fb5a5371ce182e54136b25c7db4e4ec66ad243d72e59f4475ece411e51d817ff45e" },
                { "ca", "27d80355cfbc0533c7a63a8b6cc36c073cd901ef834afa4f1fb5449e73b8f516af895eaf202f8b0bfcef182f11d4470fb8a570f7d24f3cc5701d538c7c0016ee" },
                { "cak", "553a86dc7ddd03bfdcdab2bbfead1d03af7a67ae56bfae28850153a56b762fe87af29c436656a840c474a6c5fc8691fa2fe8f30f45788c840bd0343a348c0b8e" },
                { "cs", "fbfaf8da2caf285f3a85cc1b7be9976a7b869eb2ed85dbfa4317b35d78838defb5aec767a91e909abd38396fdde4aa7bfd4c5509a848a0f00f682868005eb411" },
                { "cy", "e61727b7c28d69ace9d3850fbe609b225a2f831ab32879095563aeda5c4f80b9ccd0ae42222f6d289a94b4eb0debbf7f6da10641fcfe81739206c8f635489cc6" },
                { "da", "888428041a3dccaa81d53d0e46f9f9ccaebcedf3181d667aa11f7154c4d572e3efdb9cecbd1050ee8dbdd58b2bb8a37589eeb5631713ae96c869e675da290407" },
                { "de", "531159c5f53b0f9d9db58d795a0a452c3e249763bed3fa18e87296f0c31f50ab6c123c53c9a3662929358e1fc155e45ce3c3f4514e0cfeee2e2bd9479c970b89" },
                { "dsb", "cd7791a904cbbfaeb32e94e9de2f66e60f86598ee5fc34c8d04b01b1e03ad2198ac71b1546d246081dbf916cd5520e703776cb80e8b4e1f54a3a0100593f2f6e" },
                { "el", "0df6a1ba8c6ed17a2a69bc296fd5626cd322ec8efe8b313eb696af36959c252ec1dbfefc64c8233fa9f4016f719f384b310402527fd1471f18514f1dcb520714" },
                { "en-CA", "2d44bd7be978348586fb14f2b2da3d8f8d684409b420ec51b65becd09238bedd1844d0fef733a8239c52e408c9239c7690014e9bf0bcb86d49e4d4d1fb426572" },
                { "en-GB", "21e55dbb8349a66f848b9773af37e2fe5370a33e035132bfcb61c8bbcb61d5c1b5f6de32e92687032eb7ea36287bad630fb4c1197137baad2aa75977acd3e14f" },
                { "en-US", "4e23939c753a469073e6db7cb6ae265a3365d8ff7fdf028f8dfe0e80c26b8a987934401f931b22887ea4eef8befa819528c6ca5e21c0cab477e8e98a8488eaf3" },
                { "eo", "c4a7ceb6f619878b2b94aa1439623e9c22e15670c43378e329cc68c56b49bc4c93798db57aec65a156a614a3794558dc106ffd044bf2106f7901248310d276f9" },
                { "es-AR", "b94033309d15a83b2ea1703fdcf90bcba05b40f1245d76d1d24010d3e6df8d97ae709e3f440fe8b2f8e9052848e5c5e8aafdca12e18a57c461884b0d40d2f7e2" },
                { "es-CL", "05fa3f006db05e2fb7f42e101e25caebf28c4aed88f64b73ad5d0a0ca462c534b18b8f2db6e75d958beef265fb84ca2ec3f21e9f62d2fa85d50d43f5eeaf37f4" },
                { "es-ES", "998e7d618954e308fa017716a9f2d03eb77b6e862a6660e4bb7d083465bbdb3de07dca21a0e3372196758dc316f96542017d3444fd24be2210882ee67ded1949" },
                { "es-MX", "c07c0a5ccb73977e7fe1d7e542c93361619d0b03c7a98dca9004016744a3b98d5410fb833dd0438b0ddb67c4e20c3cddd4bbc67febf08beeff37db76512fcf07" },
                { "et", "1a0eef51d34037c136bb1b1d0c714e4c82463310ec56cc3775ce8816e8fb2490485f7319f8641ce0d57d4e3a111579f1ba621437d0a2b76e66086df05fb911c5" },
                { "eu", "6f4a96b69526e3c6d273fd15ae75e81afea3a9e6fbc3ff75a00eda89099043e8f4b16b7447426121de5ecdd4d93a73906d229259e9441aca316aa9dc3c1344c1" },
                { "fa", "85013e8a81e400c45d980eea2cbb5e4ca907cea076c68ce8bf0906e82390bfdc7da8590f4575586f56a6021e330180bc7cf917a525f638ddc939a7be307668f2" },
                { "ff", "f913cf472b823545dcde2a37d1222f3ab32ce5b38112ec0f7998be01340e03d6081e31f4da6adb1ac2501e5afde1e822a01e7b5560d5d5a6b2f346ca0f9d7778" },
                { "fi", "16f826c36d777fff427933eadad9e849e184aeb4e66feb05d1ccfee2e707fc5e936180efe87aca5e29b3a9bb92b5977a00decf3d0b273a4e8f73df9acb10227a" },
                { "fr", "052e717dbeef1da5e279e55a5b3565c9e2ddb1b82697b4764bcbd83a8a5ff9999985906355e1df33c6bf6cc2a2f8914cace4598f1a21cf3505b9cd01b4c9a550" },
                { "fur", "f98f998a2cde142cfbefc35e2d71d9bbc176f1a5e73bf2fdb64f38fccf44fe62eea587c680789317653e2edafef567165f81e698e4af5250ca3a800b54a5cdbc" },
                { "fy-NL", "ff010f2a6a5593c31a3f69aa010ba1b90ae30c1c2493e6dfdd91a2876acdefaaa26192273d0a6114ca1f307859ac029187172641ad1abf688f7ca6591f443920" },
                { "ga-IE", "4a348973509d4776a25253bb6fe66da5047115cb40aa7579b5d211588ceeba44c0b583e64ee04dcf2caba20c2454c72a5d9c2778c83435230bbc35a9437c4d50" },
                { "gd", "7acc5914aa71c2733d6763fa8f74d694a9d884b5222e9bb689cc3759e9b021305ea9cd957be82b7c720dd5f205a87a861c3f02ef473e4b3d2f6c19b7b9f508ce" },
                { "gl", "ccfe3a2013534c5b139a1666135d4f672b6c0f511302917bd32821bf363dffc69f70ea9d0415fc3980ab3b013a419a4d1b1d0e3e7f506eccc8f3bd2268700ea9" },
                { "gn", "546492ff6fdf8261d8e257cbfa60b410b0723ee060f96ad735ca591ca258164c7af1112554964d090e5d7e3ab6e20fa7d37707c77fba243b965d3ac9cf42897b" },
                { "gu-IN", "6df420ff0941fca3db1ee018da0c92a2f532607cb848b1af47aea53051674a03b59f91c1cde0c9496788020b53602f6c6c83b4594d7cacd9dc1b94c8ab1c194d" },
                { "he", "06307abe5d3b34620a253d9b0216e30e9ec45be2cd2afbebe451c1e8f0eded6a06b77c7b653340e7183ce9edd7ba89e225f09431587250ad7ec3c1ad4617f191" },
                { "hi-IN", "f57795c939df26a466adb2465ffa859ca7919123e1284d847210d87497b09795d3639a756f27126c6bb218dafe08b1284644024e2d33fc34955f82d5dacfb811" },
                { "hr", "95287917d2b4817813574de82cd54e8e09d3a2e21856ca61806f97557d71f29815265417ca22c226930177f7a75a3f4e5e20beb58673f95027f26c2921465699" },
                { "hsb", "401f12e900b53f4fcee4926a33bc1eccd19b8880172ba15a45ece2f47a858bc57270078501c7a9f9257bfd200956a9d42206a9adb6cda0c53670ed26d24864f6" },
                { "hu", "9c0fd39eeda8d0c0de3487677407736e56230ecb71b74629bca8d530584a4af60cbccabfcc463680a412b82658c95a1fa1f688bec1a899bca963876ddeddb24a" },
                { "hy-AM", "9024b161a1f01eaae36c0298efd8e94c61314660b4b2affadab226da056fb65cf223b55830da279d7a2476e5c191200fb9afc7f4dfcb5cc63cbd731b9caeb580" },
                { "ia", "7c9d28ed4b5c22ce4256a5a4fd8f7850aedb31acbfacad4980e3c320da1d39d6f8b4f23e3cbe5c3df66ebb85a2b5cf8fa04715749846b1f78062ee01ac9482ce" },
                { "id", "3f7afc6efef687692ecc737d449d4c550045eb99f91938a5c4a08eb000f941df28f8d07b16d4053998b6d88d2f5bd3acf682a5f2a93051cc3498239ba46c28f7" },
                { "is", "2ff6afea032d1dcbe5797f13e99dec19944fdcddcf0068df5253af496b2708163a6dbdd22cf54696f22e5881ae556ab601f1af0b47b736babce01893702ccf92" },
                { "it", "76c8f2e8bd0a8c0c3178adc22a2c9a732faef4da2a514e1d6aed96a651c482ceccd1b2ed26d6d33a429a48b379bb00a6de0505519798141a7286d02b9f4813fe" },
                { "ja", "2b61222f56c5d02d6a2e300625f9f204afe339d265076d2535309f61ba9ed793ebd00634164eb4dd9e1f9b929e933153e7bbf542259dcc311b86726f2d423f79" },
                { "ka", "d12a5b5ab10be37597b32aedf6d720417ccec5dfce1197ce9feb8417284233cc590af900b3563a3fed732eb5c7f130464fe78c6463883017f4c8c35100110fea" },
                { "kab", "1b37da8fec3491a268e4545ef08c4b19b68ed6a768f0cd41605aad52a92cdf5585f3d646a8133c2e21fe2cf4af35ce939e3ae142b730452413c97f1468d54155" },
                { "kk", "5852c4d262436597b8738453b6e4d3a06f56627579cf3e538388b20fd4bdda41412d5f96e85c65d1e88ff5d802a94f4d0bf2feb6ac97e93f29324b70904170d2" },
                { "km", "c087ea6c2033c364cf3e0929b4eea22fbe3d6ed34da64cdea8a3d69b1756c0446fa7cc60de149cc36d7b0c1b8770f38362ce70f70b1db22b57822d4eeb7ffdef" },
                { "kn", "d9b0cdc81ddb502e9fef73439a2282c58b38638b60b4ac43009b528acd96898d4ae0cc9d10179f31023dde0fc3305b7678bcd8cabb46806d1ac2d38d7e5b988d" },
                { "ko", "046f05c4b350868852c1864ce1dd4fee53f236fc535c5a565dd05019923741c803abc5d43dc426fb6ff75d0be31cd99816573295e11c15512bbc6c493539eb7c" },
                { "lij", "d259ee4677c9cf80b4c1d004075ec93dc34e24a028cc9a885327ae8bbe28128cd3068930317f3786e8ef7a180c8473446353fb6ed7aadf1e1873a46077e0bca8" },
                { "lt", "32d33e29480c7789968bd6a93bc7bfb7de2490e12a9399ba900cc9cb5edbdcbcb31df87669b713bd900cfc4e61156548bd3e7151a0c086b86f43c6cc625cfed3" },
                { "lv", "8025b5bd7bcdb345962c3ccbae6863577a798aeafc06cb41ab7dc2b080d6789b8fe3c39da477ad2881a1cf4807f1482b04f434ac671fc199a40eb76e01887b7b" },
                { "mk", "c50572127ddac36f07d89e2dde99ab6b14c05e15795d4ad70773cf555a56e75f8a92484d61142accd6fced952233a8145e3abeecf908afc81b0220ce97290e6b" },
                { "mr", "ab0ecf2537c694c6ce21290b89ff3db42105b10be1ceecdadfb1df92fec7b0270756d04a295ac158489f7a6e15219105bede26a9696e3dc614a2ffc5a2fdaed7" },
                { "ms", "d71f23b72d5aa049e1fb6c66bffc6f084e885e7a785a39579d2e01c4518da57b7e547e5c340fac84f841082e79112d0e0763c756c3be8a0af02b064a31080313" },
                { "my", "46b85ebc7d249fec72da85f468f45cabee211eeabdce8254b44bb1a193a2dbcd50802157b0c56ef70edddaa657bd2891568b68c1b1d97cf835de3d6e78149a36" },
                { "nb-NO", "fd75b9ef5aa928255891575bd2fe1a079eb1de1cd889ca0bff827455d1f58ce5f0422f72442a160e5601b2c7916c7009d7ec43a35053bb9efd33d68b32bdc0b8" },
                { "ne-NP", "739e1f9df8d8fee7436b3f52f91dfde426ba7102f2085d422fcc16b9c8314a39ae16243a418299ba64da40c4dcf94b16769998f997f42ff04df8ed857e151987" },
                { "nl", "d80b07a10019a8a661d1d82a0f2a08cdf8b8998d4ace2f2c84416290bdc2bc7c7655020a778c8c0a27df8d0fee8888cede0a7acf95bff0bc0194e9e13ecd1e68" },
                { "nn-NO", "bfcdf598a3914fef5782c4836c574a481f270226c935ca640e729b00646c360829cc38ecc968ee17cbcef251e7a06a24fddefd1f2fe10261ae44e2c1597ed356" },
                { "oc", "d087d29c3a4ac9a2bec58d5ebbb6cd6182c7c933bdc91834da6474d5128b7302aa3d455c5eeb290afefceb4867c573e3d602460e0a27dbf6cb43766a83bd6451" },
                { "pa-IN", "8a9aa14502dd12d9344541b07faf8a4bdad03a6f2767c2c05366d00704c5eeb3f4677a1ebd4f5087056f66b54a22afe6717f3e64bae6aeee8b91dd0a8a739f82" },
                { "pl", "d08a8508bea10df3d46f4f9439f5def1183901ee7cceb98af5c2c72ff9a025bda675506d74215d05c812a8935ae011e1e5aa46649e9a58a40746592e5026a0c9" },
                { "pt-BR", "f8fa71d60e9a78209720ff0df5ebbc925de6aa491e8c9469001a06ea747de4817957fd011167469135a8c0c603625512e215cff010ce0b6c1e5e259ce9bda2ed" },
                { "pt-PT", "b0850488706ee2e0939ef0721b340a8aac76fb8b97833f3b40edf5159ae28308d2b377c20744a10253415c044e5111001d7e0a309dafb457b84226eb00c91949" },
                { "rm", "215ecbf7f64102ba7846298b42db7a670b84649629c33db6dbb8e8c1ed63c988b704a580dfa6a22b8a71b1cfbeb2efc04977c7d5972037e02771a89eaca6239d" },
                { "ro", "3cdaf1df457f8979b196ed05aa57a043fb14edf96ee4b8c7b1caa986d171484a398b1db636b570e5480f5474d06de3d280a1ceebba877bde47f525b5c4142177" },
                { "ru", "46d2282973ca82fbfd4498fa9e226f4451dfe3e2975bff43cb46cd12bb31833b99e5d1fbbd796e77c715b536a4aab0b1babfc21c86abe26d75c16156e9a33d27" },
                { "sat", "03ce7cb4653a2436f8b6b00843f9ee0df1251db5ccc92de56402b5311bcb716853328dbcd65d4666d119cdb98aa2c64b79b6808912bd0ad73242b6450758ac68" },
                { "sc", "ec7096bd5fb631dcfad8a9a4933dff38df4f1edc0ea2e0d7d48a900a19b701dc3c2fc43546864fb6cb3051450199691a8f95a1be5b252623bb87b18d4b8c97ae" },
                { "sco", "379ca76f4166b4c54c1d42b1e31f37c96661ae38173b6b3b9f269de047766e22c2d701fff52544652bb3f1952ad1823c9b310418cbb7bb334ae9028263ec5cf7" },
                { "si", "da9a09b2fa154b4e48b5ea0902f4426e9bc36fcb82d656d9aa2b59dcc99ab2e8ec5bc51414a97559f2078e5153d28436768ac5cf55228e88d97adac83dd5e617" },
                { "sk", "6644c5acaf4f2a2b9e3f6940508c05216146dd617415292e6800f8f3e4fe9101344341107334e5f8d8ea6fe9af4e703115387030c17dd5bbc7c6e95cfad323c6" },
                { "skr", "299f61f72f2ca8e946de48a7eb2f9694cd89e2bbc8b18b9b9f066643f2c8a242e2f6aa3dbc4e6a2909c2f62f3ac6f06332f663a0754dddc49546f5768409c2d1" },
                { "sl", "fd18a48e60b887a8fed54bc89bce10ad23f05206950bc19787598ae4ace20ce435332024fbbddde156a741b3026175b51ef145d64469b13ec26d41eacaf7be47" },
                { "son", "cfb3ff9c42867dd8ec58b7064124a10f2fc5445d98ed28ef53ce547a76ef0df4eac80af7a3eb9b3a38f0462b1c4d3bb187b0848f76cf53fe77cdf704cfe4119f" },
                { "sq", "bf340d46f59e7ac6ab8fc74c14fc1a86caf25078443d824ab0ff3cb3d46656aaadd73a1ad76e0b2da99f7e5cac6509866dbc66f93253d661d8234685e4175555" },
                { "sr", "263e64d4272fc85f9bfec00e42abc69972b79b626519d1d7d1b93689ef2123417351951ce96ed34d8759595bc2c6fe6d8a9b038414d2d600159d4e05beee04aa" },
                { "sv-SE", "595ecfa8617a337c6f9e4177a78c57c357de96e879bbe209a92308b1736e247b3ef7e27151dc0e0e10446ae0c46e1d03a825581ccb9778a6fa7b3b8c33b94564" },
                { "szl", "8b3352d018e6fccd03c79f614e067866589a098d01d0fb1f12056993bf3f32223d42c464e79b6fb4a063d2b898f65e6e9439f89c80f2f54927c1bb4eadd18042" },
                { "ta", "659310a9b3b40557f1c3d0c51c3c0de63a7aec54a7bd5776973e09cbd4abd65d48a86dff50f0beb0b37467ee387df5e977a60a1592babb97a29fa51de295d2dd" },
                { "te", "a046eb7db736a186e6947f7cdeeeec4777d5981c27be2e7a021ca3c21c684df84b2a4871d78769bd4d62596f90f6fe4eaa2d58ee2a68243b66dc33d6ae48ba73" },
                { "tg", "c946bade6204f20b7462644414c7a75f9f0551d2325e10015f91f04c031f3f53e26af101a3ae822b1bd1f3d95a3aedb31e9d79670e25236d26d2c76712a97daa" },
                { "th", "8feca47ab335669688ff3afc3d0b9827855f2f1e39c732f0142d9cc83cbde58ff8854ea08ae2fa252cb70950b6c92bc240ba443a44a32e4c052722b5077dc125" },
                { "tl", "7af76487ef6b92d4da39ea4e9c135bf93db57c258f0ae678bc43a9d4108d1d01aff4a038e027f0bf0ea0e69b9b9889b0cf1fa85c06c0bd91f6cb5da627f4dad5" },
                { "tr", "2734344575fc5035ed7aae8048735679b21c20b347543351f68f724568f7d191371fad2fc13fb336a829363570091faefb871ff42544b93d588f1042dc471cc3" },
                { "trs", "58a2edf24624815bf4c728e7a9e2a96a7476866aaa75037c8fc6f5b8b5c12f72a9751d01b4fd42874d2928c7e931e9966970d8ca4001d19757b32668507b117e" },
                { "uk", "4f8bab5b8216fb894ef845c4139efc88af9e05e06cb63376c6c85824b590b244d489afa5af97f9bcffc01ece1c745bb3614035e23626b4f8d6f0fed7f1d29a70" },
                { "ur", "991eaef0d9039dbfceaa9e4661e5d5a313d3b4d0ccad8926909da51dd88382d79bf20650299eeb301b3535d6c1a39e4fdf868d6310671fa5aa9d4b85ae3eb555" },
                { "uz", "6da780591df30d51bcae334f65f7dc10000bac033c0216ac4308c8ab26e80ba1759edf47365ce7cc2b0d8ce5ad40a9dec1c7cabe5f3b836feea5ea0c3cc56b16" },
                { "vi", "68fb63d17a140e76b79d04c00eabc83f5cc0517fddf1108c5afce9b193b7dd3d8ac0212d42aee72b27b8a38bb145b063ac0cbc048753cffb685e7d35de7a2ac2" },
                { "xh", "0511f4096cc1a65f88b3f888331d73e27ad8733ced84c5a3582021c536e2532d396209b9d70da98c8cf28a969b12fe9798cb85f729bb44c9137f1608fa5908f9" },
                { "zh-CN", "f8d713a52e5d5f2810b8904a319e77a3e63910ff3c481277102d650fe688a5d2516074a1e1f6bf2055e44e62927a09e3a57168298be3b31ef929f5adcb30b408" },
                { "zh-TW", "a1bc96c1b942f26553ab0e0cbe21088735699a0b0ae3726b1c7295f2e3712ea3f4988829243f1329b9fd871acd562de3cdf640ad7e84a6761836a6d980909d37" }
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
            return new string[] { "firefox-aurora", "firefox-aurora-" + languageCode.ToLower() };
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
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return new string[2] { cs32[languageCode], cs64[languageCode] };
                }
            }
            var sums = new List<string>();
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
            return sums.ToArray();
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
                    cs32 = new SortedDictionary<string, string>();
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
                    cs64 = new SortedDictionary<string, string>();
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
            return new List<string>();
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
