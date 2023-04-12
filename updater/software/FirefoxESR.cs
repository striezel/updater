/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023  Dirk Stolle

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


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
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
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
            // https://ftp.mozilla.org/pub/firefox/releases/102.10.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "06d117fcc14d7f5ce8fbf06cbb557984117cecd5339b2068455b4d45d066812380eab423efe762eb1d8ea160336c38f20224cce7e8f4a955c374403bc7fb45ef" },
                { "af", "18e4751f0f7c6b6b7e8b618e46534229ff9a433131030469e77bcb5219365f63e08540dc9e2abef2fe66faae2d9f461248ab29c4040f0ef63bd6ff6149534c37" },
                { "an", "5a53609d8faea89df2c6a7537659fdd72a85e155c0bc709ee634aa7f695704372e491b02e9bc8a42c5e7b14ce6e032f0c7475a1a0f0fce90c9a89f27611d1fa5" },
                { "ar", "42ed0050370989cb8dd76b2f1ef8786d16ed13c87c20faefc72c5809f7a46881f871ed3e50cd13ddf8b34d7f7f0e9fbe577158d1ac8873be924bbb98addc3d0c" },
                { "ast", "d2e676fe2246d1bb63fb780038cbfcd543afaceebf0fe7e77443042ddf2ede03a79014b6b21cc19817894e977f6ed9cd5158afb2e175131eedaa4da0ace2fb47" },
                { "az", "391de43d5c01617c74c39077803323f47ee09585af1c9c3c300b0e440f136aeb6df05f86aa01a41a38d586af491251fe92c70c98533519360c34cbef322e7ed3" },
                { "be", "f1f1a9812d258e0da94b121f513d8c186a9ee017f9f155a62243831a4eb8b227272f3b1fc26564c20e80611b9ac2326368ee6637d1fdae598eddd3dbfb1adc01" },
                { "bg", "92c7e6faa832763d9e8017fab9bcc76aafcc0df3df14d7afb8bd611ac2639dac91abf0e4bba37e0da75557a447aa54b6f3a161e0bc44b21554572019740863e0" },
                { "bn", "5dc6b36b52adab8ae68079e58035b6f9d620dd87a4c0fc3450ea9f2ae9ce907a09e6ac38e503b727874c9c3e1e0792f755c66e84bbbd66fa008efe1b46a37974" },
                { "br", "549f47b9e9beeac778348dc1187bb78e070127b760eb800a48bf64e40cb3f6d6333b25b252736317a87a4bad5aa90e1c388188560fb4e20b11093299babc720d" },
                { "bs", "c56032818137140c69a8b1250c8f4fc6efd7e8b9663485cfd20732146fab170c71a8c600f5bdbc9bf7d128fb6278e603df31c6f9c4a7f6cb95f2479286f72050" },
                { "ca", "5433cb5afadd0fa8d151212a112a1cfeacc3ce31d1d6a415112191527dd5ba744d2cadf3c186029e0b71cb510bf8dfd9d466a4b84173f729b4266dbcae511120" },
                { "cak", "a15f5e5a65a2875fb8eaee7779b366cfc5832fc247575ff7343e6aa96481f2c8a7ca0db0c3ecdb5610dd37f1ccacf17e2a0dd117d710849c17eb4ff40db132a4" },
                { "cs", "ff44fb38c25026269bb1c5afb18ab31356649aeb80171389d85e107e4d29d21ad63a03d91980c574eed77dbca3cf53267a6878009e390eb1d7cfb5e02c2ef2c1" },
                { "cy", "a5fc832a69ea4131fd1d47464f5ef3b574ba64fce95d7ead09fa8b1d12e3e085e8a51f9cbf9b723072ea859229e261cf55285b0359e813ded76aedf4920748e4" },
                { "da", "43dd1897d270bfd25fb8c29527922c9e26bc94aee3f216101888da11ff3ae7a6d54154527dc093825eb9f2570be62cbdaeb059e36f792edad71203f3e09dd230" },
                { "de", "ffa8acc1d9d7f51b66d6f4152913b83523b5b680deb303628c83338d9f861cac9ad84a0678a1d6c9d41d90c49534fbe45c5e945d23537f531ae87c5224fceddf" },
                { "dsb", "d7c16a252932355a4f7348b8162d6e697e21824977a1d23f3610f0a3a876c6114c2e928d044863978809e8e9f0a1b29564fb2048f0fda1a960b747f9ce441e36" },
                { "el", "8ff9c9cadf566ddae6d167b25c26c637746985aa3fabdc2aeb65df7b988e248cbd160e863071e503624f8a09d7166af3d9a7b883faea9fe5e66c09ecbd1ba95f" },
                { "en-CA", "4d794dc98ef3b8f4b1be065ee031271310c5978cd920edef26178ee1970c8726c2f1a181fb383796eac5f5e7f9d983477b785e48dfcb1294e47066fbd66377ab" },
                { "en-GB", "f33c0af34c7f82fdb964c804f780866021de92cace44ba76737d66cddbd9e78a678a1035b312cd68a478d24f8f9dcf1c905f8ef4be62c4500689d8ce9afa49de" },
                { "en-US", "0fc42f21a624973d3ca37599037ab6e5af9060d5f149a46150cd21a1876f6ee8de814cbe7730843117f9f7da9a4692f9f0902af7a8f6d9194a24638b623177fa" },
                { "eo", "adae59e90f6378aaf650111debac5dd7ef35a350a2a6a8ebed43ffd792ce72691f2f40f4fd00f18608ff7e9aa90af00370ae3dbd458e3e9c19afd596b392c040" },
                { "es-AR", "21f70f121760e17c6a4218a1e3df3b07669b3fb7f59c64cb573f6f2605af02f1fb2fb9d54f3ea148692dcc6b989bf4c51bc2fdd328ccb028621e159b171b0a3d" },
                { "es-CL", "0ae92abf90a6ea73e08f10171900f0ba212d2c91be339bb5b5717710c4a1ece89df910eee295cda22a9764a8412ab3dbbd0608ba2370fa9ce81588423ceb4bab" },
                { "es-ES", "505b9e9840a44dc9c46aec76b6c895d352642ed69e31b94828ef587d9da3190b0332868a6fd59ef7af2982e5e4bd51105cbfd0f30efc04abe0d75bc0845dbc47" },
                { "es-MX", "b21ad9ba3863ede7311d06a13bb358431ed6fd54946d62aafe6d64e1f746ac2d26072f91ee8df35a3f1838cedd256dd1b508ace7704d0ac25c4e65246bef06af" },
                { "et", "65391e5227be06f975f43a3ea81d4ca69990426fe03b1581c1581aecd279b5f843eaec4c54af9030e5172ba2a6bbaf77450438b41ee5d68d37f319d02bf73396" },
                { "eu", "77e52d3c8862ff31082d6a70f15b72756d0c7aaba325951856e572191adc225500c747c61febbee7f69ffd6d26e09b75fa337f8410b17c6c3d2c36db778bc157" },
                { "fa", "0212c69ea5477e91cdffaf4f97dac435aa1c88f1638c9e3ba1267595e470a7b904f2e6bc4bac9da15a59c8711230b103b9669ab25019e8416918a1e0a420d7c5" },
                { "ff", "2fd83bb112f3f3a636dbcc074ca7ace363ac66ae599699c052ed60e167e6356cbdba4e15a8926a3874de2886f09cd3d09dffd21395e64fc97d7858bf0118f1cc" },
                { "fi", "bf3a7485c513f3045a3de8e4a5af944087dfb515a7b91d4de3776b8b2b8dd5ff03f710e40c7d39d9082f8ad863fe03e56bae335d24aae8065743fc1fbf3abac4" },
                { "fr", "111eb7ce1039f93a1a1d3c1b20f61b8a52c37fb04b372d2a0dfbe1b0dfee2b66ec8ec60c127fadf600aa8edcdf646333227ff26b535a3853b77d4ae4ea7019a0" },
                { "fy-NL", "94d0602371c8ea0109a8c806aa4274a20baf97649dbf314c211808ca64a9f1756da0581adac9554c7cf1cd6d803e15f28e157386da626ddbcfa39410ae1e0569" },
                { "ga-IE", "a4628ae04183dc953396685d690020e13f4db96733165eaf5bde79fcb276fe4d2b6d1c36bf588fc392cd571035d9705a04a5de8e10435e04d89f8b64d4d3c2e4" },
                { "gd", "b0718b0c002931aca17cebb72e16d70739684fb305feb13ac3df9202f15a229bdd8825fc07686b1d6e12fb580332392cf211e3629463e923b13186298ff37ed7" },
                { "gl", "ff82647e4b360fe664a9d9f243bb6b8f721037a3ffc912bb25c920932a4672d8bb6e16537cba4bbbb9a9c1c48b4f8c499639a9c3917db7bf7d0f124a3208cc63" },
                { "gn", "47682a4503eb75254da09ef9ee9e06dfa0083abf1e667c02848374ed94d666fb2629976913a4ed6a1d9a01d1a28e3d7e57f3a02ac1d68023898a7525933675c6" },
                { "gu-IN", "7ac935aba73b6bae2ae148eb0d2c4b44d8742ca434093befb14d96682882b999df8f9cbd53c4b5f47e3fc9ff6b9dcecad5256fdfcca2163704eee8b1fc3c1a89" },
                { "he", "8e244ce967a62501107f2854db1d80bfd24c80c59c36b6551e1bf853db5f39d68ed4710d9e9d76049b4ac886abc5833d95654fb347e9aaf079a6af3a9aff7083" },
                { "hi-IN", "126e97ecddf1c5049ce0164d6da6c75c1cdbbd5a4ba4901eb539fd2c921deb09434fab04c81e06469afd76d9dc50ccff65a03ee6365052b45eecc2ec69fd6582" },
                { "hr", "f29bb4dc7dadf2fdc4bdbd5fcbc8a57b8c163b82c9db526227d3ab7c27c2f4c22b8c3f2927574ae9af365d6d7c4d148b33da89a647049988fe077207e172a98a" },
                { "hsb", "a5443b39c490fc27785493f76bd9c6fc64a373dbb147036c4a5950300d62b2e902c4a9cfbfc8bbae2517c1c0d6a8f510ab22068819ca59ae7b6bf7aed893a5e3" },
                { "hu", "3cd52c7ef00fe6d8deea6364d12a99f5ab9b22bfce2b3127cfdd059c087e311ed9ee139052ed13835655b10b7f2b927878de12208e66818637c5c06baadf6bbe" },
                { "hy-AM", "3f00f1ce81d92633c8f6354ff76a562ecb0179b765c69fc645ec38815d7642123104574d02375e43310e73e88078e4b5b969876c013a63d2233141b8fe7c1b09" },
                { "ia", "a0b36a8769c0f10384f87764bfde9318dd1d906aaf3c26f0af85b916da7aa6c17141db268edc96394004adab0c091ef3ea1cd545761e0c92476826feb310818f" },
                { "id", "60c287de505eeb84d2573341dfb9c95b8a2d8ca5287971cc0c07cf94b7f9f42e9b514b0157f3af1ebaa9727f8cea1ccdb8cf07bf1b2189e1b13b9b9fb984978f" },
                { "is", "e51baa4f8314f70ae55830991b57169ca2a175267cd77268da6fbeaa994e46e9a282fe5da8122c42ccc4ffbffaa929d54207438f68f08568172daa446a31d3e0" },
                { "it", "18c1a774dc3873172c759ca45a0dfef9e085535f6ff452975ecdaf59b9c374177cb161cbf77d4c7a6e74dad261166e22c7ea4012b2867a90491171c9641c3a29" },
                { "ja", "f1c9a3eb525144654f566cd84b68bcb950fb4cfe6eabadca5e0b6766ca17e6f8244d86d4f9cebf75e43118250877edf9f3e11dc7bcb6a38b2435bc490cb26d4d" },
                { "ka", "08a666dd8f34663f1334d24be497f63e7197ef418e4988fbc5cb1c9d8df766eb7b33acd0d678851f5885bd04be2827bbaae6a4beb3c9ebd97bee4b2df015e62d" },
                { "kab", "f818199eb288066844b34551cce736cf18a52498b8f69077804084992198c464b9b5d9f88baf3a56a0ec87fd2a4f75c1461c62c161c03c5bf817a451931c6a16" },
                { "kk", "7a306371fc2503b9b79e4c56f5d85cdcb35a072a01a9ac01b20d266385d9893986fc120b46bce29986b0422a14c6ab79d7b2d1b81b2da4b5d661fda0a2ff6fe0" },
                { "km", "2369450a92fabe1775eb692d6bc49ad589f81490b728c3ac374044b6b78e51a59374440101a1ab52ef6530cda214ff46ac74031736b28cab9d9815162d34b3c0" },
                { "kn", "af81e36e502577c6a72003a791f9175a41c74401dad38b3c1f8044c1e0adac7edcba83f92073dcfbb0377be82e0ea8abeb28d1b0d6160b15be4caf79ea71187f" },
                { "ko", "9b917d58c2cbc39d44a0c18d7061cdde04c70aa178897eeb0fdc4fd1872ac76d03bc2ea94575c2d3ec5f93c5efbc77972abd66a47c7c87c779f5e2545ba3542b" },
                { "lij", "39281c544bd6d3046aaec16518f6539e3d38d4955a573a18cda5c54235850b704d9cd8c4659c9a3ce37897dcd26f4ba33114a0fc5eeda62cdc8d0167d6e82c65" },
                { "lt", "49d7575c197db9a10cfb53e130748b98c51954c43b3553ba8d6dde2235c34fe1346477a8bb696b7ad4f9900bd4d6324f180d301a363ea97aea76b566e3e15fd6" },
                { "lv", "658e5a945bd440213bf497fc50038cb3acadb3ac36bf617eeabf080d4cd617825157139ee10a45047f0d4dbcd112632632a0a543173e975957ae3fe6bf9c6a05" },
                { "mk", "061fd50ce279cf348ed7ecc85cedfeedf7dc62a5dcd2ae7f95ab4d01b7dbd81105aa5db5b2b8aa980b7c7a819c09bcfe2fa4674a19950d7b5a9b9b75af636ada" },
                { "mr", "37310dbf1d288781299c59c3f46bed192ed020e6b7c09e6ae5f266a94badc3df80e0c8605ecc9e8d9312d045a9857fed817a99a685e71c283e58536872b9688c" },
                { "ms", "8694391159947ba685ee25aabf3446b7fca121481e86af9766f246fa04a321bd4b4425bec1e6648a527cf9bea9fa512752d305c25163c0f4e22e0c8b2b628c2b" },
                { "my", "4fc45bd1daa8659d1deec52e7b786b2ed9387ce19cbe11c7e1a74b768327e822c8d2d720edbaad76faf954253d6910ee3d0a47adf3e89ddab7c62199d38ffd32" },
                { "nb-NO", "20db166ff26a625152211382e4641b6b21861ff02aee38f83825bf7a289eb0534ae22882b9d509b954125c93c08aa60d3cb2843b8f2dcf9b640f41963c3ad078" },
                { "ne-NP", "51003c0d7b6ca76cfe69ac0ad345a75de324aa4ed1e9e867c44109c2af188524f250a2b3d0e07c47310cdcec7a508ebb45e71a0eb525a28619aeda667d4adbb0" },
                { "nl", "647ab1c38e81a210d9101eaf0d15a684e19858f0635000c555f92677fe7eee80d72afd06727dddcd40e66eadf69fecc3868b0e5abf78db957ffa3a950c65ac2c" },
                { "nn-NO", "ff0016978d42891e63b9a520c655536c08409ab57242e818abfefb7792e9ddb9d7051e3d1d2728a8c9f0c62429bbcdb8026823bf661a51f02ab5a32ee12c6864" },
                { "oc", "e9a455b87cf22675efc0aba91b250eaa9f92b681aba25c35c4549c718cbc7da8dd48d1c2c70219751b657c6d9c8f82144981dc3e7fd666225ea42869c6ba27c9" },
                { "pa-IN", "b0f9d57ec1fa2f7d269df8d03179c441e3e406cb911a659a4ab8b5d6e2f4b349279a07ecda4b821c7f2a5136444f1009a7613745a1ca8db24bb550d3bd4025c9" },
                { "pl", "887ca02e660b7a62ed3e38f153c58e92c7e5a8557730c1c9b57f75736cd3fcee6071e5c32a8baa39b843a317b449f6e9d178243a215a5d0b95aaa030c6c5f2f6" },
                { "pt-BR", "0de1246e9a90138750e7bf146459f9978453a7d4b1d1a67f71e5f258d7c63814125163bbcd3efb83b3484a49c76adf271b467a9baa4ef1ced59ed87cce83a138" },
                { "pt-PT", "99575d59bf53bef8321db32e961b757ef990b245a955d8fe4d690b1c987c235ead8a63bfa91ebfdd0ad12c1b45b7b201fa4d2fe5adef25a07fdc0640edf4e465" },
                { "rm", "16f8e7ccf4bcadefc819f1c25f4d3804c22e93dba43b9a2d5c3fe5c0625fe715e490c249d9bf7123ec7bccba122ada14c57c63ec36b3e84e85386800188d1d51" },
                { "ro", "b1523f877f01907d729d9446dc9200125a843fa18014f362f3a3ef649c813194156c30e4ff68fb8e19fe70b743c211b34f3e8e9a3f16f57e4597d3c7048e5665" },
                { "ru", "6c274a77dc6852e8aa263b6bb7561d16243881e33d3aead911888d3e4f37939ddfe034dc3ed1313479f7894710f5ef3e1a924976b88400df225d1e1d8f4cdbb6" },
                { "sco", "20a79a54d489f8f0d65054dc5435f43dd9e6a93a15bf466908443007910e9e87d776e02dba0f07b8d1a60c368e97633501c9bf9956c8f7d62d20837c645f2f8b" },
                { "si", "28e42951265d6eb2cbc5fd42f8ed570e995b0774134ac5a990ed0a85d1a530514f6add7649f39dfc233a485b3593ada22258292e64695bac1291e56ec02f9b84" },
                { "sk", "6b54818cdf82f0b7ec165464b5841e3e43dfb551f4355dc6b7fcb0ee3570e45c4823e207f9d6c6463bb7794c78e90cf518a97bb864d52b4e4ec7a19701788ae9" },
                { "sl", "c7953e3f60625ab14b0f95c637f81dd735cdd4c9ff21add6847cd056b198e2f03ba1bc92bee771e7419072a023aa1710ef7659850e62ad1581311d92134a15c4" },
                { "son", "14454155b4d03711a70c50671b66a2eeaacf56a3058d9bb1436870ef80d7447c25209d2ed05353ca900e49c8348d03faf9a2ebfe4cd8701bc79a8a9af4678659" },
                { "sq", "43cce904c439dccfe908d11738f938f3e1c2b056dd0076023f237603619bb05e434dd9bf53d1b0c3282d4ff576d716fda741fb268fd99f6f6a0ce1d23f2e7ab1" },
                { "sr", "6cd529a8b4e29a2158bf8cdc31b6e68f92c13090247a41c70b0cd6dbec155ea73067e20815d529d73f79d9999182a723c63cdd1dcb9e8afa872d4ca5166f520b" },
                { "sv-SE", "8eca9ad0ddd7d8a9737995df92fdfd975dfcf684899ae22e8b6b0cc244e06a7aef0a3952f2bd21ab318e5a68d143948194b30764bd57728300b12f811453f61b" },
                { "szl", "5996fae9f6d496789f14679ec8f959f64f33e0bf7ca990f323e5106bb0e5b94bcce63773bc35c5c0435022405276063290738dd20d3faaf4a6980c256f5e158b" },
                { "ta", "8dc2bc413a4dea423242ed688601f69d1cb8a9ceab11488d63cb59f2b281b2204ed51c08d50f55e2c9ab4e9446fefb88788580ab91dec4b7edd9163a7f211c93" },
                { "te", "65686c987e0cf74d5cf03b2ec8a026aca09c390d0e0401cde1bbb20785d9e7bef71669cc57554328ebbdd10a5c3442be6a9eff85d29388cf75c5eeb48921bb13" },
                { "th", "23b9aee1b47ab93e4c855d337d1cc0e56c9b9e098df20001ecbdb9b6d169723ebf1932dcec1116b469175f71cf55c35fe37bf6cb04a7b6ab36c5cd76a8476835" },
                { "tl", "8218723485a96476b8c83feba15c94d9742dc970a211b0e873d2a0f85e086c1be84c4196b8f40fe27d01242f056cdb9b72c5b3de09dc0d17cb8abcdde6a0e274" },
                { "tr", "07ef9f4349e190e68de9900973dafaa038ba98d9ad56a31d8f16fa91deae0ee693874ba6523f0edee958c6f807f56f4de6d6b317c8f7d8b836a1f79cd0557da0" },
                { "trs", "33ed6ef7746cffb1b436c67afecbff314b329f6b2e43d16ddd6a409f90cd61668c0dffad9c6403a8252698635fdfc2c45a5d825b2352e344248ecc3c29791523" },
                { "uk", "c14a8dc47302f58a6888630144d875dcf2228ed6021ce2dea48a0c9cd6d0e25258b8f89145d9150680e296ca203afb0d6e792eee7f6ad5d96054aba48d596e78" },
                { "ur", "13e436eeb01d120608f4720ab6e7d81fa51c4026c3483f3106758e5020ce5bc8170dac4d70f24fa009fb797c7eb6f1010213df2b2288487b832d9881a84a158d" },
                { "uz", "9d343d0ece7cee5895b73ff6dcfe12961723ca4488a88876e2e8a7a4188a99212f339eac0cadd6662f5978e0d96929e4bf46d3518f79128b5498b7b4f7b0473a" },
                { "vi", "41c614380f6e4f0e1af362d622e3fd1acd26025f89858f8774ce3625f73be02e802f2a3a2a6ecbf995c2dabab6c381da296ed1bc5cee8f35a20d751c3d73bd56" },
                { "xh", "c52399e1b35a58f30c875a7605b8d1d386b8135b75958d675a2eeb5226972dcc557749091ac0a2e290eddb3e794bf2fcfd2d4bf496e8634befe7e61c65f3f0b8" },
                { "zh-CN", "e661629462e42654e231de79fe1d8d97368239a237a21fe679038bc029130d333a59ec78b133c302e9e05641260513e28d386d26cb8f4fffbcb38f12672e121b" },
                { "zh-TW", "cff68bbc8feadfaf6ec778e3ccb38bfbde396ac83eeb3930d91ad131d5dd1f7343524a015e2e32540bf42d6b86bbb0193cd7d4159381f718d8a7c3c4d36ea6cc" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/102.10.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "5983b11a3c4feeabbf1fa0c1c8091001cf2df7c5d9ab0803b0435624d91a8f304892e38d151e97da7001c1510934ff7d512d5ad6feb74121219b5cde0754eb06" },
                { "af", "e6c3ae167d6bcc7e78b8f8d16f060ecf7d004d700132d2ab41128b185198fc9f7436e8d8242651a7739c3fc2baa9b947ab84daf488fc9ab3d20b985c09e30903" },
                { "an", "15893fd47c32d61b30c0d0ee66b8b9b802dfea05423bbc5c32d2ab814951ffdaafff6d2dcc865a92d029ee33c9d84b91f958bd501052a52936fa0cd64a859437" },
                { "ar", "be511850da5c13686ba8812ffecacdf9a5d403d87091cdaa8f2ab2f541702adbeb9c9b56d5dad6fc9a97cd99a2bea3a9364aba555efe9e9d2e7f5920a3ea519b" },
                { "ast", "e7dd7cd894673c2886fb45a551ea8220d15cdc5dece4f004b8f509b639f6c660498cfcc5a8f15e5d0751204a677b76ac3466988fefdef994311921a553b89719" },
                { "az", "64bbe5a4622e287fcd37aa2bd985981d905ce5933ee3e3dfbebec5b6ff4e9c61aa1b3b12f214943873eb465f490e64c484c71ac32da657e714b296bcc1f65bee" },
                { "be", "e48b3e43bb3c7ea8bcca39692d5413e72778e0ab724ce5f15e5aae37430ca9829359323fb3d3211153dca6a5316e1c07b1058f2037d258ba4db8af88397401c8" },
                { "bg", "24639ec21bf79970cd706053a10f9f903d96dc056884f3fff787721f7f66156fe48243f9616adb7d0ddee4c313999ccc68608b612d1e8795b1cfc788cbb0a32f" },
                { "bn", "b1b4419b02ed8d8be9bc33e8df2efbf33c389df2c89737b1debd723089c86d924754f6d259b367f4f801fc8060530d545209517309031054065c7f662c516168" },
                { "br", "e06c484c9cd4c2348eb18d5166900eacf536ef4826e3aa0e15cb28345a0a372f132315dc1e251555442e67a690eb2c1a6eedcc642bfb19e8b5df2e7887b1e7a0" },
                { "bs", "7134447d6c8e289af1b93bc5ee6227f966fd70df86a357a7262ec33e593c402e1e54c844a87e4251868a0860082252886ecc915e8d414d5893f3b2634e34f526" },
                { "ca", "ee585afb2a9031813b92ded6f787ad9f097d6c52eb3acb6ef97be05d368a585a54899ba8f0f74ecb1691cd60102db0a858366c939f8891f15777e9bf1902cc10" },
                { "cak", "4438ec6bad2a3156b392c1d9d8622f39972e5f31ab5fbea4509a01914f817bd0cc48ff306c48bd0fa1eb97d48c946f81b0722bfd10104ac297cbc4551d2fc681" },
                { "cs", "d9f5cb303820eb7b65e547aaaabea2d79e6f75f4fd4c89d259716abb3bfad4694660eb67f2821169451c38e45163c630138acdcb488a76f77e683b32f9ab029d" },
                { "cy", "7be9f8bca3fd92256b8d094e676bf1ea44e054443d7ffb2bc09ea0ff48bc98d0b27b1fc7d43bd29f4eb59e4c263ccde96ba47352be10903745ec3e397ab05fd2" },
                { "da", "867ecc915fe50f76da6820b1806a961dad507cf48482e2aeb7a64b8d1dd6a65e543d27c2c169bc32e516161c1ee2c567bcaaf0acbaab68028b182a84c866555a" },
                { "de", "c7044220160e5afc9a4ec4f24c50158c755665ff968bb4ff11e7774f8d83c170190f2fecf33a239a2790b52bb73e85e980e160f5775ebd09ebe9f8e1d4cb43ba" },
                { "dsb", "9b63a842c67eba1a4367ee1b9138c1d1824726894a74426fdcf8bec83ff033250b604043ef3286bd912747b3aa751cef97f14c9a8fa75a0788fdbfbb06fcf15c" },
                { "el", "55d628ed9edbfe917d6eb048f444db2313e4c7e860ceb935bf19a1b3719219f2c4ae145624ff7bcfd75e6299b5bbb8a4fcbcf49fdbc8ce6e2de742b818d4b5a5" },
                { "en-CA", "7681ba5b9d6f135df40f26d9231c80b47da6505273997eee442527b0c1b9936e1790557d174e1398e82f5d715d77147275335770eee4d934da1ab61e42de9e8e" },
                { "en-GB", "71e04226bdf5ff93844478cde3275085615807ded2c10989976ad31f1ed5123a250b7734ddd107a67c389b864ae498f2c18418cabe318e81308ca2aceb29aa21" },
                { "en-US", "930ffe9017352e24e44edebbc15e453bb81c990c3923a26d59f413f6de2cd6a42c1d85c6f1917c7fbb6a69f4a2d5edc7332a3ad854aff6b578d2218c6b282c9b" },
                { "eo", "d1b08ffc446c9009166980c2cb25e8dbda1f8df20c33045f3f45b874e8febeab55e4fe15452e2008df67cd5b0bd6b71ad03940fe2b142fbb4d389e9296a5dc67" },
                { "es-AR", "473cbcb85596731635f793838d979b63f2b554ebbe76ecb1365a9f4b0de9089855dc1b62714514ccea5cb378ef807cb038deae32c596d05358c57514a68bc620" },
                { "es-CL", "7fccebe0192617aa271f56ab9b8dd1993ca4948a8bd61aa853fa4a4a2efb305394810053019078fa31751fd44af40c9c32899f45e98389142aa9dbf7467ace8e" },
                { "es-ES", "37f43800484365337276b9c6a726a75513b3daf179d442678cd13900f0364e81a880302a24ca2f9c9270d0aee4dbd8538b8424bdbdab79b1d5fb0dac3876e1a6" },
                { "es-MX", "b129fe48bf45f0a28ec1eba42189f2588999b6b270047028a4ab4a8673f60c3b291a2cb262ea7249e148a6147752ad1a2a2bb3ce38cc987a703516e80df1c496" },
                { "et", "f1e692877a86516468f5cde5df8ea087951ebd9bb413e7175e4bc3aa8474a260bdf5e5c43adeabe13627f07ecdc115149f1210fe32eb60c427e4f55745b4b7a8" },
                { "eu", "b294f762de05056522b7454a11898be7c7ddfb858d5ae7ab606142241a394326e033cfb25455dead1275f82368a7aac99e7ef5a9379043a109cd0daa496d3236" },
                { "fa", "cf727c432f61cc4f23a1c696a75fa68eca2ccc50ed612d5beb89acb4189fa53c1c386800832878da43340af07858d0428053f42ba49af7e2e2fc80174f6cf50f" },
                { "ff", "6066b983d3194133c5e89e7e5ca0b08eec0ff505aced09de59b3a1a0032f656657cbcd7cc064a61f27e58d7617a358a766c6deac8e3c8391bcb8fd9e6a301ad8" },
                { "fi", "7ee234618c80fb675161096726c91b14db937d3cf53aa0a8b9932fa4f20e8696852a4be190502b5871172cc5f7e5cd7475164c8490ebef34b8a5d99d92c0af97" },
                { "fr", "b4663ae5084b46092c4eb97ed551b00e56bdfe26d1bae08fcb68e857868d29065cb338d0f4813116ff0af69687bd73fdca3d95fac7fac3a253050d5b4eea67a5" },
                { "fy-NL", "37a5b56d4ebbaf444e48e6c35b9a315dc183c1a3eb4436ae1a1c7a96467bbefe0d471a1c185f86084002d626eb5e9daa3784dd5a631cb0b093cfaabb5943d8f5" },
                { "ga-IE", "3c69b76d88221cbd22c87aa32a37f62ac21ec71398aff64a5c2909831c40e5316583e2bb2acb7d5872c46d2b60c06214c1cd724f9dc953ffd4a29d4a042e8a7d" },
                { "gd", "28e985c187e8bc14f015bec1bef1949c26770161d2d64b2f7fb036fcfd43e737669408cae41d14e01eb4318104ab4af87a1ed3cd735fac99f3232a8e12433556" },
                { "gl", "b4d3f3c7af28f49db4aa5fa9a9af4b11ab5af647cc5327af7ccd1bca818640332aba49fb893f51ca705dcb4391eb71a11fd0038743df475480c77d2447256167" },
                { "gn", "970e588440d75e6e47c5398346e3fb97ce977ef73319ca38661d510666cb894f47b841e5a43cadc9add9e0d092853a02efa62dbf71ec64b09d84d59feea4af61" },
                { "gu-IN", "cc27d414020332dd01963d94cde8b721f853606c44b529bbbfe724930a9984309e72d6c47e2e2c4687252b68eb380db8c2e4e8d62f377c162799bb71e7641aea" },
                { "he", "df4f117614e7f9b0e218411878a11d6480cdee63b0f228b0a54297a47281c292c1100edc4a1b48199e4bbf75bd8a2012ff01ecda93cd316a2b3b05d35608d845" },
                { "hi-IN", "16b9e63714d7a88d709d879de643d3d287479cdc316c640c97f5dce3c697cf8b176acf32e6a0545ca3b5098cffaf415d1302c5d6f30406ff42fccdfbf5459ccb" },
                { "hr", "3ee768fba0da2c0b50a290fc0a7100b2f5fc492acfb800d532bae10dd2ee959bf0b425aa781c939255fd11b887d4697e99b8b8ad6afd17d161c90411a981491c" },
                { "hsb", "3b31ab18910849eb91d8877de9d08e8ed8cf6756b1f88b5b5140c28082e74709671fc63c757d2e9b0624fb8f64c9741d98d50a5306d74a5e90d58679a0851241" },
                { "hu", "3ce2cb97e156ba747f9dd12f44cf95558d7d3336f940158850620e501bff5e1cffb506fa981007a8adb36dcac0a63d91784f96b34f4d768b040c450b1f87dad9" },
                { "hy-AM", "c55c66a445aace2ec7a38b7886b6c141ebed571134a5cae691d9c84f3c9431127550b20c7636d227f74871a43041de8f45c3973aeff5314c828fc5303328a2eb" },
                { "ia", "46c9450682692a8857570122240711895a3c4bd4075c6b0a8f99a22e708d3324c7450c0dd3489e21c8fdec07e1a5b00b9f1956d533f908c12dbf46de78ccb964" },
                { "id", "804c7eeeea2ea7bf96a128e797ed950f85635e6af73fe92d70eaa2c1ecb356b807ff8e91e1cb9909ed412057cae321607b6a6f2bea29637b4d27f6d33626e685" },
                { "is", "40814b3d8050fa8dfd0ffa78ab196aa9d8c00dd25d1baa16cbc39ea985d38b2607d2bb4f9579db3047199e4e20f20e9acbb04469fefa6127d022f32ca7cd0170" },
                { "it", "a073a9a62f5432b674a1759af5e7ed83dfb12ac41f2786aeb463d4f719494bd58f87f1230cb9df521e73fc738e67d3034ddba44cbaa536b8de575c4d1aae5c09" },
                { "ja", "423425620182956e4b28f1dc3b6efdd4c3f6fabfc60037d2a76e53055768d7345f363ba378ab37440d0fd1e8038480ea30fe284ae87296db8721406b4b741697" },
                { "ka", "e2b5886dc7eb0e3fbc639a84e3fd8ed75f142950d0dd439a2708125ec84c782a36b8afb235927cbe764604d0bf77bf3906b9c0ce0a68ae4e56b73a589271dc63" },
                { "kab", "99dbd108fdfc299a96e6bd7d4f8d3c5ccd0f6bdcf909e5a86bb7778ee458576cb8d65b3e95a1708ae6e0a92bb8b0d4c2d1fb045e60f042a1c5564f28d182bf58" },
                { "kk", "85b50afeeca7a23294c8b26f18bf7706dce6757304ab2909a557adaba8f04a25ae0b97ebd1e92ef3a6100048a4b2df952cbc9faed2373695889cda07bb52079e" },
                { "km", "f47e137f38c18ad8081f15c4846538abc9dc04a892045d1f266f9305f9047a7ab798515c5fc7a6d9d23b89019ccd775dee47ab6ed1765edc74cf25559880616b" },
                { "kn", "53ad7ccafe1b33061885bf652b095e4b50a532fb84bdf3ce36c14438c52998030b312c77cdc0a2d46868d96945e37994d8f9cea66ceae9c9e156d3fffb8e3bc0" },
                { "ko", "48ff8263d73f57ff2c0497c21caba1ff92a7dbe817ade3c476da882c4b2bb3fd828ed1553f46de5d6ac1df9085dd1d5c67fa84f351a7fe71f80f2278d5e1cb58" },
                { "lij", "50e43ad9a157aeb889fef20fe2e6acc2cdcb89c0754395511fe3d22afb9b8e9376e5d6836e23048e0ba90d77ee5d06b0c8f7392720329ba6f049690ccd6dd7d3" },
                { "lt", "5bb2bde34571adbc3671e3896edb177fc75e2cbb7df8438f2e743dc1cf713328e0e53ae849cb0fde16d7ac8886c65977c8dd636689b81bc01449d18729767a94" },
                { "lv", "98e526a9d32b93dfbe48239088028ce730abd002621343ddfaedf3ed06eb65e026cbd86a92e5abca065540e587b50c48a0bebbef85d010b33ffdb1bb3688f567" },
                { "mk", "9b881d359f84b79bfd3f4c594f0e1bcea01b9ba94d8e4caf85608e639ecdb45743a6f1e6e211ebe65c3c280f4d79ce7eebca4a94bde2dc9b08eee09329af79d0" },
                { "mr", "28e5d656c4d1cbacf2588b95aab0e4c8dd40ae248cc4f823f3f43541f89cc34273d70a36dc156105b12a65600d46591231b6a24cb1a5bd614eb6096bba59d6a9" },
                { "ms", "02b20fbbd7e25d78afe070059956eee8c24b53c5c33a65c7c06dc4a0d568bf19d079ab873932aa8c32a0a7f4356dde548788e549e235f0462c35600f8d8bf178" },
                { "my", "2916be58136ed2636ac6b957a51b268a3e4b43cea1bf9e646f4bf34b8756f9823ba7ca25508cb3b007f0271dda42e729294e1ec7b5b650896499ed2814b94152" },
                { "nb-NO", "c3d02407f818f19b6599cd33b58d9b085c3fdf2e025e69677d827a02fff10ca5b95b33525f104cd153c5291cfb4a39dbffdf07562946670ca8bdbc0d60bc4021" },
                { "ne-NP", "c22b6002cab9562a4d299961f84f858a7aae395dcd22d34dff3d1e9e1154eca848ddd064be20e3fa398a228811bb88b3dbe4ba2ad34c2c8b3e74eca7574cfdb6" },
                { "nl", "4a1c7e5a6e80919c93c8bdf6d4f3df0ba363a925e719b27c44db9920e21ad11cb21d45f02bcbf49b5750e80708e9ebef53e724062d1d63015cda17fb3c217e75" },
                { "nn-NO", "e85e08659bc5a9a4a24af22fe30b3f84def0f199c4f3a84adaf16dc4a6d82222feb01a5b268867d6e2a4ffd5369b3db0ad23fd979f3638bfc8bf0acc891f6aa9" },
                { "oc", "8be36d53a89860e52989c06d31e1a429968bef785bd29ba7981ff8c0a8aaa56f4c8364146ce4b984a3b25e88433c8af49bfc31d9ed4a329936edf1e53ee23c06" },
                { "pa-IN", "71ea284bfc72b0961ac0e9fd93d2355a633a1b60132f68fd95d9de4c0ab9b6608049dba7227a65125e22cb4e8dc18fd87be8ced3e4df31f5c41605990787709f" },
                { "pl", "0f3462768cc3aa8ada220d7b3bcc80011fca571eedc147f13d1479e2fe59d16a4d30177f954c86c80de1abd2787ed6d1612a62e2506212a75d5ec50858d0666b" },
                { "pt-BR", "6bdc5137469222c0ad5293aade9393518da066da7ef7542d6e475f5190649a6087b5624297f05daeb68554fabdac3a77b1b27bec32a10053b528bc55babdfd3e" },
                { "pt-PT", "71795a6685591d78252dc810774b4a59a49a92791516535b98f509011f12dd4adaaf68b8bbd452bc5039612e57734a7cf6d930dda3828eb1ca5116715df443e2" },
                { "rm", "1b09fe6bbf442d29e70bd1ed87990aa83b4700bd23ac06b3318708752d7b96c0e17ae34328149650cc8a57c0e18522dd7d8796b332394c77cb052338d4cd7dc0" },
                { "ro", "bbb128f344fbb8697150ba987553ce81f75c7ec4ffabaed5db1eced566f8999da7beeebbea1c3a17c3f9eb2c24278f4a9cacb7f02a7e5e0f7ca9c5cee9adf4d1" },
                { "ru", "f3921f731e9789ce373eb3b96505feadc08614d130d334d36fc113f72453b94dad84f71845e04cbb9b6ede6b308675b3ea3603596ab2bb2dd78fadafc0b2eb62" },
                { "sco", "11aed4c4fa2df5c2caef445d4a4ed19e2a100e1d80ccddd0db1eb0f2a8015653f81459bf79c3c0ac49589b144f911f8e2b6e3ed0e4ed23f2eeca5ec6a30e09d9" },
                { "si", "e5fddd3f85058bf3486c07de7c0f03faaa0c67845d7399190847619ece9d409971622655edd8cc7acc80595765f5bc000276d66e5834064c911a947ab3ac9f7c" },
                { "sk", "52c1598f8a62ae81c0046ce35953a5d91cf093c8c38e1b5cdbd56a8656f8af764a5cc31bcefd9c3ebf8d70a5c460fca34566c7b57e53884bb2ec5f07fe0c285e" },
                { "sl", "fbb73e76652fb043fca183245f4c353a2dddbf5eb82d745cae8fa8faba5a279f4f43a149ec7989fdf460bd7bfb55632370f1e4967ad55b2a25b4205c83f3f529" },
                { "son", "3d69661cbc83c2a0a72f31febdf5b2c1f75a3ba64671366e0510e52ddcecc33789ba3fa2cd92330ae1c8d350ebab05cefdefe44167cb44a1d190455ae83b49fc" },
                { "sq", "4e451f774d97f6d1a392b07e692dd4bef24777521f944ea6c8a9dc9f09ad4ac4c432af6b6d816bbd09812637169484bd6f7906e5953d5ed63f1deac0b2db26f8" },
                { "sr", "e079a525b817d627024dcf9ae118dd7c5d1953f8850045512077334d55b923b2b91840f90b0576f1ddfa1ec9229acdea0734d4080ac1179bda6629525c2f0229" },
                { "sv-SE", "15cef27790a3d9f815f37760b90d962196cad70f1e2db9fdab57bbaad9e264bd6baa0145ce4a36cc03733c0cf877f180b5e689b31c13c226ec523a0bd4da6897" },
                { "szl", "1cf1add9b034bb3a4ea7eb260b3635ae492a36c3b7116fc93f1c40957f579d5a1e3ee0d0169fd9a8a9814ff0a9f863238b5a75df1762b2779d47ead30669de36" },
                { "ta", "fea472d42c0a42884be93d5aefbe701ea1469aa2cfcf7bab56071d3307a25f422af6ef170b7a4595c730f1e99982a9e9afdedfb577f2e7ca8a9d10f690e101ee" },
                { "te", "cce0be2fcf51d2d339bf93a686de5bba2a1ab2969c072adbdeec3e84d91b295d2b719d5197f27270ac55502e84a6db90510ebd6cb3109a2553ac6d673d5b9d53" },
                { "th", "0f3f3750e70178137f30bbdd13facb2edd86cd63fb9c24fe1ea0c602cbf64984cac1205b906626b8376f6bbfbf1e7662c8b4e05bdb1ddfe7415af613b0b502a9" },
                { "tl", "01475233b50304cf6ccaeeb37c87cb3f3b3e8cf33330690883240ee9c8bc9d42c7bbe166be13b44115d3de7f7cfe9e453b00612bd3ab47b809e769d51a8f5931" },
                { "tr", "7a3c9b0a46d1a4c5616afee359a020e48780a79a9acc4977a20bd1c9c1c7298bd336bcd514d04cc1bb8ee4841ff57cbd420115ad0609202b9572f198d07d37fe" },
                { "trs", "9a2cc5fa3f3e2a3728f038840828728242ffca0e4a49a724e1c342e9576093196e0da6c5e52ed1eb03ce2479e4dcc2c15a895337f08812788aa8cff1fe924594" },
                { "uk", "c1420b63b90cd37df046c14321b38ec8f4ba92500e70c40b26d42b7dc73b1660d783035a81f8c161fe760ec1e7592bde96063742e0e2b9f23b6635a2c4e24933" },
                { "ur", "e511f55b37d0d2bcf4d309a65ed6b04c6ae1d5caa454b1f5b0c20170aa667d94f6e35d2c8742b91117151f500d24e0888f58988ee4bc5ff650d00e5c88269de7" },
                { "uz", "d8ad0e2bb9f5004dfeb72556ea453d79116403ce3482e72e249ce9522b8700c8505dbe2973bd42d0b4e21062ea2f99396e243a49bed4d2c0b1a4d743a173e4a7" },
                { "vi", "d5acbc584bcc2fd11fae94fd82d0521cf5d36961e270b27d236d0c3f565f244c1c9b838af9da00873208967a0216f62850138abc52149bfec76ca615a61fab89" },
                { "xh", "901a08ee44dc7ca0f2963a545224e1275ec7962f6df2a3727063f8423c4afda17b93efbaad32ab4be94a57174378741a936cd8729dbb40bfdc6d6bf1d04e527a" },
                { "zh-CN", "9327004f7e39b09c4fb5aab884c031503b57e4b5a98c673630fac051ce398d776d90d989626acf44b1c6d4c83f973ff95eb586c7fcbcf66ffb401cc90b77c6b9" },
                { "zh-TW", "c365aed308ef810fc5b6f421ca06c2660c950b451aab19b438573422fd70b8a8154de141f8bc823a20de30dde5f3f47b35d9783356679cb80955b258e42b7929" }
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
            const string knownVersion = "102.10.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
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
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
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
            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
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
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
