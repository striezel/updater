/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018  Dirk Stolle

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
using System.Net;
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
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "62.0b15";

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
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains<string>(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            //Do not set checksum explicitly, because aurora releases change too often.
            // Instead we try to get them on demand, when needed.
            checksum32Bit = knownChecksums32Bit()[langCode];
            checksum64Bit = knownChecksums64Bit()[langCode];
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/62.0b15/SHA512SUMS
            var result = new Dictionary<string, string>();

            result.Add("ach", "fbe997e94d1e7b4e615b1220713362008dc7690ea1265b30c8860150b75e597aafc4112d9758b87049b8d20781d6a4738b3184d9c6467257caff0fefbf8d6b66");
            result.Add("af", "f4f843b8ce131427aa48fa875615d7c25f3fa74b055d18880e0e3e6f81ca89e9aa96822db187fba88bf2fdadd3d72380953838fd186923111ba98b479dbca6d6");
            result.Add("an", "41cc6e9e10681d4890761c0b0eb080617f55072cd351cf4eb1083386a0508ca0139c90bda56af79dc01da3377405cc9ad4dc323f15b8621e74b5500a2baa7332");
            result.Add("ar", "bf300687a5c3b1c4411c8e4d7a25d956e6c2d16463580799775d2d6247e5705995ad172bd685c7ba3fe754fda00d09e0bf7052058469976179bb9cd7bf9f03cd");
            result.Add("as", "0f0e47dded1debcd3faf798c7f6881112c413651f7305b5ddff04bdd4f08914982b7f2c5255bb21e65da8a7b96628b8aef968fae0b9733ff8d3281b0a2aba9ec");
            result.Add("ast", "4b3fcf5817b3eee1c159ca149e00ae0042fa4d8c0dda78e50e27f0f44ad13d8084f231d879954834dc9b19892ebfee3668b430cd86e00f5927601cdc7701ec44");
            result.Add("az", "0d6e788cb4331421d5db7b3200007c89a89fa95eff6898f4e4d22363f1978d2acce555bc5c42d5f571834b8d04330e81108a34518b08110fa57705f3d4f8d1e8");
            result.Add("be", "895b2f433b7c5f36d5ebce86a03d74d15039de51d2a7ddcc155dacfae17469c2ee0617f747af3b189e140c8c014b0564373c216b58c2163931ba4de3e8383d5c");
            result.Add("bg", "4f15dd25924cfdec33a6b7c3ba7940392edb37c54e88841851f9aaa974e24c816f7dd045f628ad0a0bfb5eec65575952c7ed792df2c0e9abbbcecb04e1e66705");
            result.Add("bn-BD", "3a667c877aee31016c720aefbcb63b03a74710af37ca48f078fbb977f777efc826f3e9757b47f29c46add0500f4f6b6ce3274a088a8f6cc6ddb61ee6f60d505f");
            result.Add("bn-IN", "faec34175a194ac98c535f93b67e129fefdb239c38cd58ef0619b1ed2d35a1f13241b83ee845d6330986365ed9dd33e2d01c02b61efb15e662f830933acc0ab5");
            result.Add("br", "7666e718aac808ee28649c24cd8f7ddad1beb8db85db52685339391745da68afb4ab854eeb66fcc0d3ec9cc5f52253c987c72c29d8e1ef81f3460eabd38786ef");
            result.Add("bs", "bc8e6d6da859627c7fceabc9b4fd6d86109d16d33b8ece44b1b72d715665cc14191cd015ca25daec4368913de20b9a0ef14c1838275947a8aa772a6d34a25846");
            result.Add("ca", "73b4787ed13a6e68e04b68e42732d5f92eeedbc3d7fe7eef583757d37f552507e500490a32a293bc785195e7dabebe864724db74d933fd7712698740e7639a77");
            result.Add("cak", "9d9537ebf64ba848dc32a8fe4e6e8c446ef80be1145c68ffb405e2b0cf5e0695753402c13d6e91e66ae4bc0aadcbae0f1007fccf08a00ac0acc61ad491e21193");
            result.Add("cs", "1a2bd5706f77b5978dd396ce9d8b87c95c7c6d4d6e8153d9fb47ac1f25b3ac70a40f1d58af10bf2123de001f0dae67d477151b8e68c2f1c40b88887bba31795f");
            result.Add("cy", "737f6e5f60a6a4a44029e70ffa60c91f6173b6250e3240f4860ce7184bfafd7cd6d6cccb7ba95784b9a713558a214efb71d71f6f3bc883d3bfec7096bc19fa78");
            result.Add("da", "0141bbcdac9d93cc1bd182a27251dfdbf88ca338bdda3e3c6dd92f5000c9778bbd7efa9cd8a825f95b66d9deff78f1267c3718c7530e8206754f796368af2f71");
            result.Add("de", "27e0c2a9c7f871d09c2ad69e121a63a843c87307d152e0272d650cf29f6caeeff33101bea3947a649c4b83b31b60d81495c3cb0c162d26209372dcc91c60c0f7");
            result.Add("dsb", "d712c147d2cf7b8828cba33ec018a08e07d64d6b21fecffed32efc56925ba059006e3e0397d207e14f30b1e94f7c656e12acc83ed8202542e60fb14ac07c2246");
            result.Add("el", "2a1de14571117b37c34bad17a91584a288f1ea3f388b744455d6e42b0e9166bdc8f941cfa7295913fca58cfde69ee620d8e8c88fb6feb1d2b4b3689d16e2f0d3");
            result.Add("en-CA", "ea6f4578aff143c63f520134a119a0ff43693dfb4cac011f9c0aae61357b8967fa9922e6398a7f698efe4cecd1b8c6f3f692a5d069a3e212f3c19df8207b8917");
            result.Add("en-GB", "3bf0791f7a44a0be89ec553d1e4bc08b6daf568bda3c29d930ef9194f525fb5d84ddf332307fd6f78291b01dc8bb52ae3aeb84b0f47f15557e215263ea0a7313");
            result.Add("en-US", "0fdb1325c7db3cee4ae2e5a77fdb6faa98bc5d1f2fb313834968ef8e3caaf08494744b97b661721801fcdfcf0a0eef267bce434aee53a3dce9f23a61925bbc14");
            result.Add("en-ZA", "2f4e2ebb6b30142c25631b6b3774f306da587d60eafcd62ec6349644aca58e2f7de7d5c43ac6672d1bf5cda506986ed1d73443670dcf60839b186a85467d6e7d");
            result.Add("eo", "db7c5423fcc26d6f014fcc993dd554fb77b30f6cea02261af257f295382f285c5ed3b107f7d9703edc0f4d26ca246ee76a5bf3e4e2ad72ea4460c9b78fc499e5");
            result.Add("es-AR", "018ac5cae0b330d74385a5e1998b71374cbebc0f087d7bf2a3740c079f9bbee88f583be9ab8b5fa2db7f54a9d152216ddee0b2f0969d9c3fc24e82e1b4aec226");
            result.Add("es-CL", "eca81ceec3b6339ca6a14f08ad5b362d896001be071a98201ec4740f3c07501f10264cd8c682c8b8409144271ac5b1346026c4febc56d3c2f09a1033669ea3c4");
            result.Add("es-ES", "bc3900a7673a5181fa2abe87d537b8c6b433e69159247d7a45b36c4ccf4e48ea47a547651fc71d033af7cc605078ba0a909741e56f129dcd26c6ccb725ca0306");
            result.Add("es-MX", "ca65c2bae39c4ce6172c042c684b0ab1dbe3fd7065ed678d99456e2f1f3eed72ab208b797a59b8bac73519af8dbf7cb219424524a71adee483dc405bb888d504");
            result.Add("et", "5ed7dea22b9e1f7d5636f92048e860eed17c2cc27e9133c4b896de79f1936b6b3ae200e1cc2b5e4e44202dd7c9b48995ee8c5184f5896a040d66df13ac7d2034");
            result.Add("eu", "a7d8b389601b4a073c740a0ec80d3b00eb3cf0f458396032e16150de4849c5487ebbe3864da080801a182c977cb88c90e27cf1085d3adc913013a2ce8d9ab1af");
            result.Add("fa", "9ff3346d541c962589729330e6aa2ad3d2f31bb31c08b17b3636f54e0666b9aef54ae88e3d5fa40d5a8b3c1a28986341b4b544809419619988c4a658e71d323e");
            result.Add("ff", "de07a21edd3d2411fa8a5936da4cb93eab6f9e3b08f931e6106d79cec69e15f476e960b8b14237aa876f06e6f989f79db9edae36425e0ecab3ef171d90ad7a20");
            result.Add("fi", "5c3952bb3946da754b44583583e4992b524ca65c399588f53877a69e333a486938743360f39028692c27b86d88b7798d3c02100349cdd87cd34290eaa511fc1a");
            result.Add("fr", "89df7d5f3996c837ca55a97eeaccd1229bd2c88a6ff45a6671fe00afcb62891329bbaff4fc8fe149185c31008ba7f5314f4b07d2f3ab3f1dea044e4786be944a");
            result.Add("fy-NL", "c948a64ddae2cd5e2dfae3b6311ca0a360d9424a4b78e81b29bd2a29fefb99bc5ad10b6a3ba10deabc2fa6b375f872ccbb606da90d8d723cf66ed48548fa96d7");
            result.Add("ga-IE", "bb4976c14ea48566b3a404d84949dd5c75e828ef743b144ebb4d5e2cdc3d14578d50350cec7c7cfd94108e5b34dbad4a19f96eef6e373ed0f44e93b953af9c5d");
            result.Add("gd", "0aef3b605ec797d1d1c053e231ff1c809e4148725e9c65f2795d2aef26f69dfcea175fefd37b38a6758df60fab2167c19380021b7e660f33dc339422d8b7a781");
            result.Add("gl", "a21c1d78455f5acba0cb243ae67ddd81344c3748677f56a56ae2f6813924ec7d35e3b72af20c7c31298e3d1da0ee94e6bc243ee660dd5fc393d2162f43327144");
            result.Add("gn", "ff353cf4acf4e2020fa3a566b35d9dee0e5c40a4839e2222abcaabae4438173b8c4f39c20047c5fc65c34db94b5cb7dfdf511fa4e4e743bb4358bc7861f519f1");
            result.Add("gu-IN", "65d8e9a3b03915045e479393f6d3a3283a2ec9d14c721b894f6feb97a639982c0802d9c2df6230d18323b3bb303879d1d1326ad6f4bcba13567d82a33cf4fb0b");
            result.Add("he", "3f55820a557ec85ce40a64e51bda4c2faf31a5cc2d288be94eb0540cb3ba284ee21f7050b2e3bbd22b4eb00e1dabeeb50774ad7b7aae140e4fae2b928846c4af");
            result.Add("hi-IN", "815fee1ce85e88f33a03df1a566a1d2cef81bfaf54c967b513f349b5634f88f2877732d43ee9dba83547bb0016825477014109d6b6cb6e00fdcf8a78dc6f5761");
            result.Add("hr", "3ce16cde18b762935df413ad6b1044cacaebf5aa66a3d5cab50fb9f70a786325c220b2bfa3c1e66b15ab1f8b96986dba9cce081848158faedae3bbf93e81dbd7");
            result.Add("hsb", "8b887e739ae1317a43d7a7c4375f6c056880d0dfbc7672d9dea5b409014d1858e9007947da8104a89f18964aa8998d84cac335ffe95335d1a5633fc23245c960");
            result.Add("hu", "e79d487c44074e0eb4817c83ef867e5020f3124ed09f439196752b496302b4fe6e7226c58c790d5c8b0bb808194e7e65acf18c08a26345344cf196f1ac6ddbba");
            result.Add("hy-AM", "bffcddb5b16b9bd92368aadd4aa95c57a61f58a6959e90852f611d1c4fbcdbb6377b62c9e46a02f30abb33dc3b8406c15eefc6af826a6f8e720624c8ebc81205");
            result.Add("ia", "8665da38844f67bab8b19520d61178ae77e2ed5a35f9e17c29b13d46e5a576f3b8238d78f8355ec46dd6f6214bde151e252a450bf31033f07239fcd12d08a2e7");
            result.Add("id", "b7e5913ab26b11ed965d5f7ecd75fe21cd754815c18f5b01700269900c29a8082dd45a452376c079e213d0751c4d84204d0329233cf65b5cdb1b90dfc593de15");
            result.Add("is", "be3d9a28f54afe69ce25d8ac644ca2d1c77100216dcefd40bfa657bd00a0c738ad76a53b60f82eda2e8a7c77f9f5b1a579381aad33358a0ec4f733593b9dce03");
            result.Add("it", "f373c62e648e24a58ebdaf00cd4f2d117a01713395ce3ef40dbe895da00ec9504fe7d0f15781d7a482589cca1198a139f8e851a5914628061421e43c3d79d4ac");
            result.Add("ja", "58c34661ffec20bc15e4ded824f9e034cd527deee858d7b4934d85763e1b4f43d8eab45d4fa2abf1169a98c5947cc06241887ab8e94b3387c5819088181040d4");
            result.Add("ka", "461107ee37318f5b2fd7227466556be998caf26dad9af523d2127a5a0bfd3c9d3fb9bfb6580fe25a26df7708e01b95c29bcba55c1d44ac22c40d2d70f617b3ba");
            result.Add("kab", "34dbca38681a82321a641ff38de57380b5f6a082b24f21a7d5767213677f76ec7db7ad50d62b3094d73cbc94e2a8d6191dd50a61c8351bb41d30c4db0ab8ecdd");
            result.Add("kk", "053eb4b4ff095c4044ec5dead07fa5d8d0badf0fde1e154be35742f70b03b3c62316ae105dfdcc6ab8d25e746f5388a73a98387a72209b4979171ada35804ef5");
            result.Add("km", "374919a03b1cddbbb5f3d562d97393fda542651e73f70a73b37efbef8ce8c0fc59f0b83c047f0b05166cd1775d313bc615397bd298afb562f82d2b6c9d2b761f");
            result.Add("kn", "6563711bddb8b04fe35f0576a1ac0bb4005928ac00190d095ca0d442b58a2a6221662034cf9b969829f25decf753171c90d897bc843f80c4eafd68b07b2a51f7");
            result.Add("ko", "311c2f5cd6725337555a53f00c2d44b469726c19523878d981660f7de1a421121a4301b8d407ecb2276132306dfe650feaf6281df0f78257187b6128f3abbc4c");
            result.Add("lij", "0009b39190dc864a2d4cddfa3d04f2f2feeaf2e5b0932f2e862e06eda249a626564e820eed25df5a4aad199e1d53e852807c85711eb9e837f21b826ceff22185");
            result.Add("lt", "0b425d6fe1357c70c23113181c5b86bbd9cbdf740cd06eddf300a44f7a2870cac064b16803ed63ec6653cab359179553beddb0a959be8ecfaa10c4b547ecab01");
            result.Add("lv", "213c4f2ba5a7d89582d6a792a124026de320094945274943516b8972e64bcb90e01f9233f44c15896bb2e514f24cc6409908aef48fd17d48a700f1acc91188e5");
            result.Add("mai", "1b628e606a0ac6df2512cca92140410d35cc70c92f9f5d7cfe2e14814b1b05cd57892f31f934de708e7545b76d6e20d6b1f44755937e7c8e0f5cc8e72eb59980");
            result.Add("mk", "9f1957761de6112bba87b93bc3786c0100073fdd789c842e387db2778f5dbb02e076b5a1f74ff4480859c4b7ea21383684e2e95068150886d1d3c2e40d30fb23");
            result.Add("ml", "f4792c7e4290581ec21d1e70f7581e4ce8b78ce113f33c7de55c3ce1aff0f651aeeb4bd6e22d34132947bb80b99fa50f299b34c17625347d1924155a839fd25f");
            result.Add("mr", "d2eec0f29c30cb13a9357a3d082e689c0df5d5b2dbef6ecab723a8ae18ce79fa15183c6c25a3c3c6d01b03120c9ca6508d3bcda9c58533c4a8df6abbc8922b34");
            result.Add("ms", "550fe69a3c1cec211a87cdd5586345e506a424dc4d681df9f484f4fedecd8966304f6936265275059bca8a68187b9b5b548130c7af9f8d0b402fe7e1ef6a1685");
            result.Add("my", "17235e24dee580f4becd025926e54d3f3f7bc75a2d229d729d0ba3e92fb2622d37ac03606b4e25829aa9072d9432727da5681732d21577f1e015e4e62dbce0b5");
            result.Add("nb-NO", "a8bcb3e0d4cd16ab17650b1a3e6458cb0b7b5722b301f87a042cac773e5135e20f2fd0807811b7ff3a5d73e424d240897bef8764745e766b25356fecd3d277dd");
            result.Add("ne-NP", "139960503286b30faed664156ff7b523765391e283b2506b2a6e664717048c227962bd8c86c6ce166551fff36ce2e1da61e4a9569c9e5c1a1f37d2041e441204");
            result.Add("nl", "200b31ecb67276bb250abf54eefb5b3a9329619cba084095b9f821fb11a20669d3f1d64039f715a939cc9441e5152c95933e0f17a93ea445e03dc84cb888e566");
            result.Add("nn-NO", "95f295323962132fdfe11474667e1555a53d52a330982613eb1a4c58a9752537d1105519a9c4fc30ed61bce5ceea595d2353f7f8382448bfbe1779886f68142e");
            result.Add("oc", "38d48a9fb649e76efb32b0b05d1ade923f74f7f171ff9777c620292b6d496bbd39a5e40989a94591d75282cba4df6af8c7ef6d4a1794da7172e44bc31ea08cab");
            result.Add("or", "3785189f5fa33c98e0b4e91e249e19f1c4c1cc581968ecbdc400eb85fb8cfd55d3a0a3737518c1f5900feae385d710e2be3ec6e735281fd3140d948ee9dac904");
            result.Add("pa-IN", "59ebb1a694693aec10ea94db782ad3c49e601fe06ee465a051bea43af85800e29b719f0d9838ee334b85e2673ca1f1481c3a9ab4c843b23717319ff510afe32f");
            result.Add("pl", "b5d2559258dd5a48a691dbb50497ee1c75e7e57ee24710f735cb434bf1b7eda79c330b66d3b628759a3064ba8691dd9ae4cdd29986df989b0331929b33ded8f5");
            result.Add("pt-BR", "f03e4399ba8bc44eacb8995ac04d2b09553e5406203ed4d1475ed7ceb9ae1eb22b8fc9b620e693533d0529388729936ee5f642555fb4ec0fa6a5c884dd79e253");
            result.Add("pt-PT", "7c72658a9fc0ec610586073505a278ae395b283a51123b2a654ee52ec242a3068c30f24fcf04f1ba4b0f52c36b97818b7109897400ba9856356a80f9b49bcfa9");
            result.Add("rm", "3d3997186cf6070bf32a45a3d38e919bdb216b086c5dbebb86bb31b52ced14a22dcca595de1319b29f41f77dde2cc63b368d883a3c0c8fb4710fa2be05bc19e4");
            result.Add("ro", "1a2fbf28b0a33d416b038af0a36e9b7caf855c6374c56d72196f553f0767a2408555ec005b9ca3f4163007dce6e34f4e4cb641c443a12d5dc128e5273dc79ab2");
            result.Add("ru", "f02ddc6d526e3fdc60ac0a62c868d175e47026ac09b722a854f0dd82a239d714c077ebfc0ebf585a43943dc614230086b5d02716c1e76dc4129a7bb74e15a8d7");
            result.Add("si", "f9b8d3b4b7ad186fd14fb3f53c251218fb3c0755daf57cc9428afa30fe43a5f27e53ddba26593d0d02fc3ea9fc67e2e2aa48b778ff69b64e0b0957b24fec30f9");
            result.Add("sk", "a14ab81d5314dd47d1e22a95dac6e91a31f4c35624f1aa8a8d6be512e8fafe4f64db80234a4f55addec966fed9fd12435fd3ccff0db814ef761a7aff14c5fc88");
            result.Add("sl", "9ef9510618ee8d7263b99a53bbda53660e04aee9cb1026854a4ca12a3f47b494f16f40a50e5c9faca1191ffcc49c1a390932d80bae128cc2740f57447bd0482b");
            result.Add("son", "9bd856b686830304d02fc7f7b9d202c0e691ed76ecf2a4d551e71b36feed0f6a43edb67763cb8218314a3e2332e2c8899944b7269de1f96f1119c9c506368744");
            result.Add("sq", "43aa0381237a2aa998022ed0e9bf6dc6421b64d3ba5b40fe662b2a17d440c69bcf61716ef4ac032ba316aef2e0e2eac7af280cbf8afbff0e4fb6ccfc1e2765a3");
            result.Add("sr", "34fdefff3cac4f7909e62572b3620538cb95bf11ed82da9f701795c5e7974ee355972bbddff2f848d13ba8ad75c62480dd4f2483c45bd4823860f70e211a4f38");
            result.Add("sv-SE", "fc788494dcc8b95bc230ac45c17d2d5b08980ac3b75cb1cc4ccfabccdca58cce510b0193d0f42f766e764a1f9d138f5851913e672368a9734695a973eff037c3");
            result.Add("ta", "239c13722d7c5bd5fd5fbab2c59a15ccc6799672a5f3915bb220198d8575aaf4ef99cdbf34d6a57e4716310cf8f9a0f3cc924b5cb6e81524f8a3f0a615331794");
            result.Add("te", "447cc032cb369bd53155d3fd710b87b381925106ca2085dd4441101c7a6ef5945ef1ec10d0f706c7e719d9ba150ca43d5ece04975b5874d38b4fa58916721cc8");
            result.Add("th", "1760a82a7efb018feeb0681c68a7df1d767a7a5db4d1cd0c1ddeac22276e5cac1229a4faf1354891a302d62e2f304caa66815d78c80a77dd0fd7bd9e0aceeb8a");
            result.Add("tr", "01996fe173f8a25c6568ca78441a704e5af6c733cef8f2e6b8e538f20a37cb26b03a350250be8bba9484783527975d26f63213b4b36a82287881235797722f7e");
            result.Add("uk", "c408a5296c887647c0e65ef00854e8427641f93ee58084d0bd6bdb58ec5d8f2692b2eae43b5bb13087a6bf565512e4406c3ed8f6777a9df2546ba1af378057c6");
            result.Add("ur", "c647599e3ef249b58e2f9e6757ebb50bd88e4ce89e841d1a284aa17693bc75602467ed7ab48e261061e0db6599355428abd32391493abd1d2c27af0b30cc4632");
            result.Add("uz", "f501b5bce55e8e5b1b179e7de7277437b39fc8ee50310580c81b1805c2ca5caa568a1b8343d492eb269f495f29aecf32fbdf33f85bc552f1be3ffa98bf728a99");
            result.Add("vi", "cc96e205b1739e31720683d65b7ff92b48d57aae0469b2bf71c3e0aa469f9e57ee2c938053e940fdc06e60a0f814208bb825cf7148d5445237d1bf7852f6c8a5");
            result.Add("xh", "b60ebfb3d346d151e182a817f534ba35d8e2c61b5ad5dcf1a886b2d7fb34fc11c08a4ab92940374e26c6ee9edd7174a50a327b74de977d8bb9e35321bc5a3bdd");
            result.Add("zh-CN", "c8d504d139e26d4ebe579c25eccd5389e18e4629064b98b785c45abd2802e1bfdb9afe6bed025b2e5ff63a44de24c94954c57a3fe5f960463b2aa3c006553562");
            result.Add("zh-TW", "c35c067ff6ea5be92748ee45fb4cd9f54231c10acd2cce780e71ed86dea9b4584a582304c1cdfc492b0ff75fe93fc235854fcde8929e587c025e915e7ade986d");

            return result;
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/62.0b15/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "a2a11684ca8ee993c40092c3baa76da4c517544f2bbdee2f46ed26fec227cdd548c1d81d91da2c744f7fc96cc26460c1669da9785318697dc1d85ae478d74ce7");
            result.Add("af", "91b9498fa87b29f2893dca17813b2b02ab7d0430e6557725f2ec708e0ab8fbb8bc5d34a4e0e51b13a82e2449fd05de28e42ae086151f1152bc294958567c27a9");
            result.Add("an", "af10f6eb8913ad6ce0c0c4a99409aa1d5acfbaa025edb6edb0fd988639f9164aeb6871515ccd944950c9f07c11fa971944c3268e34db28cb1930dfd2b3164c62");
            result.Add("ar", "311473e098e63c2464e7c458e05a70d6194da0aa7afd8a7cb15662a79cfdf239dce9aa09078b73253f73d3416e33774dcb434e941838d62f452b3c582da8b734");
            result.Add("as", "235e821bfaa8c8628325e175c31b8cf97efaa430a10cafb92de65dd726963ffb8e782097f73fc9fe455d3eba427f119e9c16d102730304d8030b6163dc5d8ea9");
            result.Add("ast", "e44ddd413dfaa950de88b972612c1ec2ca90355222020218f126d3ab0a8590e404c7b334fe4b098020bfc41837720143d65086cbbd8bc2a4d261a7c51a19fa27");
            result.Add("az", "70f665fcf803caadcb6c198de3c7c9fb1656ab95429f365a1d6681b09c051a404f11db1ecdd91424d29414d1cf425829fbc81f37631fef139e5a1fc7114041bb");
            result.Add("be", "c3183e2b4a22e6b40f473363b81eaa2e1e2f5b34c05664d4d0ded462e15f370bcb215e2cda0d66f3e08ddc68af99c6832689c1ec61b02677cf547565214cfb47");
            result.Add("bg", "dda5e8d8f9dfcb72f09db7523bc291b9537c3d7e41408feaad0ad3f1024d423ffbc83c881fe8c267247e937fbae41abaf78d3a8381a2d1948d0bd0a48c374455");
            result.Add("bn-BD", "85a8c47d44c18e87c646685a17701f7da63b74e99a641903d2e8273e4d12174753631d4e1098e2dd7d6b91c496d7ffc65278e2d9f1cc50a671beb26f28701a54");
            result.Add("bn-IN", "ed14f685b737f172bba301048b78e6070e0ee5c80744a49e9a386c2f3d7e7a494c25a4007659f65d886206436317929afa7e5a71f50565dda273591ca3c5ad1a");
            result.Add("br", "c0f5784850a7f8e421f84540ca62b492c7975b001bf1cea95585872ee7332c5fcffdb4416ced31d84d0f82bfb1155f28dead052e60910f6e57545204b900fa58");
            result.Add("bs", "64a83e76b00e0ba7fa2170c09bc05561133341cbf78d23ab32b9ded57b195cae1d4122ec6c47527a47f1f1cd5dca849dfe617150f7073eeb40cdfbb8dd338553");
            result.Add("ca", "1bdece0715749a293445e399f6716b80aeb1d1e43277fbf421e279b275339ce2bd75a4eaab8abdf7e6a213c50b3bf3179e3974494c6beb05ad62be1cdfe43ab0");
            result.Add("cak", "756cd9c086cc74e338ea860a1b1a3e92a7127066d6a18a463e9fa4073a056dd946193d4891a6c27898ef7d3eae018b40d04ffe1067454060989bb08456345662");
            result.Add("cs", "ffea9ca23cdff7a4b3f0decab24729fe970e9bbb3c4d593d1a8f97409b9fbe2f15a31ff53caa40bffe7c46587005da4a3f7326eb5f3ba867b15d78fe0a2f3c26");
            result.Add("cy", "d2175bcc33fc43112c3ac15599febd3e27bb8a7c130b1d7de29499a81aa4940a7e6c91b57549d6b805dbfd07566cb0baef3bd91ef5e87b58806c9934ca63b322");
            result.Add("da", "4eba768b547085cc6e4efec4dc561358378ef6c391d1cb957236acb1efa4360803c57bd14695f1b234e2b03765faa7067794d8b8d64fbf96a55e9f86c9297721");
            result.Add("de", "74020b6e12740886a50728c9aead5d6a233f57b55ef21ca5a0cf9f1e559a8b6a475c8b6215f71fdd0f24361ee09cf372e42326e289a2d0d4959b39cba21e8f8a");
            result.Add("dsb", "17cb411b84f4cabfaad22e23ff7737bd2c35e2702aad18983266ff6f75eb5e2bedb8a0e13ef5bbd241636dee5e9285b06eb9d230411bd230af873aa3778f0f10");
            result.Add("el", "850290dc2fa598cae59f5905aa3f60c0a888721990174a5c66d9343d614e8d471352a5f2fbaedf576737c324afdfe98090ed88572f9e90b3c3c5f373b4a070ee");
            result.Add("en-CA", "516f4584d5af8b59b5778c631a98aee960db5fbd0427197fdc8ab297d8a8de173bd3af8708858e31d0cbe9499720de7fd0b23af23b0cef021cc77f0dabb5e853");
            result.Add("en-GB", "3e6c40d6399937be800553fc4ede40f8009362efb058a5126a95a98cd9f19c31af7a6f352b23cfeddec8827ad6178a7e41ec6ac43b53fa38124d9c721e454fe3");
            result.Add("en-US", "d57f240d6a80ee2182f91a9a8f9b9a5622ffcd6c1a1f9fea434cb02c262b1194f56c62311b129609a49fc7d3c77206584698b5e111b7416a6734fc2a69b008a5");
            result.Add("en-ZA", "336e375d9b57841cfe4fc091b7d5289933362cdc63db86d6694dceeefc22029db4796a99f893f8abd8b05805c0d1591697769ea28fdaa2fb4ed9ac96a40a2386");
            result.Add("eo", "c07fd7669f3948f8b271923d9cf3ba0275e559420abe932a71a75075183ff6c2c6a495dcdc92eff5bc953ff388add92787ed60e3e2f644081ded4b27acda4508");
            result.Add("es-AR", "051a03f3446e42da921ae16ac457d83574b99b1ea71d5f0b9f55c8a668317907032049fd44ba6cf73847f74f97510dfdb965d6f8b55c332b7313af709cfbb412");
            result.Add("es-CL", "f5526ffacedb85c13ffcd4dc320cb4a67976d04079ce0eb0dcaa812795018a6c92d11aa972c61f3e8f0f115b75e8bb65966ca2f55fe23586049bab3b5a8d8cc6");
            result.Add("es-ES", "2e9528d82e33b65a12065b354d3f31e915b8994e57d6560f8b0e9d0ea6e128284f223ef214d9d114dc81b33cd5706dc755133efe39a2570ac20a6d0ce68f94c1");
            result.Add("es-MX", "ece5e6a15373ba20785f757bc3bb9fffe6a21d3cb56cf696997571b052fc2c8514a01cb2f6b556dd8781466a6d3dda22fe5d3b0f109fb81104638b467903b8b3");
            result.Add("et", "8bf808fe2af55d7b300686efa70761970f58284745935fb9cbfa75e1c7192e27219f4c288de4f46831ed64968c1da2b2156236e776ce8c9666b22810ee99d3de");
            result.Add("eu", "4fc2b4bf8311474e0401be2d696902615537962640c572f57799e80780911b3f328cced7045bc01120e1e37a03bd0bc8c9b4abbe47fc84bff0a24fc2b1a6fe03");
            result.Add("fa", "7415f61f0676e820b290f22fe7cdf7d02828ed29cad3f1c5fb03b9a5fc8ecab1ea7bdd66e1fefb4ec1c3f94a3ee1a3e74eced67689205bb2b8432abd6dba6330");
            result.Add("ff", "1ca6ad60d73be66f7cdb66734fdb767ead5e6c71b1ae6d63299ff93237aa17ce2a31b5218140e062c5d5aeb7d454b1cb7f4bb2f6c3642cdbc2a33ae5037319c6");
            result.Add("fi", "2868473361f52cb52facc5eb318ce1bc21664e7eb0baaf6138da2e006eb1df62de624b9ef437a6ac3839edc17fb1a756b865780d956e459c9913fa5dc00c7513");
            result.Add("fr", "f46a1f4fc0046cb995107228ae0b0d32b2831195173f0ccc09c6641bbe37f01d4fc7e3bb9eed087e3e2c323eef1ebe795149b59beb8934ca0b8892a74c0aeaf0");
            result.Add("fy-NL", "2401746cb031159ca36fe5d8df4c9e73db0cc94d6a06f545d383c158120b9871bce967bfdc0ad0f3b01db047197afc8c2dd88ff36f37eff5abd7ab944d105919");
            result.Add("ga-IE", "64853278e718127e6a06e137178701b53fa7ae71d3deec24d9857b08b87b744413c233a7095b854158a00239916d9da1a1e00211e3ba27d81025f9148498a81f");
            result.Add("gd", "98bfd77b1d7b84095c7e2c91d61480f9c11739d352abbfa40a9523e04a58d9f2d50d976cfad79fbb3a2b1fa0447f3f4c02a4c1d2bf187f6be22fdeb554e87fc5");
            result.Add("gl", "4bd3273cebef272c06adf6e4b8a87a2d74c31d26f4ac1906dcc6631098ee41d55ff1f1d6dd66b6abd0d5ae922cbbb3e5fa04f571f4e436cff7df66248b776f2a");
            result.Add("gn", "676f707b1e576c3a60b9cacc49367c0ad902fd2b1c4889972d7dc81e8deffd9f50391a750a2ed62bf211dbdfb330980edbc6b953fd8ebbaee1805cc88795d2de");
            result.Add("gu-IN", "225764b7050146058b2aeee80ef74f2594c3d23e87e2e2cf5d2ff6596d47cc992c3966734989b90dcdb58d85a1db9fe2cbf3e1662bfedcc0767d0cde0c1a34e0");
            result.Add("he", "e4d5e62e2f9289ff3d30338f69e2aa161bda8429396d9856190a9f0a899a6f42258a2a23410ee4e80d0463191f95b0db6f6ebc05f10188ae0a821ee0986250a7");
            result.Add("hi-IN", "29a37007e694c651ca04c901a54464cb3e0d32e383442e028abc0c812999a20612627dcfe8b8def4dda37a0b4679c72abb2d871044c32368452f60b2a7efe78f");
            result.Add("hr", "bb8fd4d3fcffd6cc894246967f1a9a53dd85946077bca0bf76f1c1b8c31d75e43ea447657956d5494c9ce8574f32bbaf6682a7fcb70e0fbf8f25f35d2b9e02cf");
            result.Add("hsb", "5706f7b327e097e44fbb5970052bd2aa48d0d4333953a1bc579f8f075af424bb29d6979fdffaa191d7591e8cd19f043dd0b576521cf94798a32464dd27374574");
            result.Add("hu", "6d35d890ef1fb0eddb3b4c4c8ff15b5b1b6914d06ccda3c74534513b8e4312106c94d86c4fdcf1146d93738a28204c79ed7b44579d3ebed3f11a2f416f9d8410");
            result.Add("hy-AM", "1ecef7c3f33debabcd5508b8cfc4a34a4a187b48a3a48fe0b40ea61a33567b72a68db03674591a33bd70198e8b558e3b38ab240a4ab9305086334879c48e1a10");
            result.Add("ia", "3480fbd06b5897003116e67416abd2cd1d0fedb72acc80800209deb35b8bd572910feaea38c867212988cb8700a1eafb6b9796cc66276a20e63590613ac1d462");
            result.Add("id", "92f050d4f34d9d8767c2685ea08d54d00c810175f32e8ff199e0dfad5f7f649a423f62ca99b2a57c11614aa88f8c1af109ee9cb169dc81288788f885de4a23cb");
            result.Add("is", "e922aa67b04b219e42eb011c257940955bb56928bfd99296da7be1d4180d447cab316c64dec5be6b0c2c0a1b400cf3537c69384515e158dbcc3d6bfdb361f265");
            result.Add("it", "78740236295b0ae5412cd0e754e3627a8f98129c839257231c0829be82f4f1e487240a2cb661b6c2f0825559693aba106092cfbf00d2b72ab1a369cb0c1d35ff");
            result.Add("ja", "83b6baec62863b3137aa923c9923d3a375cc452e8a9b11bf3731ce0305d82b084f83138815be3c02118b8e833c38531b464f15acba964043ac4cde20d0eb46d9");
            result.Add("ka", "eabf3779bbb25d06c72cc4672afb84aaac4d985823b0e3881c37e6a2c5840a2c3154ad70625b011f5df991b1a2e6db403594f2995ca0e35b06dfe6aea26e3e01");
            result.Add("kab", "8534272497c88a302117749bb5b198997cddd809c3466a1590a5b1594e79d1f7cfb43508a7f51b0ea7a2f8160c12fd69464ad36b9dc3f5af3aa8ac90f01e4208");
            result.Add("kk", "c5da9f6538f26a8a54ac29d467b3ea9a4a7732f17efb02e907890c4393094250bc6c88927fd7c74d600c8bbd626c043a3fd2e43857a71a165947f0b3272d3b94");
            result.Add("km", "132004caa12c990254fb25b45c112013f0f64173971a610538db15e7e009a558691a5406904a83d5fade1bde089194f923d7c74358ec8b4b0e5c7819dd215995");
            result.Add("kn", "b4823f2c00cee4ec1522a5b44aca910ac901ed8908fa717da394093c48c673f01997b5a0b593eb4015eaabab2d0e7bc94c45ae61be813976169eaeba05e86fcc");
            result.Add("ko", "25f07ea9cdf94c9a5074190717557c4a12266025afe8b24308501d0112f7cceb0222864d500b98330330b44240870816a98c7d222ca51b341947eae4836189e5");
            result.Add("lij", "200806ac8321b0ee1939a50a92b9514bc0ec6740509e825c7b7edbf94c30c7a6f4a65df8f0656bf21af4b8566699e4c8176807fe59a87b27ede80d48d474bb57");
            result.Add("lt", "6dfdb7407239ddeafb0c55205885ccd7626a82e7a6cc29e53714bb3c43b843944c6720fcbc34f205b52d9da4fef75fc96a1bb7ea6561266febcb6d9e2d292b57");
            result.Add("lv", "d05b6092c5fe3e97ecb7ff59dc29806f802329a2779ceb1265be1861309696586d0aac759629ee7d68b3f0936d1397ab11e5cf3f99fbba1bbb19f2c7ca33d412");
            result.Add("mai", "6bbac6538466a28032b9efd6c25d80af54a3d5e01f41a4aac7398638b6097cad536cf6da62439686b9fdb19ddfe1b9b9bb748891f324f368b568b831dfcafae1");
            result.Add("mk", "aefb2d03a902af24262b009bb1d0fbc138304b590019db307ead7eda86f1fce9dbc5dedaa7b63ff0a3ce65a07d9dabc0e1f5e395514d6b3e906d1f513be6242c");
            result.Add("ml", "cf13ca657621872d9a4463f1567c4829ac6f0c9b4310be32b9cd26e53d245b576e93e9241c68762ab70ce5aaf0aa566e6d4aa5ea3b9e49eaee516e6499ab6ea0");
            result.Add("mr", "abea989d5b64ac7805ab87fd558de364b759a7dd348bf2168a5310f39c922cf155a967642e6c84dc30b9ee0758be1f43631ec675f2e0ca40ace0f7ed8cd4146d");
            result.Add("ms", "2e0dfa61fc374222ef8acab7a34daf9b1cf7e9214d3cc84c18b59eecd97b7eff846794c7fbec7678fd612cbe46ee4357f1240859a3d102aaa49ed31a4fb42810");
            result.Add("my", "98d09f15517fc52d1d60b351d0259aae8060d266fabe6359db4993d919cd7521ae622289880ee5d1a7fe2039d44d2353fb1998227cbd3d66b1842a07251f5963");
            result.Add("nb-NO", "0f64f027ae27d3d57a8780912c11de49d2ab82c177004e73e46f2c86e0e0f4d5a739978c18246fe535a3ad34df6cc34e40253215259a6e72cdc1a28a42343b03");
            result.Add("ne-NP", "96abab03ee273bfc312ae8ac0acf20371bffda12f244bce519c54527374f3691022278c4aecd6c8f186d9302382b1000035c8d1dc40f01600d68756376d7fb21");
            result.Add("nl", "7e54bfc7687833bc52de72e5efde534c634045652283fc15568c767b313c0cd126301741c1e757b17bf09dd2a66a6702be2f6689718ae2d18ee9d61649c0e586");
            result.Add("nn-NO", "b830647b6d469ed1d842655e78d9568d30023349be852adaf920395b25630475f26fdeb79ed145e6d508d1170c47c0705a92c60adfb285a41a6f081e0efd22b4");
            result.Add("oc", "f258751f26bbf12e62486a40c0e8b194d5341b607426e60506f73bb9af117aed7fdec35892c6da2234234d8dc96bfcafd1f9e4e49419cc559974aea4b953fc22");
            result.Add("or", "93684e4bf92d34a3208ad27c26236b8091657d613a304507297fabb6303857a646899b6b7595a2f1c7ed960ab342fe80b52434f9f364a00dd682b3f69080d017");
            result.Add("pa-IN", "1c11092335785f3ebfa8757be54507694e87cdc76b02c2a354528dce37cbd1386c5101913806ca64f5d4f57b812f296f32aa4988108cab3f270f2cfc5f1066f3");
            result.Add("pl", "302fd15607b8bc9d1c80ff54d76adb2d4c4a8fbaaa85c3968074894d7667692230b1b1fb6d12732574c24d7998217f44f12102d306278ff7891bdbc72ca692c8");
            result.Add("pt-BR", "0954c5d653ad609447dac5976f9415c823d0863ca3629af145bc1098cbde1dc894c5376a330c6351e40920edde653a1bfb2769ca1dd6f15f10e512badab53572");
            result.Add("pt-PT", "52949c13058b903f1016e67d04b8b57f405c0fd84a2706c78268d1ed451b71f553f620b136ab6ea22324538b993da08a520777951663ac218f270e760f1cca10");
            result.Add("rm", "3beb083d373aedef5c42fc5da2079019a5648145ecb393986825970e38df5e5c5c65fc7ed58e46dd4fa34d43dbe40e4d85be4c95bb3bbae038ebc96ea550df24");
            result.Add("ro", "b27562b550b8e8a7deea3b9582517fb896e376bcd800c2cd3ba30da7cbaf42ead6cbfde81d3687512dbb2db37a8a804814b692bafbb6e85333f9696aa5888a9b");
            result.Add("ru", "8cebfda7613eaf570a946962d09b7f7d14a39eb3cb1f1ace854e2ae1bda9a341dff27720a97cf3c8dbbce688c071385cb2dca688e2d6b46be268be361980b0ee");
            result.Add("si", "20a81a14ea368d1dbcb8206b87e85ae1e46538470d71ff37efa04b1c7200c60f7472060edad3e17d773a1d36bf5fd286ac7247b461d1c58e31c3232966e415aa");
            result.Add("sk", "fa3b7cc8427ffd5cce87b4b7b8b1b8cd98134925b3dd35e20f1f30f3b6300b73c0693f8caf5b76b0a0c7a157d7c97497a94d46a1bf199ff26b6f0c5d3635fc86");
            result.Add("sl", "9832d2a213ce07506abe13f42208c710cf72f35411a58dfdaea1d8c2a2e41736a1f446a0df2bf0c605bfb2d1aa96b5f4dadd66859b3ad4bc509224762eab793a");
            result.Add("son", "4658ec45c2d14b5c22b77bd5126dae36dff5a8ab75d2e9ed8d03ea52f7d854eebdc7d74432e4774646b762cef35d5ff3eda224cf0c9094cb012bee71a14d73ac");
            result.Add("sq", "48dff6fb42b5174d5734dd68d251d7a447c47d3aa032d594ffde1ed4e64bdc625781052559e7d2402325875ab7c2e6a3e0fc12195d38734c89accc1ac7fe0b90");
            result.Add("sr", "275cff0ab06c6ef1844d82097dd2db1c2f809886d0ab66bd572517dfeba0dcd7f9ca9347664d35fa5095d62b57652ff98ffd042bf6b9adac1d2265f78181ea10");
            result.Add("sv-SE", "0602f2a0424749ab11fb2a057fb048554e48184693695751bd0909530e06e32475473e8d56ded84bcc874ff26b804e1862cab72a21c1f1ec4201c6789cec3834");
            result.Add("ta", "7912f9b03ea323ca4ad1e09730bf0b3aaa555d6384aedcc8b2cb1ed84eedad975bc2d60306c9347b38e10b9afcae1e58db9a4166d200fe23ea5eae17aca21ce6");
            result.Add("te", "58566cb979301d37901588cc175c2a833243dbb3f328991fe5ec2c77fd490614e7d9f61f0b2f56902fe1ed2efea6576048c4f441915645e9a78c54c900ebe1c0");
            result.Add("th", "ba7c63ae9b743362668b559b2630361142349f35c78dcd7ad8690d74afab36741496a100664f238c3f3d17ffd85abf235ece3412cc742025d1c365dfe7427a83");
            result.Add("tr", "57818c9debcac507b926170983c4baabaeefa394477995f9267f6e3d205a246f38c1f18eb2d05d73f3f68586637ad002018f705969d0acae573e21b5ba1e7e76");
            result.Add("uk", "789366bd3fd41e539b291e3aff576e584ff08fd9d2adb42831949c7ce145f0e4af472679f5d02e04d7caf11cd0a0a000f695c0ac8240ce606a7fbc61144314a3");
            result.Add("ur", "048abd231f71fe9bed06ae2d67a9dd9f8f87c88863ee277c2523e8ef9fe185e0748f4396ff1abfbb0194447d8f0a78f2d8fe69103644c33cc83159815545f9c4");
            result.Add("uz", "27384196c8531c27af8f549abc945eb807cd0928508f683794f1018abb143e057d7ab68f54d49debafc9cfaa82f668c7cc8e75faa1f143813db62dfc43688ea8");
            result.Add("vi", "cecec7470668ea3a22cff75f6c27ac3ea8b8df38c511f344ba5860f3939751b57de575a6ba3b6b3c09d994896c92565c22430b91c42bd5b043be476746723001");
            result.Add("xh", "3a914d56bcb98f2fc9baeda0191c2bdaae56883c6c189031440cf0e006eaf59cde363f8b8aeace163ccc734506a3c2c3ba1b1b9817b4c756184e7d280655d63d");
            result.Add("zh-CN", "1ef3124d53482b35f0732bb32d61abdba63ed2a5addd9cb838813660098eafa29a66722bc1ed699436f2365de153c4252fd996cfae6fc05dd4083c076805de30");
            result.Add("zh-TW", "2631ccc23f9da6f31785fd027a70879704452a9f879c6e90a4098c9530b73ff5720286e3ea6c277e15dbe7f7bba272677163f59666adaf24be9687678ab1a57a");

            return result;
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
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition [0-9]{2}\\.[0-9]([a-z][0-9])? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition [0-9]{2}\\.[0-9]([a-z][0-9])? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    null,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/"+ languageCode+"/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    null,
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
        public string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            List<QuartetAurora> versions = new List<QuartetAurora>();
            Regex regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
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
                return versions[versions.Count - 1].full();
            }
            else
                return null;
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
             * https://ftp.mozilla.org/pub/devedition/releases/60.0b9/SHA512SUMS
             * Common lines look like
             * "7d2caf5e18....2aa76f2  win64/en-GB/Firefox Setup 60.0b9.exe"
             */

            logger.Debug("Determining newest checksums of Firefox Developer Edition (" + languageCode + ")...");
            string sha512SumsContent = null;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion==currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                using (var client = new WebClient())
                {
                    try
                    {
                        sha512SumsContent = client.DownloadString(url);
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
                    client.Dispose();
                } // using
            } // else
            if (newerVersion == currentVersion)
            {
                if (cs64==null || cs32==null)
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
                Regex reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value.Substring(0, 128));
            } // foreach
            // return list as array
            return sums.ToArray();
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32 bit
                    Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value.Substring(0, 128));
                    } //for
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    //look for line with the correct language code and version for 64 bit
                    Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value.Substring(0, 128));
                    } //for
                }
            }
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
            logger.Debug("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
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
        /// the application cannot be update while it is running.
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
        private string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private string checksum64Bit;


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32 bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64 bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
