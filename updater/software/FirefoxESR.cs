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
            // https://ftp.mozilla.org/pub/firefox/releases/68.2.0esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "8a25f6bacd32053dabb54579f627faa9627ce4d0b971d044400a2368eacc4e7b29fe86d0e66643bc31454b3a9852926ed1b3a74141bf2da0a35b759dfeb577aa");
            result.Add("af", "8c0142fad811a2399696801312ae761a36646a2bac698190e94ec22c483255f80999f0f68529a71146b612884b12b7624c491268727d83f774ecbc91eff5735e");
            result.Add("an", "8627ffe1b441f6c5ff66f0081ce84f6594b2a08175c65e18dad8f700629dbc8113a6e78f3b7cb743e9786ad5b8de71c9cae523fd8ecf1d24ed432e69a826d6d1");
            result.Add("ar", "dc712124fe9aee3dee4e3a120fef66a37c087ceeca314b33413571bd32b7140fa0e7ddab3306231ab459492194ed35c8faf3fcd6a813306788d53298c59a0fd4");
            result.Add("ast", "66a04c2cc4e18be484676b8b6d680e702f34ff28e1636d2e346420574fac0a133050b687c5d09e59023ae95939360956d47cc60bb7154cd36822f37a7d8366e7");
            result.Add("az", "70a198e2ed5e2a0dd99859e0c1a6de5ca43f63162a9f155378bf635f469dbd56bbcdaeb1077d04af08ab6be07d909ad5b65dc4d65198bf902d4406361049b0ad");
            result.Add("be", "80351f1bfc916bfd7ec2d43c2b808234d029c1599701653b21dd950ff7877f394f66034c1f4638fba4a12f24196659bc9f06a78b892f7159c0ed03a9bcbd57d9");
            result.Add("bg", "0f1b8201863651ffc9c29eb02b3b34b50d8d038d9c359e04af33d49e7402779d7da9e3a545908a9dc67892f6c899f4a9399f7aed4dacd976f9c9548daf055df7");
            result.Add("bn", "8b22d349fd8b792df8b1259c2e3153fdd2e40e05bf5e0a603a2cac1b21b325135f2ba6e37bd90a6b5c0f0c36d2113d19de675ec46a46f5701311c1adcddbe2ce");
            result.Add("br", "8cb1085e0f679c6f38a27373f77e0a06eff1d2661c4103dfbadb2f7e02dca9d17afb2fb19ae81d8c32ec5ae20a1a5d0bf7e0ea516172cd971811497f1f6ab5f8");
            result.Add("bs", "e79169d8fd08bf5979c1ca6865d2afa7fcf054cacbeccb561d4b49c5e4dffb91d0c0778f23f379bcbbb84274548166c6326d2324bec02c8c9f2465d6acf8eced");
            result.Add("ca", "0e9952d1176623e3618d4678b4355b7df95b1b516c3aaa92902effb83310363abf50938c0460f496353a7ba6d50cb2ed439a0f3b84da3798a1e711e9db768052");
            result.Add("cak", "c29eabae8732a8fc778cdff416aad4e93401b7f832c82717deddac762a8b65561d0542dee7311dfcf5a9418f1b87a85d08ed1be9abe05f5ff755ca392d3045e6");
            result.Add("cs", "53ecdfc832b010b4e205c6cd4e4edb2e56a284586aa51c3294ec455ca2c2e130b35e8ab6926b1c847362766e7b326c8f9ac57c3c72dd7289b054f50a09558282");
            result.Add("cy", "6f0efdc843796d03dec2ec40526df7d6d0c2693ea0c963b5b30b0de99850558d0da833c8d37b467852f16deedc81da822f26279c2a4e01209f20eea269f92dec");
            result.Add("da", "71808e6840187070e8ef91371a714a3b42c7e750727a1c0888c1b41cf9ad1c06d3816bbc125f67c8da52d80f0b0d61e61ae8532318c3b0d6df7b3bfd87f487cb");
            result.Add("de", "e821f35d4d109d40fa489cd4b6849381639eb6fe1602d7e1b3aa500fc289cabebf9c0568c798c1e632e3e358cdf7d9e9b3554ceeb05811579b007594821f70d5");
            result.Add("dsb", "73b523aed0c16c675c0cfe627d202d0dc0f3209c3a8815eeef8df7b8ba760cdd5b98ed999eab3793fdb7a690d306d2622ef1726760078821da756407f97eef3f");
            result.Add("el", "51c81e8d60c1167e58ac84c4c2bc4f5ccaedbe2720ed747bfad922f573d38ce64e726268fa556ed8a9233bc00df1090de56c58babb88d379adf9c7f1b081a8c9");
            result.Add("en-CA", "2907c3711dddbaae33ec2350373edd01b5d14fa87e623f9f2a49d98a6d7e3df81e6c442c174411d611af6b24c61d245ef70ebaca5f59aa7284bea5000bf64f03");
            result.Add("en-GB", "2b52b32d8cffcf97773bd2eb0e6b8d7cd6531ad1708110f25e7e87a23d1bc48575bcdd570a7f7cca6eea7ddcd229aaaf0f1da2b5c4703d06bb2648f81f97434d");
            result.Add("en-US", "1aa733c2ac068271e21d107e2d2945ecd70383327707016155c4b11df8031ffbb13a5f64166227dcee55f7e928b733db1a5c284982be91f4f8ad8f4cb6e92fe7");
            result.Add("eo", "ba1c2af0a72430f5af246251e6bbddeb89fd872014085a4087c98ad4ec50d44a452890d3b30a84a7e4074682025eb832c51d6a5fe30a031afd21f9ffdf9b1d9e");
            result.Add("es-AR", "3fc57d9a9d358123dcc25207c06e9d2ad0b3453794c151b97d49289151f6483e0bd88f1dc4717ca22b15a9841760ff23a1f95b15e28479f565e91e7802b41924");
            result.Add("es-CL", "51bc225680e46889dec2f4e5cf9b1b4cd61117dc7dc9c9b21cb724c50fee336d558951dd62083669f071a376af61f908fb1defd2c73f93c88d4baac0fda51c91");
            result.Add("es-ES", "8dca973bacb95acf1086e653b5d5d939ec952ca6c4be156de353d1384c28730908974a9f6cd165c5d664be964443f7b6f56b90539911b8a0da5a753f37616d06");
            result.Add("es-MX", "735153d769d64ef3a23ade38222511b98983254b9da1e291b07619f6d0e875cd15f13d85a2a7cbafb602852f1e7bdedc43b3af2a639091478ce64f50b8ab4745");
            result.Add("et", "f26353795e1e56ccc2c6f11c2f7fa62f3b6acef65d16dc8f7cc5c9442bbbdd26128447cfe955bc0792997f019f279eed51e66f654b1ab90183a0c9195453b128");
            result.Add("eu", "db9851cbc28e7ccb2bcb43ab8e5d8c41749b876676e2f0bc2f1a0d04d1414d117352b470416e9bd2ce458d05248d215b9e7163d3a1a4b17710b8fde3effba1ac");
            result.Add("fa", "f5eee5a98eae1ac11ff5b513996b4a5870e0edb8a4391b2a21cbbd7453c1468747c2165d959ed39b86a974b8d8ce0ae5e990896161d71bee2db967a2df39ad19");
            result.Add("ff", "200700b273af9bc92d3f04263f8a2a2169ef6eac590ca45f31eeb0f41c51fd5677efb272781b5337558311b4543f827b11b28be29d8315df8d8cb313394c2e25");
            result.Add("fi", "836cab587c1bff80a9cfd0b24d673315db18cc2e33c9a798e0a4791db6acb74e970a1a040e1c2e370ead387023a84ae1178f207c6834aa8caf98b4d36caa4757");
            result.Add("fr", "cf31cd763c5fdf84d57ea9fb90467de5bc9d35ed6161e2af0f10538539498225f4ad1788b9670f8de5c2d8847fe1521d2dffe2e1f2d9bca5a52968e9b555b6e3");
            result.Add("fy-NL", "b7a601d9d0799e3e5780fe1ed74b22f4f7069c30f99ff1075fd66f7dfaac4e18b5e0b5bb67b4c9546ef125850d1791f7114a1ce951b55effcec711df56a6fc3f");
            result.Add("ga-IE", "65dc268418916f147e4dac6516f8ae8ec4be4640f200d0bdce5a4329f526bacf8cced8602c378ee752a2b535b64bc3b7e9e7486c88669f0960472070f5ec8e11");
            result.Add("gd", "be91c5cc068a7eec60750375a8fe9871f3bf9a71b6456b2ee7a58f5749699035ef2409a5a511564aac5adc5c2897c0df5f0054628aef620a18f1237b6dcdd5d8");
            result.Add("gl", "6e6c8babf21c4f7f2507c42b51bce33208657f89f9531b4488bbd28a339c658d1cef7d76f5bf7b2f5ef9117b939fc9a92930d20c845f0a3ab2251c46cf27a8ce");
            result.Add("gn", "925f993f6a61a70abfc7950002974ddccf1b2c0a607cc81c47d2fe63d18f47498743f739495331623f3206322fd60d7334525b29bd67288e989c8430bcb5aa8a");
            result.Add("gu-IN", "65c29706445657b3687bce6d712aaef42a3abce744882bad37b72cbf607843aeeb3662a5a1d6986891edca0cd3d56f73a03bd2036b598a0966eee2ca7c8a553d");
            result.Add("he", "0ed104de6bd991a7b87f6551b9660f5a22903aea1b3dbf59eb46bb175751c0aa4f963cb5e00d48dcdbfeef826cf16ba80439e2f8c73ed7a781f309443ab28164");
            result.Add("hi-IN", "dfc08617392e39abcda737a855852fe3294ac0c88d925aded9a0e0968841fa3f9df0cae0701b3cf9fba19e4b3c36b3ae76e4f01b1762d3bb04250a905794aaf0");
            result.Add("hr", "9a01fba02771b57ea13ee4a58c9424ce117924a98d9ec3a338a5ed78e0302b5472144acc1a81c3d8d079b3760f198eae69a4364be9cef2a51836e44ec13d0f37");
            result.Add("hsb", "2bf2a78b651f3a95104622a3f444a60acb001ca1d216b9eb865bfa27de9872ae236562d42e0872c9259301931a9b3970533d61f23fdf4231710cd3d48455e0b2");
            result.Add("hu", "7f95d8c17211504af82c1a557e2ceb246cbe2d5063113d5ddd5333a080d0b45691435d29be793480e5a31c67a277ccc778d2202aaffe98cb577701470785912c");
            result.Add("hy-AM", "c554e507ba7fea8920ba1e5de7b1a2abfab09ebf4bc91442a7e520a4e59a6bbfe657fa5b6d34c4217aff6f0350a8f9370b55e0f5b9f9610c2737910502aeac89");
            result.Add("ia", "81fbb658fd84fcb1138d247575adba24c5361502f886b689fca89b9b88a25258527ca4eb4f132c592b7c115cbf265c12f091ff8b2d4262d848a1413b2fda11a6");
            result.Add("id", "1af834900a9586eff953ab1c4c6d8ebbbcc3a60b6002f91bc574a0fe6c55a508c992d05c46336d1a629fe2e8fa269df736eda84b5d63cd406a2083af8485dd67");
            result.Add("is", "89c3a5aa1524efcc3f8672a5f6dc9cd6aa160d40a7caf64e86bdfa49a9dbf536a99c5562b18fa75191072df225a54016bdc797d64ce8c4de14f5ff7608ad8921");
            result.Add("it", "5ec8dc2a7633150d373f3433f788d197cd7c87a5d4a813cb4b30ca7101cc01e72ae792b1df103ab5c7e9e1fcb849b1b8ad1e0e2da0944c281ccb42c8d0bd75e1");
            result.Add("ja", "8013f618d05d6345275e60fde74c000a4155976a1ed60ccd3d73cbd428099681351c6336be77ab3be1ef094128e0424881c6dcbb0fb362afdf3cacd001cbe1fd");
            result.Add("ka", "c348fdae3255e4e3159a7e709e6ab501819b254dc8d3e408dcd4d4f88ae733a23d2c4e1909cd8bf3e0afd6c05c9cd13becfbe23e2a72176d8b1514df143976eb");
            result.Add("kab", "3adafeee418ec8e696a91c17c429a15fdd521d588dd26368569161ec0c19ac88790c92e37d7489880fb6e8e3a315d5c79c06a6c7cb0d014d56f2343e2a6b2618");
            result.Add("kk", "cdff445a335e540736f000845efce3116b365a457bddc54e5da66cee9656a62496781b740ac6800c7abdd0766f3b55200085194b1c8a8634456b16d899643805");
            result.Add("km", "66cee06a1f0a4fd3cc498388e6b5bdb438996c4393b714bc627e8dc1392bfe2bc338a3f1106982b8d220ef7303775c3c25a7cc0091299c2401a33cb830cd03ad");
            result.Add("kn", "6e23e5bf7a94336fb11b59cde16fbecfd4f21c4b060bd350f7880e0a59a4e22047b4f107cf5e4ef8b080e8f781586dfd05ba4aaf39f71fa095faf77e3a519219");
            result.Add("ko", "e131dd496b0a32c8682e9697b2e4462bfd429c36349a55aa0b3fd27a78460344f87e1cd657441f54e66fbcb344a1fe56ac32e33ccf1d520f3caea3ddd9ed7f52");
            result.Add("lij", "f057effb9d0180a4287389f3a98c9b28aea5be81f23487577cfcfb43d95b242719156995e55875ba9bad2435d57eeb1ab5eeae2393e1ec90dc438ee86e03f57a");
            result.Add("lt", "83c42e55ce547091f8f01b22a2b686f997afad721f2aaa355aa5a7abe93bcf18e04084c0a40c35c38ced71a35e393d3f779d9c70f42d0a5e89340eedf8f8259d");
            result.Add("lv", "3fc32da1dcd68542016669d6959a8e4c6380e2c31ecba1556b8908512cbe37202478088a473f948a3e9ae31bdf2fa0b1a97436559dd33c7ff2b24475de97f5c6");
            result.Add("mk", "c0510597dfa90866ed7697ccf935323d1b7204cd1467ae4edff7d92f994a6662ebb56ae1f4a5999303912220bfd7957f56de4453307e1e6acf7c55da783d3787");
            result.Add("mr", "25784bb400f8a5c32d75ee5dcaf6f39064f8f455faef8cf1d12b6c6023a9f1a20d53be66a50a65cfc39eb57f8e672d287e85f2893c1c344d6ed9533f2955fd92");
            result.Add("ms", "8dcc09db2b9023d77881d764c2254d0bc7f72143e9df53ce392be713d957e27b9d8ad39734c36f067044c5f47b23b12dbff468a8b961c56142b687ef443249ca");
            result.Add("my", "8d4a7a14bb7ccf468b21b92ea5cd432b9212b552951466c39ceff86022711206a10ea6af869ac2d7e64a95bde94e9ce5b20d1168ee00150538e1b49fc5c89c97");
            result.Add("nb-NO", "21ff9ae1b4484d1a903a5ce75064bad45b82539ef2abbd9d764673b2b52df2b3f5388216210a16268a6cfc18f168e62254637a4f38cbb813268ff39d8e9c8b2e");
            result.Add("ne-NP", "ee3ed5c10464ffe0d0e82f59aa8ef99749edb0bfb89e76dfa367eadac37078088ae056fe3c55f864f7370f6906e9354f8777a3e075e3d4a6355e424a431cbe4d");
            result.Add("nl", "49d87f2810bca0a63f97c994cb241f2d688b6eec2971b5451e47a45a7fb0bcb52e41ae847486d45720f5d07d9fe52c59d16afc383cb6afcba872f388108bbde0");
            result.Add("nn-NO", "47a87283a915d5d8413b8401a3d235d2d6afd3fc319d9907a4036f11861137d01c0aa5af405c7fe9ad347208d836d4373543c055e31d6214d7da29c7d49ace89");
            result.Add("oc", "6a81ab38c0a29d6b4537463662f7ba1ed288eea0fd7895bcbd76480c7fcbbea9f9834e21f534908e46bb0001a2b592e2e03ed7035e7df3374ce40908314fab59");
            result.Add("pa-IN", "20f8193bfba27741d173d7e1b1a2a05a9d811666c89f3f1b073e8eb35b1fe57c7b27b1bcf0f304fff1f46eced9895b74af047487fe1243d90f12cdc27aa2289e");
            result.Add("pl", "ae5587e8f901023005f6a94ef54341347b07825544ea69eee5b7f70a67d081f01a6778a8a7d9be880b7324567f67a830b0af9b55ec93533bbdab99411f8aeca4");
            result.Add("pt-BR", "be374131bd91c101e599716e91040a280db88c61afa80c99578ed6219a2c4ba10553545b50ee0f658a2837d0ed1abe20566f427f77e226ad68e9fafb546209ad");
            result.Add("pt-PT", "0f713dc6bae1abec5653d8f6d23f07eb99f3c5354c1c9e20e78cc64d5f8492893926232d04176b4fe3c1b0df54943e384972a7905944059bd0df72e037f47355");
            result.Add("rm", "04d0e4f70daba841946a90051fa83574dbe3a1fbdae80a1aecf3b45da333bb653b6b28bc9229f42703159416ad43c35da24f95e97e027e5e9fe3da65698a0b5f");
            result.Add("ro", "4d43bf6a91ca98b5ed2217145089e7cbe10643d4795b2638bce0adca06562146557f034729dc97b90afe2773ad7e53804bbce3341995000a36c2d025835c65a1");
            result.Add("ru", "997548d8950ded2bbc508347a89a28f2af0624b692117e22205c2b66f8df55898af7a69877ae3f0b6b3ea03020230fbe98cb7919543dfec1d81f00419c1c76a4");
            result.Add("si", "7d3b2df00b78145b2139b18dedbd1ceddb29b262e08b797c29f5079191fd54b2c8e49545626896eeab1a981e750eb89c927ad7e6aaf6fe5996f1ae80cd29d782");
            result.Add("sk", "3a9802c18405773bfbb72c791be176d53b1cae65168fa8a02a4a05ed1a8f9d8a0825eda42a1b984cb6bc30a219228cb3db3c190395fdad6f604e36d8506f5975");
            result.Add("sl", "932124c232dd103154be06d96e482b359a8b4b897afbc9185b92fc5c45fb978ed49ed2a4a4cccffa12bb81e28b85686e444b92e86532055e8a3a4994139b4971");
            result.Add("son", "6b7be0d47295a18f93e00c52394dbd036828e339e8178a355050ca1a449659357aa7ef042c5bf54c584f403dff58fa0c0dc0b54da6d79b0a8504dcb1f53a6cf9");
            result.Add("sq", "81c99c4216eb8f3565fb8605e51eb4689449de00ee4323f5cacb68e1ce3e2d8ca2f84923e3794a6b795ab0a539c0a3ac6c668de71646f67ced8bfad61a01eb4e");
            result.Add("sr", "5547e94f649f6ad1a365fdea6fd8d94e509ec7a4c13e56c22d5cba6791070b127f6f833a53689d49db9ff6c436048bfbc6c2b2b7bf2e9c6ee29d4e82d0ae00ff");
            result.Add("sv-SE", "cbfe5c2e6447c3f21f89dd31bcb4fc804c50a5b97a0db90933b120ef9636ac36fc589d23713136e32d55ad7152dfe3c9d94796e37f5397898a961da4e981dd7a");
            result.Add("ta", "2806b82354463bfe629422cc0ee17cb368be07086373668ea93235622d0e20797777a397cbfac3cc3ea0158cebc352e2cc32394be5a7007f61f76cc167d811c8");
            result.Add("te", "af11ee1e525f521992b639d97c6393fcba8b7a2a0691200a6e03ec427b72b68419beffa286cbffb975b5128edbbe7c5a88b63f9fda98ce405eba3be1826126a7");
            result.Add("th", "7616a5c017b39619ad066c5c45b7433ca48b96a0ba6c446b972a3ae7519e23232162a6b92dbb349487e750ae481149cae47ade598e0e85c76c6221ce84101c1e");
            result.Add("tr", "fda23782d6d0fce38ff084e38da09f47f4ceba58da8fac3aaf5dc8146ffea1838f8e4c606813df417f12797c59034a1e2b346326f0e2c2f8c9e9100339306936");
            result.Add("uk", "fa8b2c61bbf6307f2ce3f67bcf97e3fdbf2fe12d2e77664d8175014684fd4729e9c1cb4c52154828235af10d02aa9897123361bf3291d887bd48749f32b1d0bd");
            result.Add("ur", "dee7a6fbcf859a384ee39417756eafa7b60f8746291382c262f8862cbee16f9727d47f84e87388c8cee0932be17fa184d13b88af9a234d84402473a87e1439c7");
            result.Add("uz", "9bb7ba5f8876892fea1080fade894fdec77fb2b3df70680adaec6d5b49d12dcd6514caf8c48b0cebd5e35a4bfb27160f5d0316ddbb1bf427c5284601b0583cf8");
            result.Add("vi", "8e2bf366d7bf6d8b65a5e34309a633e00ad42822f6580fd335148bcb95cce8570c78c2246433e52406f42e6d7df4040e0a6202b30f80fc091f3f5de02537f555");
            result.Add("xh", "95aa04dcc105196b7fefdaeee85588c2a311bb05661d4beddec013546a1f022d00ad181d741ab0685340d520adf86e08bc08331f16445844679f90626adb19cc");
            result.Add("zh-CN", "000e97c264490fa9bacd8c8767234d79591da2f8ce767284f69fe82426217cf6c7b6d126bdbdaa9d1d2595e03c731812d6c611904429f0339c87a726ec097db2");
            result.Add("zh-TW", "184eaac269463a06e878e0f1ccea974287c457a72385a313054c431212bb6799cee31a2ba2e15c74ea141963cc544faf87594c5d0d95c619400a4c3f38b3a55a");

            return result;
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/68.2.0esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "b2b6ea9673577d8c8839a988a3da79f4612e901b1f213d42a0e34e54a43078d90cd9c5715f506d5b0fd012099a3915f2da1f8ea9de64fa3a6d65dccfdf7cea8a");
            result.Add("af", "2d672d1589344c6353c6280a9e88ac9c67f225386c126286d07e4ddcf870a4c7e89ed4e524a9223cdc87699ea7614dce1ccd8274d1d6c8d04ffb9ca0280bfee7");
            result.Add("an", "49dbd98808851f1f7700dd904ac9e66648f1ade387741a524fa4480420729cfcf2fd92b0cdc30141118bd8d870cfd547860565471576455267489ef2997a3ea4");
            result.Add("ar", "e533dc2069d9b20408d57a796bae8f67037aa1e89f350f7bf279fd7d671f10ef5a5085bc26982fde0db82ed804e19b2e84540c254b5fa4f1e26062f0eb682b85");
            result.Add("ast", "c695fa3bfa897d934dc8ae3767369cb9d5b2b94770b92fabd150c3c83b8d02f63c765a33d140b25e273a6a693f9d3848e12f62f565ed4dc3d0c18eaad08226e6");
            result.Add("az", "2a906f1b1eae937c13c75d51810ebf641bb4eb7698fc114748362d2c34938ab76553f017969cc8c3b4bb6ae12578c06c21196b32e5dfd4cb842c5997dcafbfec");
            result.Add("be", "4524b294e4a0b05f709a7ad978e06aeda4ec965099923b365721bc27ac8a2c406eda904bab1d73943cac416186ab70d2dd5711b28ed75f078f4e6c491265efe3");
            result.Add("bg", "f5fefe350f70e2a2aa20af30202fd3d01e45d3380978a9b9fd358b385ee6fd141b6694455a2c77b4842b7b59a8fbb1bbd4dbd3081b24dff25a40a0a4f9b831e2");
            result.Add("bn", "0a68b3fcaa4cb48ae2a30aab42ff2bc353ac7019ce12c2dc628eae31fb70df3a64cd8cd5f0223e338b790cdd4d6ce9f9ccd362d652ea6230f81e69156aa588b8");
            result.Add("br", "e96880901915857b9ef91bf4641b963c801c7e113dc02f0b9acbf8803841811d1a094ba5cad1b5ebc2a48c326ab85c6d5a65f3a3bd64c3428cf1fd856841952f");
            result.Add("bs", "ccd5dd75d6e1be7681ff358c2bf6c08d3e5014de9c5a0923dbcd6115747dee08fff010fc5d2bc10d624021ebd38b9902d0ba86519164036fb0308c32f3387f4c");
            result.Add("ca", "3b42af7f830e8ae5941372e302269b2d2b03ba339d5dee016ecffdb1e080a9badc1f18acf2a671633609b8bb71650ca9a4c414dfe189e3bffefc26c9a99a1dc2");
            result.Add("cak", "082b206d41af305320b4743e974cb3692842817896ccd63cef5caaba483ac70bf45a1f2b9d50fe3bd4a81a6babfbdada013a5b915767a92845bf755382228819");
            result.Add("cs", "6ebdf879eadca9fd5d7427a17bcd7d123f872dc62d77170627e6b248e53de251620e823f75d80786407cb42693e39a2f0d22f93ac8814c67a16613c1a4441910");
            result.Add("cy", "4bd1d7bc2e3c15163525b72d25245441ab43abb40a4bfd0817a2500b0b4c0e72b213b5b1844c391a3bc59b6eb045803e07210459eb6001691b05fbb2db3f9987");
            result.Add("da", "4b2969870c31337b666677e90febb49002c8d6dd8193f55e159fb1ee4cb90517cf94d8351a6ce6301490d136615bb2d096c2bb9abb3cf69ef724c5dda3f85631");
            result.Add("de", "29734b046112618d2db33ef1af246634c08d370828a0bb10b4318f513c9476c9d3579b62026398d0c8a64b96a8134482c7cdc2ad5f0bc8f241fd863bd7ddead2");
            result.Add("dsb", "d18db3ded55e967d6b9640cb8bee7d27f1162d929fb44eb7b56bc4004040b826dac780faaa1b5790c08588b5a89693976186760236eb6de6b6b591b7115b435c");
            result.Add("el", "f26e2fe24dd8432ed147af25c73b22eb79f4ed2b52e9c7b5d60da14b59a7e59e30819cfaecab6ccdcf21db1867e00df17d2d1ccd0d8ed1c915b4354ddaae9403");
            result.Add("en-CA", "df89e01d8fb9691acdb383516b1a03b87a7c6b43de0dc6d9bac0bd0709ca867d4a735921df0cb46967ce66a02cfd9654c7dcae0357e514017a9d1f515738cdbc");
            result.Add("en-GB", "368cbbc972c8037fbe2e9afad170d9da9bdf256fddec5d77377ac17a39fb51ccd0a9efd6c39ff0e168f7db3f59b497e01debf6dfd0cae2c5eac5d12e21d3bfe5");
            result.Add("en-US", "588ef369398c8e9d3a96c48d721f0e3f5f9feeb6d7836293f5f1cec0b4fbc590d69fe135b77b5ff99bef28f341bd9f8108fc0bb002123dde9aa9840f094b905f");
            result.Add("eo", "5100471c07ae881bf933ad7c2054488c386a0256785a4f11961c467f5314d9376bcfa44105246af51507ea2dbf5f8a2a80e58cf22e4faa67d5c90202a34a2be1");
            result.Add("es-AR", "c493de73c312bff1dcfb42100ce428b4456d4a02d0c3cbb8b1a93c070646f5e12288beb11cf8df1d2dcf4b8e35496adde07d6bfd0e0b7194b3596931030a1b2d");
            result.Add("es-CL", "7690d7a2387417edb6b61545bb735f04878272a3f82d8bafba865a0bad4fe2c7221e902e1b851232e0719237d1f1dd85df38c7dc04248e2f64eef8fae02be466");
            result.Add("es-ES", "51f729e235c7c8e1517226b9f9073e4e52e3c7c5a8a9419687a9566c205f14d9350bae47474a6389987345af402e5d3ebb4afa7b97b6f7267420ee5683ffe8d8");
            result.Add("es-MX", "793e31e4324bea822ec09eaccf2465ac014c21e8d6f091f0dc2667f856a65b5765984a1a411945062017d360a57a8657b5b3dbd36716b30f5c79ebe6afc1a16a");
            result.Add("et", "d641397e41239cdbf19ebac38aa402d4cacd37e3eb599974c2bff0f58012ea982d0ed7628b351d4c1a700bcf732f1efafe1a62044efdf779b9d34f30327bbd1d");
            result.Add("eu", "0f151be44b85358a350abcfee1d4425348d4dfc80461aae5ff04c48a41ac4aa0e1b0607899158a50ee6a1ea3fa20f550d92d8ce26b1193300ff740b401c3df63");
            result.Add("fa", "be9efcd62a328b47da36cd1cb585aaa0b633ffb4b989eaf86f1e0fff266dcb0251135bfdaad48dd85490466061fefd186975702aced8b242921068dac4b1fe49");
            result.Add("ff", "3fe9cf5a8de05747b65afcc671e3a5f4d7a2ff65e3f1ba1aad9442f308847593a71a9a8fea15cf85f727c85af309d255ff60c1f8b32eb869f8e5a777f8465547");
            result.Add("fi", "7eed1b93e9ea226b056c2f1c4bf01b160d49f21802f8c08bc5fa720c2f437c9c761d74e31db906ddbd779371a85df90081091fd75df46428782786e3af8e2069");
            result.Add("fr", "65a4b5ccc86490e969a2a15d99746c2171103c76dd6a4e8c3911a909d01ad0e8a6ed0b8e38a3d38e8cb4e7295bead6bccff906338ce1d595f334e8fd1b664cc6");
            result.Add("fy-NL", "6f81fa0dfb6f745957b9207a8b9b7869b4b076bb5f09fb6a43e907d5e6f70ab9ace5173cac3fafafa93ee7e92a535d59ba0a4c7ac88cc0e08915fd2bf989048e");
            result.Add("ga-IE", "a2ca01bb5fea5d19f64dd76263431a5abb007876e03c0ec7e3140fa97141a5e199a7becdb82519462fc35261a58f8c923e073ba1b654cb8c1d72d233e8a7bbcd");
            result.Add("gd", "c087bb0af55a4ab6aa037e232812e806328f3fb6b2590275dab25d50e043e4bd81628a1b00be6f25afcae53a2973b5f8d3b1d30a7bb8067b400b91787e0c9327");
            result.Add("gl", "51be3e2f3fc6627d9794fe9a9e8a81e79c07f9791953c8302e39aaaff6ce3867cca758d09570d3a6193ab8797404fa76e5723166625f2775fb63126500064a4a");
            result.Add("gn", "37635320ab2e7d25398cf1fd31fd92cef4782859b506b251b87e45731923ac64af87c68cb45610d64075243aa6aaedfa703cdd3be6b2812881c0dd764080b1b5");
            result.Add("gu-IN", "5f3d96633e500358f2d2ad40920f4a3cf71be3da00df5388b6ea0a8cb64bf11e26c8b28981294f984cca3063e182e1bbc2e3643e363a4e0b87bff5d98e7b2e55");
            result.Add("he", "7280afd428984d4352553e01b4f7275d0b7e248cba9b1bae2ad8fdb41096583b56d033e4ab92f003dd5163459f440fc89e215df4750856f20d0691377c7f55af");
            result.Add("hi-IN", "0a0ee8e31941636c732a5257da2fb31cb6d09160c285fffa52623effa790f1ce96ee90ea86190eeb8dcf6a33d4342c61b2586e7bdb64d3a8e6817784545ead86");
            result.Add("hr", "6fc185e4fee525e861f0f076688314c5736bb78eee01bb7a1335c2fa940fa9e90cf6342695ba4f931c8df8ef2501b88463f5169a628dd7b82b7bc5c8e00d78fe");
            result.Add("hsb", "8b491d0796cfe3b59f1538f4b72d0a03f9ab1784680634c361c8b28b5c0940c5fa8b7771bf2b2d2c87a17f4431ccd928c21bfd49948dc2f0384d00e311bd4da7");
            result.Add("hu", "f4ce2fd424e079380384d9d87c09446a4747ef67a9d0d96281d4f38cfcd2bc9fc29409ad6775eb5e3b7f50231cdcc44751e1ea536b9c541ce67225ba1d20b7b3");
            result.Add("hy-AM", "56418da66f8a660ebe35815ac13ba327a546d6794851d1c4842ef94c45da1983d5ce870236812d22b9874015618d9690fce47a7d11f8c9c2d44ecef8be2b1c68");
            result.Add("ia", "b31e1a7f162a9cb8c46e50bdafbefbc5817be63fb7780abf41d1b113ed34c1a1118e80502947cf9ae6192e62e0417c09ee95d7d5a5b4f6cc3448bd059af8f468");
            result.Add("id", "f6393a6f124eb1697d484a1ac3bbbe692d6f0d12d4c548d128d488f27bd7b50bc0fe90e3a5725c3107a8649c06447e9a3a48a435fb8556069a5228f869d3d3fc");
            result.Add("is", "b49316fda4d7f6e46349279d7f62fd786fed8cbb59217a2504eb7c703b58cd8ebe65c0d0d90ac387a67c3c48c981ec2e21bbf65869b90d21ef4b0b7d9ef4e296");
            result.Add("it", "b546c3050c736cc7b1175cb698939ab5fe08fe85e74dae711c3ac4145e35b7567b0024dfefba81461e4c260729193c444f7e2f840641aac6b8c50c75d0283460");
            result.Add("ja", "9b455a7820254659694bd19015add24b7e08f152f7290fa097aad8348106276dd11484b61090db5f49d1a0c3974b68a912f981a2a600d071653409dcdd6f19a5");
            result.Add("ka", "c36c31670b26c353a76c91174179a281b4db9a88793f4bf406f3ac8e5974d255a7f0a4ceac90065b684bfce3cbe9bb2bb4bbbe56471ecdd3a4dc29a2835fa0c6");
            result.Add("kab", "105d9b28a661ad7b4660fd96912a9ed26f5129fbb357c8c68d2d33c4446bcc58fb00cb0ed049e922cc3a89720914a9b70eadd2d4498c126d479a55421eaa4ec3");
            result.Add("kk", "f183e1fa585c8e5eee1dd053c9898bf7dd491586f209545eaea35500248d85b7170848d0f47e6fd35b6b958e427f73a82020fa1e94c83d64845df6eb94f9006d");
            result.Add("km", "6c48ef75e7a334fea74ead5883b3b3b1b176b1523290acd535cbcc653adfe88116ccd0361e0ed442e6a3d9bfa27ed42b4badebcfc65af7a40790b301bb797eab");
            result.Add("kn", "93ba08e2fdcd816bac856af8cd71755d58e05c3fe626a63fa11f74f894fda9310953f232b4b17dc116d50041bfed22afa040542e662908a7aef4c783bf254f4a");
            result.Add("ko", "b5cf28ac500dab6e0733107317f349e086ef81b99f07e23d927a811f43eac8c0f7cc323f384c275e6507a756659c6bf0962a7e5e09501a3e41f6894f76b5e002");
            result.Add("lij", "f9746b7acba7b103552108c072298d257ec752c70ab13c8711614d81f0c62f7ac710137a7eb7824c89f34b9f517ac9cab03f93f2f4033c2bb45967a1509937ef");
            result.Add("lt", "251112b52bd043fabde02298b3fe635f712b802499fc95d57cdbf7e07693e2c9cff93e280408d9791a64c1f60f21641f435b280ba7d4ce3f44c099ad9dc36b16");
            result.Add("lv", "348adf1e76a918afd90a851fdf81fc8a3ea95c12e5ba544020159692800206db946b7cb0464d2e64ee38355875e4430f881df3fe63f811e143e90b2976b8c082");
            result.Add("mk", "3428a4823339f695258779fc817edddc742c13bd213f05a2f4d193dcfd6cdc33355989d70678dfe81fa582b795ceb08bcbf72cab8f64778a518ebb7151e23060");
            result.Add("mr", "e5e3292dce67856dc339a6e5a51566d322f953b8a81c817e57d32b12924900e2cf9cb579748f8d342f8c07fff0c8da5b20335583c2f71937536b1413e5653cd0");
            result.Add("ms", "7388be09fdbacd9e66bdc05b3bed17cac403c315ad5c44ea57c98194ac738798cd1d45e5b64d7f6cb8db7069a58c0d912d3cb00c4f7e8625f29b2feecb1acef3");
            result.Add("my", "5883e4c6a168277f3a37c42f3dcaffbffc0e5e25848b6edaec3b6d115c6c48e319ee57d53b283b9efd99c1cb6c67e9c6367a7e91cfafe0983d7dc878d8175690");
            result.Add("nb-NO", "1b5927a95df6a6c11b973f2d573221b1d5ecd8e85b40e0947ffe110c68ae61afcbce632702fc6b4e22195dc7d0ec760ac1b75c0e4e25eb00a608f3e0138c2e25");
            result.Add("ne-NP", "d23035e56cec51f46a0fa9abd6a2f62e341019d58b901706ec879b7f101e9c2a3f4c74cbd307f674dfd74bc957a838a87c96a8c3243b876462c8685346479fe0");
            result.Add("nl", "4d4d6d95a5e0fafe5dba8140c0e22b9e5cfdca752981beb14e6844ce8d6493909aa1ac9b709533e290c199937900e5bc92c2becdcaac6673e7642ae159771038");
            result.Add("nn-NO", "7d2731d24d75a17aaa49fedec898f5b5b5642b1f71859368e1188666c435422f9c220dcad7590ece432b77ca36fab474900a7943f46c6977ea958c985c162a03");
            result.Add("oc", "e4d9cb6a8ed0b84c9935b31c73ed47f29bd51d9ceb50f5f3da45ac772aa356f432dcf204847fdbf603c9ba0550c440c3cb41f50dcf2150fbf07d37a3497165c6");
            result.Add("pa-IN", "757b30aca6a28da494e3c5c47185e135fb71080fded8588d6ea9cd7363db89c1942d18aa62f80ce88126b43289a36b73bfaf343be519cce2aebe6a6711328068");
            result.Add("pl", "8245e01d5246db0f98057041ef6835c647fafe6ae5d09bc00a3fd1433b7d4d279a364ff1603b1cd7625cda46f7f97ca96addf96cc854c924cdb066bc228ff7dc");
            result.Add("pt-BR", "0a5411bb8bf846d9903614313ae018b7d8ab94f678853e524055071298b9b342a632abdde958be7b4cd477414092fc1e3fd6f06f80c5fe2d5fa0f61e1e1f578f");
            result.Add("pt-PT", "319705e936e423fd2fa844ec9b36df28c8720d4c113265a916e6f0205cdda57152c31d451d16aced1506e2fb1b12f35361d120481c68e2b8c2a7d5433c903af5");
            result.Add("rm", "d33f06f91a46a8dfbeeec12291c9f9f73f92b78c8651b95f3ed77c59c51288f2cc350c0231b80cab214e5394f106d9acfcc7cd3804fe778fadf86976ee643d02");
            result.Add("ro", "f5d528c40f6c04bc4f06f417c676940ef9428ae0ae9b5658a3280875169eeb14d022ee42f31551b34e843496fa496c0e00045077fd6e4e301ef95c0324dcc27e");
            result.Add("ru", "efbfc532ba8a72068cccfd387340d6110cc5b3d5aa8046fbe1bb52b3fe9ea7a1517b0af59302c36be577c00d4e4669e7e1462bf928f9f1f9619b9287f1fd7ba0");
            result.Add("si", "797b0220e7f0382e8551d3b86ab746ae057c301bf328db4069d99b3d286071650038def23743c42323fc89541e0b3703c5b3a2526c79765ece09c98d4ec31e96");
            result.Add("sk", "f6a69265f289c17c80a56a58b5e81c061f32c0f112a4c79e8b1dc6f7f084a357a5226fbcf14cdfbc92cd9b771a1d154cc4f2f5ed592a10c13949782fef946780");
            result.Add("sl", "87b3ce8e7cdcd95df26d3cece00cb1c75d5d339d259b139334a12a61277fba03a6c7373e0de407eadf45b8a89d40f65759c72925e879186891a1abbcdb24f5f2");
            result.Add("son", "642653e1580a8c270c92fe120fa101c290659f9fb33370ef2319870c7ea33892cfce4cd582e28ca65837bb1968f93db64b6cc0a79a25e74cd7b9f4c13a7e5b69");
            result.Add("sq", "dbe2aa6b8a8d5930572715e6d3bdb9c4d8a14f0135d3d67cbccdbcb2d68fc560b463f1a7af5ab236913869fea370778e2624e2a824efd623931647b457e485ae");
            result.Add("sr", "987c0912626f051a08b4d5b16dac6efbbd5dbef74b25384404215a766f7e0c84db1bd82dc55fc89f942b4a0f29f7959e0dbaecf531963513094c35b3c51ba2d1");
            result.Add("sv-SE", "cd7b16acadd04e1b99e078147fec0a728caf87e798d817f68d807e9c3d277a9ea6f995b1c3cd5ca16151ed9d40c584ecdcc3f0734ddeebf88168ff99d25748bf");
            result.Add("ta", "4194c8a01925a22adf2335535bbd990a63e7ff556446235555e366aefc968a8d409a20ae83113984c8ff63c5d78d5f8642112531f9ef0e645783ce4b2aee7542");
            result.Add("te", "fe578dfa6fd789112ccb6c62c9ffb4aa85794145016578fda01c674a415dcea2b1ac94cc34e286b7e488e56dd8eb5b42220bfb67e5d91110d1571c10eb0c0744");
            result.Add("th", "e09ec6e2bec29c5591d4e9ebf209f8fe0260e22d31af1966d7f37626ad5869ee5d255d977785e4b1be1ed84c5ae237977e2c08a0e8562dcd16105614b13f4415");
            result.Add("tr", "281a050060c3ebb528687ee0d54706b9d60c60a01a82d356a65314258f011e641a255d49a4de7ae9845e73898262c1c6673dbe299501c15991e2897e7324f9b7");
            result.Add("uk", "b5c5a9a230d6718bd5691df02d42f2b5788ce2316022870ebbb588db98e8643bddd7faa8e376d7e0b48ef7104cf173def343e14760895f2a176b80d998998377");
            result.Add("ur", "97eec32d1cf7650285f4e973d537e07fc3078c8644dca3b9972bf4957e44669895cdf541c9418ed091cf95e529b18b019456f11e8056452e5a9eb3612fbf3c60");
            result.Add("uz", "7cb39855b31db3acdf50b302f340371b627221ca998a70b6e26ead80ce79c4c257dbfef9c7c00b8d061c131aa1b6f48b63d652ae622580e611ede8b19b9a945f");
            result.Add("vi", "19a9de34b7caffc8abce9cd1e3102c5379a7a992ac2e8e37a18ef8b73208b76989bff1bbb5b5834d38a4265f592b3041a4d7c46f26ca53159a5f4498d2ba6919");
            result.Add("xh", "9929300fb5eabe6da11b71bb9b096273637cdb2b9b62818c531f7f01e7349b2aa829f28bcc8f4993f1ba130adace1fd761669c2e8988ec77ab1ec73c7f6a3f23");
            result.Add("zh-CN", "e7cd79ea38b1d407c9ec06c5421664cd8ffb6f2e0167ef3e7127b98bfbd0e2a3365dbb4bdfd2ea809c0cb53869fdd094e1e616d2c027f18e82bf32f6711b2de8");
            result.Add("zh-TW", "545de4c649d04cc3315291b1741f53d54aa2fa30160d81f9d00f4ca3c84f5a7a24f81115a116b70529fc8f7c96f3929c9bebeefaf74e200a0148642d5a5b427f");

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
            const string knownVersion = "68.2.0";
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
