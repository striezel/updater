/*
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
        private const string currentVersion = "141.0b8";


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
            // https://ftp.mozilla.org/pub/devedition/releases/141.0b8/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "73b360275945f71bee1ebc327594a34dbf63169d2392f94b6385b8710cca0d39aa1cd61639c965160a6ac5834c273463e2d9fba188d43bed3e1cffde846285b1" },
                { "af", "71a0fd0e8f11817a28262807f9b965879f40703fb7b2f90510b2562385c61295d2c0d83e4095d35a60903a3cb140eafc1a8dfd834e4b524eac059f98c28b7e17" },
                { "an", "49b03d50f89ac12c71a900e95e9bda9fcdbd622c4003ca5ec03a989fd79fd25ea0ef1bfe174f94e176996c10ef3936ff9c5f2c7ef4628a57b584e769cc5252bb" },
                { "ar", "4ed2bfaa073cf473f3ce490400b196f3387b94371b9a24463737c73fccd5911d6fec0b529f9055706d99ac8ae47b81db9881b3300da0398267c96f7e3ae4ce99" },
                { "ast", "7ea87a91a787d0e3de1858f5b672a0a20e09622833e4c36bcaa53396c54ffcbd4f3074c4569c06ef7815f7fb360b697e25ccb0c86e8c73f0f6ffe5b7ce3cb35b" },
                { "az", "9aba9ebb62c12767ccaa2f11024d5b240df47d1319a7441338e53861c7501eaa69e68e92c7978af6196df00fa7cc92563bf3ff76e477cdfe86b84ae41b0d20fc" },
                { "be", "e7867af63b610ec896688eeb615739443e2b15885631b0a9850836dbaba1fdd7ffca73b43ca6c7aaac763bdc4af014869a5a1bd219243419dc045f7e84c5a951" },
                { "bg", "4addfb2c459b19edbe97211875e5378567bbdb5b296db70a8eebefe42e4612b182fd6233b85a05951a2d7eef3862fedbbd8672e85e547270e1b092b987b9e682" },
                { "bn", "5539a8cedbadb29013a9712e8f7608b2cccf0e74a1353965b840f8801e2ff470c68dcf7ff11df7d489b479e23852297690f1471c7d27bc12f9179289939220f4" },
                { "br", "15a875d4edbc71103752dfcf6085e6580e741ba58f0bcb515e201a718c0f74867cfc64de5268eb29cced5a703a86e6c19be8b3bc2fc368ba04d4fba3086623fa" },
                { "bs", "b81965c49420168ee059c3f8cddcc907b356ee47327f178e1139e0b40640d4c73f249c2662c5e7a2658bfaa747baafb924b341ec0dfb76c2e0842f457cfd3cfe" },
                { "ca", "e732433c0b6cbb9b6fb3553b29c375fba918d3b266c32b4aafcc59cadecd82d00fb7e3c79a4cbeabd3ef1367c0f7f364051fd13eb6512d2cfa354d327e34e46f" },
                { "cak", "b12c0aa21588ad580062fafb5503672b64cf2b33a0521090b85ddbee3fb125eb45adfb76f3ce9c76a96ad8ed5616de195b537d84cd8029ce6fde630494b0c1a8" },
                { "cs", "f597ae09b1fc18c49615e11678853ca47991f1dd7b5a364a5fd623d2ec6e6f65fdc2d19d242598c83cd2df7f709f26bfea86d191efb9d44f39f611f98d631329" },
                { "cy", "8967bfe3a3edd883a71b6eb7d1427f0551c33a4b8dcabd774c807c085ae9afc9b98eb961db075bb985bc12d77576c1bd3b647c36143affe40b9110a2e4bd386d" },
                { "da", "567b1068fdc9c6b05262d07fdcdff2f53648a81f4185b4511f1b2174ca3b26bca8d8f274ab8d3889a437bf825859dfc94ed6c19ee19ca9f01598214d0e6ec8e3" },
                { "de", "692609afbfd2707daffabb039022a7cbaa3ed5e01403047e60dc012a6cf21843243bcb40bbae00aa4bdbb4ce423dfd48ee7c6cfcbaa5142a848f51b4b25284a2" },
                { "dsb", "8f883be3ef12065c18237c229248ece9b8b2fa17e0418aa885cb697f61b8cc8fcbf74023334c0b04062b9030c8ac3feda6984efc74dec44dd0e7567358109cb8" },
                { "el", "3c576397473474c2d3077392048a0d69cdb0dd25de2b785516cc43dce16f4e46f3443cfe19fd1c1296d9d99919d1426ffd644f04025a86657f422f68eae2af85" },
                { "en-CA", "6000daa26de2cb899fb6a24de6339b734b3870f17cd00cb89af9121e81bd9f637d7ceb856fb8d5968fb47b4ce1035278538bbbaabcedb072f5e60d38f781b86d" },
                { "en-GB", "db1d1b948588b769f478288298d1361a3a6926affcb788eb5d2f4321659557727bfde23b0536432c6d27a92b88b3e8e32a6b4dc171a49e3368112d3f84ae78a4" },
                { "en-US", "92acb013a558fe98dd832d6f51b165ad4ae145261d71e7cbc1dbc083c6260fcd86fd495b27590c1c9e3c2e7e16689e56d0ef91dc43a0bceb4fdaeaf1ad413d04" },
                { "eo", "9b15d1f564fe4ff0ddde55e9d9c482634d414aabdbb3210a7403df12834278b0e759958d46ce223df90bbfa5fb37f6e94bc8e16b11ca11f814b276109c20c0f5" },
                { "es-AR", "ecd8f121903dff66ceb48f45803ddab4cd1cb58cce6946980637635fd5768a6753b7a2c89d124a189cf21eb57b8c63a36754e95afc227480e446dc9b10fc3ef4" },
                { "es-CL", "907fc18c3aa79fb3b49908bcea289ec2fffdbb3586af97f898d93bd3c3bc4df00c82a16203613656aea8ad466a2b04321928f8bcaec265b580ed1ca64e6b6840" },
                { "es-ES", "25aab5c7cede16f82404cafbe85eb4d9bf3b820b2ea67ff13cc52cf3bcb7a7fd166dcd934810902b6157daa44c222bafef711a3ff9537576c0c4c8f6e6b74d18" },
                { "es-MX", "6a6f81209bd05e79819345bbdb18bb257c076cdd88cce07a7aab06ce76064d2620dcb53243951b05e803e2ac62d11866c77e629fb83cf78b64d392a8dd0ecf89" },
                { "et", "e40374f991fc22fe1c4e6e1d677c0fb1b3f9022abfaac7efaafdb315f18fe8302d423df3919340efbb4a7e61d3f799655411418e444c180b7e014afa2920ecb6" },
                { "eu", "4d38204a84ba9f684c2d3f56d689a87412600296706c6267091a302dbb140811f6f38850c089eb5b09185c84cefc142acd5640bdda3ad2d68aa268c6969ac756" },
                { "fa", "491e08cb1d01336f9cc24e14d320c5c064afeef4ede94746d1b16ecbc6839b58cb625231fc989772525aff4daae8eaa4014368bab21bb056ceab640cf6328f47" },
                { "ff", "a9da820c4c73c4204ecf3aa1fdbf977a381976e702b641f6b54f3415ffed040d4a94976a7ee138fe802f59a9993d32f5b8b3e594a96a635aa6c0042c1b32b86e" },
                { "fi", "0c75103187e94f9628bcc0ecc8def4a3744d95bc33e542775bf766136251685156724c7a9ee51424e180a7d7ca854ea519263740bd3335e0718d17f605ee5432" },
                { "fr", "5a39b92ca6d9448d2c91c07bf9f8184aad16b05be82ad78fc9100186a61cdd50d870d250928c26dc9a191eabf4bdbb0b5bca8f525f5c5169d99f2c20219bc399" },
                { "fur", "1328fb9cd5a87278709cf3f1cd57848c6a2fc49d19016bf5251ae4582e194a4ff76d42f6555513cd99c1a7a8b82a38446e83b63037cef1d5d2f1d4681965e179" },
                { "fy-NL", "6563ce69fcb24bb2217c4295b9e668c1a0bffdf747a549d3211d557504f2c06f597da37b568fab97fbf28abb65ce3b72e1f119b0b576616404c59945892f5212" },
                { "ga-IE", "beac9067f6eb3bb35a173e6b4d24c245eb49de1f2e9ee3025a42cd10cc2c08cbb378e863e63589cd179d277fedea78ccca82fa86ee74497a6f4e96342ea0d904" },
                { "gd", "9030ee121c5afd23d5240c1762f79766299c5588697d2778ecf8a660042e5b838c4a85da419151dfdcb3d31abe6d8df5f16753cda79af331224ccc6256dd882c" },
                { "gl", "c40605b7dcf700a885d6a44388d1cb725c3c8068db11e9f0c4f2c784eeaa6a4e361edc5b8d733c0daf889f7fb2ae7accf79dd43c8d38852b8bee2fde60b147f0" },
                { "gn", "96e505e984554c42f9c2216e88eccb00278e7087f0a25810aaea4d63beadb0fbe73663e7dd9962a220e26e846da47232478b32cafa9a8f90348a0178e70d154e" },
                { "gu-IN", "9a2f8820925f316bee27f1e776fb9baf0fd0c8f358f30bcd2513cd0226dc0ed1285f3a0f3545a3f982da3d2bead30aab48af5015abace15692b1ad3ce8dc2fbb" },
                { "he", "3a3e25ad842e01617cbf4c7e715b6ba355e5eb42fe7c1dc62ad397b1a847aa945d359d5e2b09258da8464b25e02e16e18f43ea9e45911bfc860db1c71681aeba" },
                { "hi-IN", "994a91b6c3a425d4b8eb118a5ad4d2dff48d536ce464475c7d4315e8d2cfe6966e9e636613b34ce5db71714371955947491f000f3734a89521e2b636f889759c" },
                { "hr", "081168fcc9390abb0f457e120d1535ea4fd66279a6a178eca43377a758b932cbf46444eac03f55744e1078ee19d8cbe84e0e7cb230c1891e6e6147f6cbc70305" },
                { "hsb", "952ab620865c2646f48aeb0e2a1f3f06b5fd5173c4d9eb0407d7f5d7e6ad1c5305d9acb64d171f18da6fc6315fef34a29648f1c53280a0764ec5733412c4561b" },
                { "hu", "b5b91b5e2ed6401e437d0b317fbb31949666b03e604e7a6e3cb7f5c1c88901e035b5de866ea1b4c2b8aaa1f8cd4bc3102cf44578c6a1e4a9427dae5c9592ffbe" },
                { "hy-AM", "bc0448fb249289823a3ef485c6fc0b9eb77cfd1d3f30b4f816d3ce339ea910d51a6fe2d70c3e5648c2383187277efcdb9d86b03d5dac51a5408dadb78a4ed1fa" },
                { "ia", "d0173902f7af7659b1c08487b9ab1c49043802fbe916fedf8bab557a094d5d06d59c71b7d69f59f6c782c38b9c298459459c88e86664cb35866d4aee80e2ed6f" },
                { "id", "c52969f54cbaede5838829454c50c1dc1678932843154a626539f3ad18983a1e3c3d2d0784c264df9a16890443aab55808c32cfd3fa559cfeccfad521ae75fe4" },
                { "is", "9c645778bddb11386717493647584778fbd6e153d5c13d092153de17d1085315200952f205d13319390e7203ae5250482d4733f703108f07b5f97011044c4d5f" },
                { "it", "702df386e01daca54d748a04309e7683ab5da49d180dae85636cad60cd2b64f98d365de6cddbb94fe634dd0fc60b7fa40dbebe37d12fa36ec690c57b0eaa55ae" },
                { "ja", "0ca13b3946bfc0fd152b4988dddec6c20df918ae87b0944f2cdc6e7011eeacc1381a6c1f69bf1bee26731d2bbe47534a38fea61f94e9bfe2a959e7f1ea0e1cb8" },
                { "ka", "5778a26386e938d547bc79c6fc245cc2620f7a0f639a85b92f3eabe6dcfe03d81e4fe0f8421f3f90f46861998666c6e6caf5157e39b0017203a6da53173c5ed9" },
                { "kab", "9a7ff523fbcf73c05895b0ea6b24ad7fa7cd0274290ddaaac54347aa6a2528d9f599f808a05f753aa3fabfbf5621201b2b37ab1c17f7fe7c60dcb2d1bdc6fdfe" },
                { "kk", "5d0ceb86e612e85295b542ec18384827ca2a6ab5e7601c63e85c6ea9712f640be759a4681f6067a9c911ff7494f5dd273656534b97b8cb2f63be241c218ad11a" },
                { "km", "ce9e1a24497660e9c99e74443ae608d75a5c85296fe5bcc4e2e3b074fa2869603bfd057ad48ac3749ba4a219f52b9a4a9d6e00591e3ad22e1c29aa85eb7455e0" },
                { "kn", "f0927acba3e37f3b50a2f44a762e84086dfc31b26f773356a865178eb0b7ac158b3ab1e5d444af1a1f68282900a710cbf7735c96c211f36f1b2ecf6f9f387f14" },
                { "ko", "f7ad57b08ec13b4b9a03657149fd98da0a33e6dd5cb2bc6df938264c467e3e7df4291629fbad9ee6f01967e56cd3d342eb251e96d1b07698e1463d02087fc592" },
                { "lij", "01ffa63078827e99a5509eb7572b6a25e58a60f24b77d8e8a8e21786d87ddde29dba4bb80035c3246492df774181a75ada9208f59eb245c9830d30e4320a70b6" },
                { "lt", "cbddcea4d4f17fa7df0704903f72470b97578ab79e6412c101fdfe010b157c5dde151bbc688f870ace1ddbe2528120d12c37244d61763b6684d5785ee8934e8f" },
                { "lv", "71c5b749ea88571e485558e93c55bbbd07aa9c61c56f46e88eca2c88c3ee9e9fa51d0a3ccea70e710d8292708abca44a3ab02ce31d8c5e2c360058f1c62f4726" },
                { "mk", "8151f7d0d8e3c12ee67e03bd00d4e0e1d63ea07f780a0bc16353170d2fa46d4c17398df5e3f84e4b13cc6d17ad3079b95654fb1177bdfd54936173fba2150521" },
                { "mr", "a04c4110578633d68dfc33a7955b6db1265c5373e2c7c4e03349d4afe6e3056a08b29d2b467ad7b031397d0a348ba75d59d1d19189e4f81b1f745a272cfa88a5" },
                { "ms", "cebc154f3c23f737a53b9abdee1ec5305c61b7772b1541d6d3cde7863850e92ea7f0fb9a23b00c99432c76db835b9cd3b5e506dcedffd108eb04619501f00756" },
                { "my", "a8291ab5e2df262c15580e4187b6c6a1560f19032d17ff2691e72e6a4105eecfb10618dd0f75c7fdd7d2607a351dfda057a6e3700fd49a5aef2aef02decd4a1e" },
                { "nb-NO", "ed17f6a2d2b77306c532daff9f9511bea9f57d2e03f7d2f12a3c99c092992419502e4ee5df0c1f11a22f2fe60cb6834e02c47da8709c655ef398eb0163d1b94f" },
                { "ne-NP", "1566997cb78985c3a82bc5deef2b32dcb814cb8796e6dff1b8eed2994e3d4bf8b651dd68bd723c0f017b1651f4fda53a9481ff50490a4896eab1f89abc012537" },
                { "nl", "31756e73c9ee26e4f5e519147f262d8197506e0c73faa35e82fedd4529fe9dfce430640e0a29ebd5f158c5ec1a79e7984e8624065f0d8befc0ab79e5dd7287b3" },
                { "nn-NO", "969247769d05d7947147a133fd8f7248dbc0e35c1180dcf8c9683efb79e298656e4c142b6a172e04a79c8c644c0235ccaa67f7e8cdfd5cb58fe281665c3025b2" },
                { "oc", "ed98512f4d0014edb00a3e2c4f9b1898ce190a0c85bf72c2939aac455ccf22dd928c6089951dce96c8e5ea32b102262f3a9b32d9a2cb90cdbe1dbc9856ab134b" },
                { "pa-IN", "996f0342bd12a3b4672ac9f740cb04074fb056bac2113c5ee5f78e05b3713ca33ee687998343692356a0c6e6b932668fa1222488e873daf70b98199b23990cb7" },
                { "pl", "54105c4250573f87a817c7d0590639e3dce0b045edd28ebf1b3e864bab4ecd4f998c1c20f8dc0f0adc409336d955c14cabbf596c252e7cf13794c6ff08637f96" },
                { "pt-BR", "b1ac55faf819814b22ef7a40d6adb92da55f7e5b0962ac99e35023f3a735de3fadfe65ed3ece07022068d06b508a45c9cdd41f846b2d593f8121962903741eae" },
                { "pt-PT", "781d81973d2e712d8b28c98a5f84ffbb99f1f6f1b19c927a0be107965e1bc932772549b2e02168f095233205f948408a434fe869bd14120e7dac79fbbe13f932" },
                { "rm", "0f4fef844fe77312a89d50ec23daa288a23232cfaaa3974769688f624493783f2c64965e4febe3125e0d80d96f2752c93aad4b574cda4fac550ba89bb45ac425" },
                { "ro", "bf18b338948ff9081dd34a49d744e3f9fa781c3707d4f02b0a6770597fcdcdadee8c64cd63344d44e47f6814169788ecdd71c20a5afa662c1c4822b076bd812b" },
                { "ru", "d369c19e8dcaa277fa801d11f0dcd97109a7c011245f55b032e52aec73d212d37bdf0cbe2b16342ff3ca8ea6f33828d5cf621f58728e1a980a5c4b6e803974c9" },
                { "sat", "6f04c9aa3eb38f2e6155b0bd2f198c51f303b1073b8eb65a46c91b504b6f4195b0e03ce41cdfb28ce2017dbfa240d7dc302426697cba4b4f27d9cad306dc2d7e" },
                { "sc", "78f27b426f7771925bb9346b0f557a39816c5134c0f0b2d4575d0900650492637ac89296a82f5f54491683c9ac3a9677eb8cd2099dac6f6aba14090bfdfa7e41" },
                { "sco", "686834d14f476bf0372aafd24ee1b6f22da178c8133386f40cba3eb9b03e7e1abc006b58d750eec9bd62bc4416462735ce2879be3bbf0b523a06bb2e5026b5f5" },
                { "si", "2e1f58c5938a03a02d07b558e67bba9a72e9598cd4a4899f72c8e08cc6dd15b8480b5465238576b9a085e0a92b9d7f2bfdd53485c5a19b6c318fea5a166a34c3" },
                { "sk", "8f915d43db893b68c3bdb66ffe39e4c7b4c58216b60c5c8e1be72839c8d81cf1558aa2af9bdee053718a851cab23d1f8e21bbccf4611d7a91240835ac879e189" },
                { "skr", "2da69dd5f5834a19d531550ec5ff4ef588a771525ee1201fa680c7a50578ec6aae6756da25af814b61929eee2eff89652bbe392e4235e468ad74b89af5e2e90b" },
                { "sl", "ab0094b6bfb32545dcb64004b617f030ed49e593fa2a50854adba0fbace9723ad2f0aa6a8aac4f4ced5151d8bbb6873941e2f60c6f6be5498e811377d98dc895" },
                { "son", "a7eae5be7b06cf388e824b2aa1eb0af2582d858931a9acc8981e8c912310f02f1384460594ff8a4c7102f9a2626c196f9dbe280f1312d56a155204835a4a227b" },
                { "sq", "152d00175736616ddc6bf3dbef65c106921f5485309a96f9e19f8228d0d40da00045cf44833b8342c5c2f9eb3939a54c8362102a4cb2106d2ad3deefaeaf13c5" },
                { "sr", "c6353c690a9dd7e9b2ba1d693788847394f15208f38cdb934dd8c6fed15f9dd1e27f614bd8eb1241f653b7f597ed428cbe9697433426a1914f0c4b4ed3668f9b" },
                { "sv-SE", "2cef1e5916539d100588b3134e9f8a1eb8a390d37bd543f8209934802fc4991ee45cb7e4f6502da10b157b951e9335cca692a119bad52b7e89b3772b1526907c" },
                { "szl", "e4a3a5479206e86eeffe369b87dbd41a466e62aa780917cfc004b538770266c08a62d86650ed5258b972aebf6364b36222d5eaac58f68b84dac87625ef2f7f76" },
                { "ta", "e67bc4a7ee353c748f5582ab8cffe1964e5fd5d45169cadb1d1a4a1ef715826ecaf168deec8a500a41b2fbe30dd9a7e84e50070eb14ccd7f4c4c9633997aca45" },
                { "te", "527daca6718642eb2049fc9958278f4e8a4c57b6018131708103439c5449c6b771af6158436307b941a0a20f0fba1c25577fc05951dab462486592a86362c440" },
                { "tg", "e2894d21fbf378734c16a863f0315f12f42bf94c441dbdb482202df8269ee512a45ad6a25e56384209ab674b36d12ca1c9c61ae09c07b700763dc5fb8a2dc295" },
                { "th", "dbbe1f93cccb88b1b3ef8e1d344bb419c6002fe93a413b5ab439af98e583e205b0502e15343ad5097de8a22948cbdb68815f4214cb743c9c280c866ed082f1de" },
                { "tl", "eb2244040603f939f594b85fad2dcdb73025d233142a2af4b1189605b0d0b50b4c4051936f0040b5df52461be9f7248cb2a7ca1f0b90cf9d6a94f40ca29612fd" },
                { "tr", "f9ed26a5bde340d566ea0a347b17ae96de9b1aa7a7704cba3ac50fae8d8948a71f6dfb9bc0c9dae50b8a56143d3faa6c24be16d9a354897696bc371f0248f4aa" },
                { "trs", "9dbb87d5f7a07ec10cf588d16c93b48cb21d7f0f78252072574a3ee20b11b2477d7ebefbd4922c0f4beaee4bc94942bf4f4dfe2e5778b67135f5c5555df89c2b" },
                { "uk", "09488d888ee4de540a745f2f26a8004ad277ef677a18a71cd427b8539a6a3ab23f9dd986beeeb7ad66ccf097c443e46f95f9e27757c3a7f7d30515788c31d20f" },
                { "ur", "79146a4f92b6c6f75a0335084c0aa1efc4e9ed44115aa230b67e6a330ee867d49657639a6577097074d0e98ce695647a42fa7a74da5d78779572391f54e1a690" },
                { "uz", "9c62763b9fc7402f1b5fde138c66b5b0229c183915ebf1fb63d0b9906d6b9e27afebb86ec6f10ee0162c23edfbe6873111f024294c4f320fa1b91e334c15abb1" },
                { "vi", "b3c3ede5fa8eef0da8442dfe6fd9a82154f64fd998c896911b2e1fa15d62109be420f32e675140873fba5e6ea8127b88d1b6ef07120e55ceab501094d5e72d69" },
                { "xh", "6e5b622f218020869aeb432f8ab25d01c2ad1c8152ed5beeb2fa5586556fd465872d3832bc0db773747c11e163737eebd9ea86dc53c79194c56dcec336f0de41" },
                { "zh-CN", "492f321063d87f7379c3b309202c5a35bffab7d3c900b88dbf0b79e76be9ef1fcf2e14ddaf59857d3c3f8d1ddcf9291a8931199a540ff63e303220dc48f084ae" },
                { "zh-TW", "79fb535c46b1972b679106ecf79c1febfed4d580c73be7879b17d582ea5df3ea51617cb6cf1a52640da943d469b35da124eb60cb27c56c2f97fd8646227b839d" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/141.0b8/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "ba0121313a0a8a6a61fea45eefe275c3846643e9c4e46e372e101cf713d3f8f7c58e80ea02f7a042f05b8de2f2486894edf2c23cdecf5c734bb57315382fb062" },
                { "af", "50cba08bd8f7ab73991c65712101d224f5e714efb5b6bf5c82a549ebb8f080503609fbf2fece0dc12f02b94ec3b8b5e8982087480219b9ec6c5dce80916afe34" },
                { "an", "e7d63493a06ae87a2d7d9416ec5f5198178e249acb0be9197283294f610073e824aaa4c5e263b851f2fbc2c9a9af20a0f77018127b9528580b5193af17fabfbc" },
                { "ar", "d63456799e62ceb8975bb011aff98390ee935c4bc8270deb534d851052c01b778c513e087d9d9d323a668080e7efa37056e211f4cde5bf9a0ebd13941ae96622" },
                { "ast", "1851f2741f37cc3543b3c4089fa0647297b10d9062e53a655bd51d6afe1d0f31aabd93188e10accb982a7101b5f1c966837b2bab0d9a057b1f1fd8df4145b84b" },
                { "az", "579ea9281fc50850f34dc5536f7c188f42c3e2584994d4b58dbecd217a803f2be345f392e31f7d65e2eb25993bcacb760f488b797737be421cf8429faf58ca56" },
                { "be", "80df34cb2a931c42aeb3cae78098c252058f9b44ad333a3783f35ce5a1054d1664252f5072ade196ca9f1b39acf42a1ac7e020993caf28c55db200b7e76a586a" },
                { "bg", "445001bdce81bdcb44e22b299934d59561fae297ae7c65ec0314264ce607b8125bbbcfa1abb107bfa06f60fd978a560f6900cde20dbb6e4e5b3092a8e6f05774" },
                { "bn", "c09a7eb2553b2da8040f9bee70f0605696dc7ec042c6afe4f4b561b373c222e0b5d5dd162f3d25758be45a8c79956e087631d455c2e24deb626474593adde755" },
                { "br", "0299e0f56ef0e81597324dcdb80b87b629dcbfcfb1095dd3eee753b978a520d5a64c3153405a097dff9edb1e3ef6a8ee245815dabcf97c0bc67c32bb0fdcbd4f" },
                { "bs", "19ca617ae8ee4b978f8110296e306f91b3fc337c466d7c046e7789bc8c0ae764c11ab3943aed9d3682332d1fbbdb21e9c13f08b641340c5b35eb808a946f8a18" },
                { "ca", "227a53f1beeda497419380b6d2de3ae8e145c0e19a88f2667e2400a49f072127dda9c67b9b1ec5eb91b4098e41664b50f9f02dd8b73cb5447808a6914e2df313" },
                { "cak", "51cbe328b4fca00fb9e42d4f5b9549263c51295b843c651c1ff20c908a667500eaefa10abf1d99336002e27cc454b5e3a26ebc3e0df565eb3b90b16038add5fb" },
                { "cs", "debf1abd4c1ca13a8166f8cb2d9092a365cea05019ad57bd999bb8d443cbc1c2d9cf01decc192d48eda3f76d028e8206413daf52c2d6ac8e5de1e9cf5c9517ae" },
                { "cy", "cd5c6c315a3f487c9e1dc0bac83ba9f4863f9255112782733ebe078798174cb74e243291fd6109d1c1dc0921e8a085e6b3d6493d60d089b80b579c4115259c9d" },
                { "da", "e8e7cdb7566c7a5738ced0f9a0f00b06371cda0927c5b1388a3dcf72316f24f53b097818ce1b5ea0c60d5ee34089f7f2296c9f140e1e6d3265e3c5c931683ea2" },
                { "de", "8c620d67c952a4b769f273721113b19bb107c53a6884341be4dab9f6c714c83c149eef8c9d893845683e21049baa4a1e0e44fafe6a3a1c465d03814e751b28d1" },
                { "dsb", "fd401b9a7df45f495c1fcdcd5fb19922486bae6d9a231bc58ee3ce83747917c01270a5a3c9b4c9adf06ecb534d89450214479733ebd98e8feb120325a748007b" },
                { "el", "356dc54e0ef04a226c098beca5125dade836fd8b902ceb450bd81c1762b038d41cfd5326bbce19a50da11ec74bdbd5794ba769e7fdc5eab1419df8066b9496f4" },
                { "en-CA", "3bb33803b0baa05e45f655efac0041cd862febdd0ddab542c9ae1ac447100405aea382063945c16166bba52e47fafb02f0e3da40f02603dd2af3f43044e92f12" },
                { "en-GB", "86a0f6490c141a96c6cbcec15914e80ed9f36eda1179619d4e047ad5f870010982728f2069afcc5aed66b732998d6f7512a8b64f3438058021b4caa97fe62f0b" },
                { "en-US", "dd2774cbc04841c5b327044c166cb21d5df38720541bae3295541241a79da4e61f0414595b4d14b5ef48f5333f8e749a97a8ed1e0d107577334f9ead6aec4118" },
                { "eo", "fa607329b6c71d1a9c80f0ff33ad1bed8c4f5a7ef088cdcd0e45933cf8820cc7578abffc769ffd79491f6d6a4b689a50e00938a2053573f9c4b0ec7af0765347" },
                { "es-AR", "5e6dac3a684a9aa8ce8d1e36102afed71e66a9ba7289807c25f6dad94138bf4fd7cb045dd5aa33c47d11b462c73ff0186a6f6b6990680f64a311354c9ea30f67" },
                { "es-CL", "d28ac74ed4a2fa4ca33ed07eb42bc1198cfb02365272128c5eea8c2ab23668e00d3f6960bfbdc23d02445fa28e1a56653eac076c5afc483924e7f8ed43138f68" },
                { "es-ES", "7f7ff26c95e5b234fd4dd95dd208fe7fdf0bfae11607e52195dc0c9cb41996d0c16a193abe8973e0198fe01a213c0e5763e94d8be6aad18736a7fd997ae406b0" },
                { "es-MX", "b0d6c67a36e99a4079ebfdf608aae440192de31e91c2bbaba8db2526d0f7ff079163e8c6b095e2aec5bd1da9ccf5bca4869743209bf30091570775d34164f7fe" },
                { "et", "8bc21ef845f97fab648699b0923e2c1b0d152ef7ed13ba02685e2cb7b88906372725aff88d04bfb3fcfef8d23350643be6aff8500f3611bd88876899d97d8ca0" },
                { "eu", "1c6519a967931e7db334720899daef151508491499423e1fb9bc560c5a3fa72efcc4e4973739792e1e1cb297dc14ed569917953eca4abd30318c8944f1089ef8" },
                { "fa", "6cdcd7ae5e1d04eb4c3687c6c9f357ebbf2b234f02c15ce689f2cc73a21e7b21bbeb514230b19af4087c13a0529dd93a55216df47eece13e44538f930ae1170a" },
                { "ff", "82e5534f5e113cd364732dd0fe5fa2ffe61aad3b6d6bdddad0a5a4c2c86bb42af4c6d4aa516a892bb62815828b04d16e5acadfab765c3d4f7191718bc17560fa" },
                { "fi", "8f9e785c0e6fc93d85d2b7330e363c809b189a9d900217d62109e2d90d4dda5befb1ab717d85d739059867c8b2ca2619ed924b8f9d811d2ba86c6662de37bf2b" },
                { "fr", "291d1a4681b182c3796aa75c442e8aadc42286134979297ae10c677d5035554c1861dc2a21babbbc813337ffbd575aa435c613888f62a78b76986c3172ff9417" },
                { "fur", "1d35b8f7704c8f0cdd47dd4ef6ec0a0381c76d058cb4cdc49689a07e20e9365be9513ddf4ea78e97a627e85a30d13826fef6fc1ab8c2facd423226c546d74a0c" },
                { "fy-NL", "8bdc1adb10403175b7519d5fe4c3a981dd4b0d94014e7eac4dd95da02aa88d65800e86df065a1b932f9b738a2187fa3313b8fe66ef32834f059c2b13362f9e86" },
                { "ga-IE", "acc436c8ebe9c70f7ddc14075b6fb843283cf78f82f572762e6b474d83d1a7824d7e29aff6b33434f2942e6de4022a0656a246e1bfbd0af14e1f604b70e1b4a6" },
                { "gd", "22d4a0f1ea0b9ea51a1e0c4309ab965c5a0acd525d34f23b57e4079e9636c9f5fd79dd28558da131ecbfcfecaa10867d340efd8073e772ff544c987ff82965dd" },
                { "gl", "ea0af45c332417cb424b5516b5e63113218cbcfb18a082ed4f7173ac1be91a2f6606c17e6f00b3f2e3e70d8bc413081d5f6068f0c6a9b5f925614e02830ffcec" },
                { "gn", "679a71b013450c178acfbd3d3acffc828450a71e7c18663948fa1b6776a30c53282c5b8dde603fe50c2d39576d7738f809c769d20772230b06cd32c147464e3e" },
                { "gu-IN", "220804fcf0f344d91237a6ee80ba528341cb27116abfee03cf514a11813952d30729bb8702bf3044e270c50d48a5a59374b588a17f214edcd48d49d698de11f6" },
                { "he", "69395768e23cd687515a4584d5d38fe78af0ef6528d0f777c6777a245e0da5e5781d7c5416d3618dbcf5b62be2486673eaa9786a2bdb529f155509372726f161" },
                { "hi-IN", "09db15f0410d878bc85e713a1a746d6b9043e14de0cf072b68f34a7ea618878bc4f16feed7c5e0c0767d652562b88bdc0d061f21d45651569fe6c48b3a89879b" },
                { "hr", "6488cf49955b9b362ae4449afca4acadc4b42c97f567230b3dc3cf330245027f0ea1df5f5900bb770983f3fa38da48ba5ae4cbaa48ddc08d1a937dddd803f1de" },
                { "hsb", "23e98cf7d1a6d0522b16ec057ee0f0da699b84ad07564d7a91e79b7f08a4288bd9f493089b1ca2d2c7a37a214dae3635c4461d8f3c14e003c680c01ce61777cd" },
                { "hu", "f86e300b7453a8ef6e960b1a6d4aafe7c49ac3eaf77c426bc38f4d848b389de5726d4a8880223f9ee3296d70487ffb6078ba4b5390eda74ec952d254b8f02e6e" },
                { "hy-AM", "60d88eef822af01ae42a310416808392f46befd3557e27f7520b75f574350fd3aa1a3146cc94f74a9d0f687802ee307d9ee4c1b74bd0766c49399dea6c3512cd" },
                { "ia", "220316fea0f59111931026860ac795520605d3dea4c23406d8ec441db92c98656e26a25e98aac768cf529424096df6e32dacf64eda77045817079c418f222421" },
                { "id", "42066be0872c027c56345b2fe2312382496219efeab73cae21d387709991d6be8b06228b274ed991f0f6d6d24450a14617cf6c0bcbad096b021f2eb192b94d34" },
                { "is", "4b8038c863350613ec268163f16da0ec4627e3e79d11d449347481889b602dd8cab8fb938cefdb9469c4792c54748db4871c88e9d1a0c40aa478840a18be4a89" },
                { "it", "94e4c10f78db6a7bda357ba132af46e3108130226d4d2aa9ecdfc65315df09f90dabe0fd1adc91854c3ffe2ec4e4bf0527c196f9e9a036904bd670ad69cdb0ac" },
                { "ja", "d41d345dd1acc6c7237c9794d2577327831767327db26eae601141341cc47bafafbcaf36048c349addb63adf29751a3b0dd0202c1e9b04d6bdfc4fa9386fa51f" },
                { "ka", "6b00bfa05626975f55c559a6534f2bde4b8f0fbac86fbae8a9a42e5239c30c4dac10f804ac9185834ff4cdc3355a819d2c67c356ea196076a8fd6171efe6f69e" },
                { "kab", "f074cfab3fc6b43b2d76c983d90e6966780931401597b56d22fff066eca68343b34ad4ad316b6ace062fded5b867d81575defb7d9c9520344783a2a938847598" },
                { "kk", "420b806d0581e6c20096785f24d420b26cba97f59574325b0998bae70c59320161be9e54fd7c8d47bae08a60113ecf1fddb443507c50d525a6c23bb9ba2a3b8f" },
                { "km", "a4fc474027990177432de313256c55343c9c5707d0e35f6530f0174a77c99e966cc52312cc5650e87ac5f9209d60fded83ba6f3f99ed155ecc02f0b4c3587d27" },
                { "kn", "6830467d0a74d07aff0909348b6d6dfa8f64b28f9f7ab9968c9ef4f549e8b6ede4d5584265b71556773f8ef29b66400c9c21438b878bea017492cb44e74a4f64" },
                { "ko", "9f796dddc17bc7363185c5df706af08396d7500957b8fd86f66f1ac3d10a2c9eb44e8c32a0c9dc971f76848c07ec3b019da28239354d72e16432e00409c4d55a" },
                { "lij", "b801cbd2de714b8aadd7d25c8f1e1984ac423da6f73aa7fccfb5f7903036ff10782f243a962ba2979eb9a183436861554d85e331162e491a1ca131142e476b28" },
                { "lt", "285312495eb8bdd1d8fa798bddaa401f324a8f4e87d8a615722884918b11d17a98da656156b66137d0f41eba0fef0b2a8b826de699f0444eac59e6b4accfe031" },
                { "lv", "74a17db4e9aad9aebde9a604e5ed132acabbe21ed164c9bfc4f2ba7751eca53d65ffad3ad911626e53d1fcb3656d65012b8244410647722e0e00894f75a0ea57" },
                { "mk", "11b6c238abf1fc6555e6d602813281632c2580d9e0b57ed257f868db524b6e7c35e3d818d4bc6a5b98c3a6deffadb862b16ce32091ea4264c7acf0380152bd91" },
                { "mr", "91271e34ad7e481db3b7d14fadca4df51b654424f561d190f89b6b9a4a773e3c8b057e1b4ab0394f5542ed3a5f891df065c600e9c3c7bf4a407387a6d8dbab6a" },
                { "ms", "b8d7c3005e0b5197bc2935c5983997f4c3d2b2defd522463fb03f3a4d633b8f8ec2f52db58aea11658d6220bbe7f42164a41d677c569b2839be41e6d2da4a8ef" },
                { "my", "34a0cc4bb2e0ba531b579e9be8b2320a077f6443454829161d2e4f12548f73d9e42d4ac1097a289d9df11308a44f216a2f3450ce10cb2919fb031e9b479316f9" },
                { "nb-NO", "6c5c9fdec09593773975a554660f4ed0ee715a62c0060668857a1aca165c5687d2781fc2f8120c292f5830f8cb6fc2a3da5d301f6f76e5bbb8023d0be114416f" },
                { "ne-NP", "507c6a7200eaa0980aed857f225563a27892cd962d25aad5bda07e5c04eed4abad0a08a92fda3e5b933c86a016ceed5ca32276c5433ab128f9f835adf4c3c8a7" },
                { "nl", "e07c5cf6c3a8aa6114b40b00248f0c8d9738c4d9d3027fa45cb4d3be1dd8593c303a5aab0fe1bce59676c595778a9ab73ee17ffe570361b4676e8d321523c6e8" },
                { "nn-NO", "6967ce334d876bfc5e79df3012c74919e681a14216222c39f738c0851dde06f32503a099bfb3377982cb089f2c860d6d0cf1147f89a0acba6cc8fe42af5505f8" },
                { "oc", "7c187369c7efdca5d29d003aa95f8c6f5a59dd69688a9b7cff19af10643996811785f4014f90549b5099c5072efdb9e67254666a6e4899564052f5b80966b8e5" },
                { "pa-IN", "8dd942a048bda4dcf68ae99205c77c52f282c9f2d84d435ec37490b297684a00ed9a810126512505f102542f02b61d4727064ab59c95a889e5e9df3a995db088" },
                { "pl", "5170de8bb3886b259d636801af9aff3373a4c3a10909521ab31e626816ce50bede10731b6527a65fb637c30e64413e62534a1a320c2e5e30a6bd65b345483c91" },
                { "pt-BR", "9bc30da9ee340884e24172a8abab715b79e3a3a2813e4197b0d86d552b949e027d3daedd2964b45ee34891fd4322e0e8c116e54d43c93ddb76e3f85708ace139" },
                { "pt-PT", "9386e4379842a88c686827c2e6eb92984c3618ff0c20ca5080b6cfa1fa6a8e2bac43b515356861e8acc8ea4d5c7b32d6ce7a505d069cae97c35258726aa826aa" },
                { "rm", "47c9be4624e9a87bbfac8a561031ce119e816b455e7b136210f0efbab9f8c61fb44d9a2d0c29085c69609ec1d88d8b430bf41e7070bb7f844ab97a29862e8781" },
                { "ro", "c7dab4e265d0886f10191e0122ae66d591c0c9e3b0bb1581f3457043e1f314a080a55a73402265fe6a5a1189e014312095b227a62c5e38b90dd873644fd5c35f" },
                { "ru", "95b26c750b372057c6c33bfac3093b439b2b126eb2b2065ee5cad490a3941adc315fd51681f8aa92e9a3ecf71c36dc04be2ac4a84a6ae392e0a6c190c5795dc8" },
                { "sat", "28eddc5c1afeb12bfd711bed46d855abdae6aa97f9b8ebf912955a8aba8e965fdfcd58d45f725589fa18bfa0c39e4bbec8552c6bd1283f98b41a8abd47d57efd" },
                { "sc", "06deae7dd9655bacf83bc95f620f8157354302f613d5fe2eb35de1bf34746475eca66772dfe3ef9bc64fca62421c5c0a1a4ea4c412991ec48d30cf8dbf3bb770" },
                { "sco", "31a4bff72017944dfddd644474caf52d792b48f463a07803cad5c2b13d2fdcf0deecdea50a76624e3a63e8ae028b10cbdc3c69bc3fed9225ada5eea5d430c9ea" },
                { "si", "0cb1ad33d38414fe7503f4583e9b02eb56adbe91b69816714745338d91a9a34eeb51fe930d999d72c5eb72d0f2cc1c6dcd759ac22e8fd919d20fddc3fa0aa77d" },
                { "sk", "a47f9dfe7c89b9cd2c91ed85da5a04b15a9bce8cbfbdb5cef5dc071d06304752de22892f657489d4c9f122371cecd26268f74c3ef4b4d6800931facd90a59a39" },
                { "skr", "009559433440aafc1d8403ca624a877dcbc4331fc5b1be45f18835ccb82df5e7b87c2212fb47eb43f9c48ed5473f47c563c2d7d3e51878a08612e53c9246560b" },
                { "sl", "5cc85f56b0c8cd00b27bf586eddf73783f8afe1563fcc3717a26a506aa086a97a6d606451802dd0a59be14f787756444b21f99c5dc3c53833a9e2ea5820bf926" },
                { "son", "828d32d7deeb68ccf69ef450c14ff5143645b3e33398c476851817e2a22bd86d154b0973d23d4ff785781e188018422962ac9ff830a5d5446e1a577cb34a6e3f" },
                { "sq", "b2af37a1ebe3e583cff0106492f52a73beecec767f3960b33b547cb48b43087ed5b2630f8afc87599542a91049a48551390713eaa343eed1cb2f854556eba02a" },
                { "sr", "5bf0b18d7b8cf94b27a2325be7a897cad27b4261d35ed7e44c16ea73f053844ce1bf98ee7b3d294bdf971ae8c20b61b06caa9685b8406cfd3adc50864683b74f" },
                { "sv-SE", "ca26836bdb9d0b7e6c76636fe67cbf53d33afa26702c2bc8692ca22a95e2c5d65ba86d516757f6f7e0865f8d73e10d8e7fa063e5e5c394fbbcf6df375fac47fe" },
                { "szl", "58c081b812a0a3a679035a23c457d592a84a0a09f94683927e8eeb7088be4aa5e7e594281d0fe6d4cb6d6dc431b758b13563a998902b64b746e8f1394215de0e" },
                { "ta", "8b4ebea9b2563863e554bc638ef6cca6ba9542c2b04e5d1f61fa078b8cfa5f87285d5f5f5f30676a9105b1296dd724480e7adc2440a15332b556333faec65d0d" },
                { "te", "2878746a03f2507e3955a2f100dda7ed5b541e0e241d216e956b4540fe7fd8edc6d28bfb3c8b79598caee6d6b2ef2980886d7435e761de024a30a6d8e949cb8f" },
                { "tg", "b35b1a42b86433e979474c81de2f185940a6e50f91b921e53bc276172ec1ce13825297fd225ce29766522d6d4144e3463b791cc7c889c987e5fe2ecef03c5a4b" },
                { "th", "918bae201b84465fd9e023ef03b1c0511a0ee1bca10dfde8851c83b98c5e92f14d2c331e6c8990dfbca50ff9c1fefcf9ac8906aa4b6166a6b96de45aa460df7c" },
                { "tl", "2a09326c9d9cb31bf065ce64008d6a98636b0487ebfb167d24894704ca72a1ec99cef6c7a42a6b27e3d78ace70ca1a28dc37734d8f17260a3422ad06d33faa12" },
                { "tr", "a43f095deed0698d8c85af0c748d84a2d2ac67f2684a0a288ea3059491d3cfe2d8192bd0e593fa95373c87b5849863250492a5cf38a2b8d6f1817d75ac2b2b23" },
                { "trs", "b4e05e2c8a01fc548fb2112fa1f514ff1739b21d88185e439f113d9a37ba4240072b02a9bec5c107ac5bfe9640edcc30f23173b2000ba43f5e23e0f24aea6f72" },
                { "uk", "3ebab8954967b8f6ae3b95e22250d9ddbde8c19cada55e45f9b84a5b4a2ef354a8c65c3de840877988631efb8fda93b32077dd133d58e3fb74adcdbbbadb49ed" },
                { "ur", "ed6632d6e6015bc8db0a94371eb535dd61424ee60c66bdfe48bc1bdfd9e6dfc46e6480999654c352e67b1824cfc4300de66f3c250a601c20228928af863694c4" },
                { "uz", "48c7f6738a035fb5d968cab6a44ad9458586ccdfa2748836f71439123dd163b210770ec29ab4161ba4e41856277894f937ff20214718b53c10b23934b4f09945" },
                { "vi", "aa7e0e7ce8db73302bb0dd993626f8b47adce0798cb1a15931e3269a6d1e9167b9491cda581e351ca2bbd4ce6399c31a48cb294cb6e19f1bb16fc5a0eddbb6fd" },
                { "xh", "82f2e519916b3c916101b08f09428671187760ddd33ee334fec7ab9c0c63229ff569c1525cc33a46aa2fed8587c544d89ab280c00e303ce6f61eb196e8bb3c43" },
                { "zh-CN", "4246987c32b69e3e37286503e421a58c1589eaad46d5b733805ecb1433dcf375dad7078f8eb0527ef8a249bdda028c6ed1c32421eb8550ec67d79f3a0b7cc80a" },
                { "zh-TW", "d867fd35911894b4a470d4c5447cb6af92f01890282b961dbc738f7cd32649cc6da2c31df3ac7258fc682e3f65d1c1833f60e90f34a5b713b7ecfcf5ed88f6e9" }
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
