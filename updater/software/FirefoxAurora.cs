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
        private const string currentVersion = "142.0b5";


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
            // https://ftp.mozilla.org/pub/devedition/releases/142.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "d795fa398702d72aacc51badfe909895e63a5e1c68e8063aba6da66b9cea7e6f4d04498eb916b52db87049f6a3629b9a95451b3614ea9c054e0619ac34b98735" },
                { "af", "d50c284909bb557a51fb513d0b06d5251def63a27dd93d5d5c1c9e56d9d3a91d0e1cd3e634156223de0f4459dd2ef6bcfebcc343e0725b8d10f84e7b1b1d368a" },
                { "an", "9f1c9836c8ea56a1d56dbea41dd5ffccc9b557b5cf9f51bcb75826ce3ed964e048f6ab12a52eae6857966328f602704413d5a332014774c3ece76628ff3b17b6" },
                { "ar", "83fa1bc05df60c850880aff7f1e0e3ba6bde5e999a6a29746ca4ed4763c3973bfbadee94a1455ddcca604cd2b101d12c571491876b23f37afd9350bdaf94b199" },
                { "ast", "d02b424e2d3ea3c2fd1379d65501df1110ec6d549660617acd26f987e41acefb9d233c8d39334b0cb14d30ee198ed817d3dd0bac4c871e8016ff30b4123f40b0" },
                { "az", "05d99d6010940ab0f2609f300d11fd10ae504b4a85a135705d9abcc67aa797d046346e71de6a5487a742e173e8f6bfbf7ecde0ee80638ebd520d28eac09ef926" },
                { "be", "7c5bdf59c0ba807c6e7b329fd13e97bcc7765ad766c8a759ab6128b9c4c87b01472ef7250499f00e31c55c5fd188b53d1dadd1fa0cd9a0e8e7279a0ff143b060" },
                { "bg", "6b5ed9859507d16a2c22d0187ef46f73d15839696582cc754208433dc4d21a4e882dc9e4c2557f049a41d0e8da4dd029a145cd72304c6e91b51715ab3d1a2c43" },
                { "bn", "7a20f4a65cb53d2b328a22e4d1ebf65a2edbb64d19c1cd358452f8eb6fc001ecb8c8e763573d651f0581d648f83b6faa3c9eb28a4cf518265e5232cc4c1d0b9a" },
                { "br", "7aa241c134b1a62c51bd0cc0e7afc039fa37c74750e3692cfc4334ae3446b1ea8f33c2e30838044db2ddd2562c00e7fac1afd33f40cdbbd0332071ca075118bf" },
                { "bs", "722fb63bfa09094d9c65249f41017aceaa772340034ac6280cf799935376828b531e2d86d98533ffa7d2db3366b0cdab90598e93d5e06aa56f8dc1a21ccb33b0" },
                { "ca", "26990eda56efbc95a799f4dde55b1e82bc6a592039c4a446afe49f9b96880dc70b236fbe47139117916793126278f88a8483fed60713a88b7e07fbc25fda09ae" },
                { "cak", "cd9a771b61f3bc4511e0bd09ef6394de7518fc9c69b02af1c1aa3f5b557b8a9c11c6c0a748d63f9e103ae58c5a36ea365346410edf3c695be1bc092fd52cad0f" },
                { "cs", "8025d3065726eaf896489d5c50244d4a0949e3f9312c779f3d1eee6265b5f6ce241c75edc7705a20efeb54b0e162e0892d8b2e38f87268b16cf19ca1f453ca30" },
                { "cy", "ad922e516f755711b2dbcca41ea234fbb9d51205f47974b3c5aaf867fa3001378d6bd0dca5ef5964775831b82df0b71e840f4d13acbb437beed3a5c58d1b961a" },
                { "da", "6749ec5d52c47952912f3ef83a914de4228841c12ab0871411cb2f9771ea1ee7fe66722515c73b06df2642813b484110679e3a7edf1e56eabe3630bd8db0de11" },
                { "de", "0a5fd84bd848a49d6cb490f478af30cdca67e2a1f8c56189eacb0affe688f2de14e635badac5edff99ee14f5304e2ef7b00971156323c7dfecd75e4282941bcd" },
                { "dsb", "a1a2744370832ad2357fbd48a1d6da26ea5ab5d4038ce66c84d2f56092f9304383ac6b1ebd8d5637e52ac0374bebaf661cff81c5b733d9a7d6e9d0f2703466fa" },
                { "el", "e261d100f8821c381b68120d01ddd55589e6aea23d9e8455e645ab3ae1dbff96c8123c242dd1abadb32667768ffbdba899af83153bb54a2310f337440e216ae2" },
                { "en-CA", "07feee551d6393d9c6c270a5efd3c1acf33ffaa513ba861f61bf571e697669de1b049d10333a13f838869fb822458a07ae7b0f485f2340c6265dbace1e2de7b5" },
                { "en-GB", "d1e416c44622633ca87faa5cdf7429a306dbe398fb5f3ec322bd83ee408a3df75283598a64f10bf141780f15c787cb91a55c9c25333c2e889886fda4a2229ff9" },
                { "en-US", "10a0031172116d885f1c2acdea3ec69ff09e957fb153c8cc73dc80737de5ab306d20f911b3ca72036b9b9eb7ce0f9bb2be1a7a1a6643376a898190019ec38869" },
                { "eo", "6f35fb3b69c4ef314635071cc99e7d5a7ee7755f805662d44d1eeca769033f87753cd3a1abef93f8ebbd5df46454631c107a834ce08683e864140287b6ae7ff1" },
                { "es-AR", "eb6e8f081a3275e5ff82ac12637f1bcb30d8e798812e95032cc8834b562ca91d0120f1ea538605fbc85e769385bd9ebb1ebeb3b9a6ae19886fdf31dac8d29f19" },
                { "es-CL", "37dd276ad071bc7f8e89e36efd9c4877a9ef09dcfe5b4ceb07cb28afdc8c77cf1f84336193728986909d86f1de54a41c7d484c70019c04b48fff91e3e638baf0" },
                { "es-ES", "66b059d3569349e320d0f4d82cf43cf4d0d07c22bc8fe9abcbea54ddaf00d50a1d3aadc4212023a45d6e66adbc8f849962ae0a8619ad6b45c055df5557067f57" },
                { "es-MX", "3ac9d123a26318d44740c8b1fbf79c9de7ffcf841b9c686faebd701e88901057cf1eacd2f1e174ed682a772cc22a26dcb7204d0b049577eba2a43a67afd91647" },
                { "et", "533b934a7169d83fa0a93c61b612a757ea3c56a606f00bf2adacde57a394febb98e2ef24d8cd7a64da68abf70d6a64686cc5e2c911fe469802ba9e61f1cc3e0b" },
                { "eu", "d649363f250e59fdf61a5af3f3ad277764761744aa28a01d62a80d2a37c96e8a061e7c23d92f5245496804dcddd5bfb615f1dff0fe8a08f2a8547ed0caae5b82" },
                { "fa", "94781918f8fd1774b8d947c3574b1ecefaa9069331a7ef40411cf09d2a895fcfaa0c7bd29c7db552f2ea8a6edde55e269eef9978be3c4e5bb7e9043831d91601" },
                { "ff", "c97479ba0b213b5dfa89ab528c47f2370d210f0fbb1333ed2410c0615983537c104db7d101a319b723229f5f4dd84f7ff01c1d4d9585f2599774ea80c5aa6d2f" },
                { "fi", "3565d669fb8e183be2e0669a7f19081794a78af81f8d8299b3ddf83fa2289eb618f5d5274204771aaedb65e4f98674f25754930997f031b5399971cb4a672e4a" },
                { "fr", "2a3b37ef7dc4e2201a28edb690bc95fcb6e0f68ca7de583d8bbc060eb5dc6100b8a58aae4628b8c8d423186f532f663c1cc75c4a90d9686a3c3159c04fd0a3e9" },
                { "fur", "e9325d94dd6dfc86c3076920bb5f2d5e157c55864ab8f31481823c05caf99fc5ee842564f604e56be2f48695fbe529e22d49ca63349c646cd82ae87ea43c4af0" },
                { "fy-NL", "7094c47e620801c99fc62f6e1bcf3a17e0228b027e6c2cdb59d9205e69f50aae6d2ce0f948f3504412d8b79fec2eb8bc7b0e42ca2341e53c31438a701e71ea34" },
                { "ga-IE", "3c87e35c79b05f1ec9d9bafa69ac1778e2d753c340f5323fd29a32ded990ac5b184565b9f13710dbeb88a2e15205717aa7048e0438b3856720a322a2e7870609" },
                { "gd", "05bcc46549f2a168ef9d98e8a3a251c29a2b135d0bb00eaca4c517803328bb53ef514ad58e6c2cdaf46569c5aa780ee706c570d31edd3576aca73367bdef564e" },
                { "gl", "15ccc163ebe47b0ee4f24733d216f27947db42345f7992b59a043c38059d65afe85f61ea60bcefdb477f5d67f8eaca710fe2a527a0ef520e896f1bfb22c20fea" },
                { "gn", "d6ac8787c137986798ff7e96f23262222494c100353d3f1da8abf61060a919d2e6161335bf865e7263e51c9d8dcdee07b73abcbf679a3ce59244cce1991814ce" },
                { "gu-IN", "ffcbe3474b84b174b423f1414b12009d8929d78c4c6cea7eb599c7d0e69123a167a9382d1290418b42461858e8a70fe8ea959c70d67ddb50e283835367a983c4" },
                { "he", "ba47a0568036b56e8d0502bb4a12f560e616cb1f745372e09b13d4e9e1b1c3d72c3a9204eb13c36804e367ed15616d911af32380a7b89c1931eaebb1d5248015" },
                { "hi-IN", "968a0a26f89270b576e6038ed7f01fec7f9694947836b8f61e37ee1c4f19d71d84aec3d6f82590910dde7308d9a33f8d32538cceb023053db46a9e5625ead6f9" },
                { "hr", "a00392c1f86be72f83af25d9dd5b490d3c15d6273404143902202719c01788d6a56444300747c1de5b68d2112073e45eb568f2ed95ef59ad10446be44b9a34a5" },
                { "hsb", "77fe7115237317e33761bc4f2f9533f2ff3ac61601124a56fd038fbb63a7a6471c7de8640445aef43191ab3ca43a43bb00dbfab7f2a03ab2d344e09661398353" },
                { "hu", "9f4abd388abc1b81f89369103d339b5c0572511c364a6bced562c00790ac14f2ba89f1afe3016147cd2a5b459eb647636b398b37c154a36d2e11548d65b23d3d" },
                { "hy-AM", "162ecddc93928308b3aa7f0614a9df5f3876e6b115cc922a9d34158f35064927ad024682d19ae687f94cb413daf229eb2190a0060a0042c34eeccffdf67acf81" },
                { "ia", "0c217a47fc8f998c241a8a4adb44f47d8dc6ce625db57f7bb223424abdc2d2546218a59448bd656146fde1e120e21ff48affa29db112456e11f2a03d8737cb00" },
                { "id", "c4aaa5d6c70bf90834680d333f15808e5416f48417b867e5fd76d009c9d386f8ed894988d296da3b9741dc2123fcbfe84c44358f2a710bbb48cc280e02ac28e2" },
                { "is", "82353b16cbcb3339ab5945b8003c3db35e736c0ad8a29f98048665332aa22c098772013f121ad398d76b5d6ee728901ff459564f6f25f69c946c931a6f2e58cc" },
                { "it", "a1d56811742a935ce008375e3ff6d78ad8426a867635b31da50f8c258fbd9eb2898f0bdc340a40b73e82b132beb2d090a919da30c281a1ec7c1b7bcf8c7b5a6c" },
                { "ja", "18fb49bb2264e2bb9153e37d8f5f0e61d226d7f74c4db3be1f987940a616d8925a9839e868fd9c23d527f2b067126cb0c416f518a3ded52fdb7cdd3a47bfce47" },
                { "ka", "f4b32194dfd82c06c453311a2ab4854eb2149b3512a3cb8edf323bbb14e346fc428b2aa7b980e7ad2b97632327b2d4091dd4f109a9d998fa885039fdadd71440" },
                { "kab", "8e00e10769561cc25f713de96145477e00808f09f2aa0d47697a39891b70b59d6744e3cb34e5d4d2fc4ecdebf7c0d7d2b98eb5a59d36689b7b132a950a16886d" },
                { "kk", "cba5c7e7c1d27e46e6baf6cf39f378f2e33889e44e2809dd203c8e1196ffc789575989e3d42fcd22cba56b2bc6b7f669812ea00b6c1c4a719403d55f1d494d37" },
                { "km", "d041ec0387a97cc210a31417b439ed84c0b3d4022cf469f497a646458eab3d0ba919ef209f95fb0074f8e00cad0419829173060e894d0c62a53cc631eebf636d" },
                { "kn", "c074710c884548fa71e80b184ff7b1b0b248a6d4bc30fa7a2aacbac36d138eea627d25bcc994b472727cd000f6ee80a24f84e4c922ffdf66087584f07595983e" },
                { "ko", "900cd05c21e31350ffd42789f052f6edd08ed3974ab1e2759c33dec0a6df26b1d4e8d5a0f5fa0fa7542e73d931e972df19b3ffefa306d6b4aeb3c47aacbdaba7" },
                { "lij", "6415ca8ecaede4405fac507ceb6ac59c33e2dfe8dffe254cf2a45d9a551f285ed15877c8c2e0bd1c01687d3ed3a33a246ff8f24d398aa2c249225fa02cd56f83" },
                { "lt", "c2bd456474b4f9146a890011675ef09119a13af1f6d4dd2c54eece328fcf0feed49b22a84cf221c960b9c19144ef702faf62b5b0d65eee03108d54f54db7b803" },
                { "lv", "96fbf7bad5e65959609ec36bc7b1102dc8e64db43db6cfb9dd3adff3c0160624de47ac5603c1a2c67cc335012569bc0c4e6da83868a3e014416fbbab76d2856f" },
                { "mk", "159d6cb75c6e1d6ee4aaa531a1f2efccef0a3fdda0cbfb9c607572310b2c1193c04628df78c1180af34bbd2eafc4913debd8eb1f5cc3242dac23e9633cff01e0" },
                { "mr", "6c798ae09cc3bbf34f0ca3c53fa297f77cf4b6a9d8d9552941929f34429075796e48a52075866ab21af5143ef7fe9f0dd31287a4fddf213869662cf3af9db1ed" },
                { "ms", "29312c5e01d6a108db535ef9f35368a802c6295e2c05c337b94ef65cf5566f64557b89f17aecfcb02050987b53fa96e23057f777ddfbef965f8ab69d349470ba" },
                { "my", "402f0fc6aef651fc1f830845e923cf532c5247f968ab1d6df35c2c280ca369ef4cd6970bb2c139c631c59d0ca1758ff6cf8c6e9d8342ba719f3165148c5eb97a" },
                { "nb-NO", "9ca42325b16541f4f938f8af90012876c7cbd3ae89facf64cf23565ff5893c3ccad89ae9ea08dcfebe80932ad5b024be471a4830ea45f58128ca6863640c1873" },
                { "ne-NP", "02bd501bc535aee3e89bc7e612d60e5e482f6c3d39876e628b78a621f5ae3ee8d24a58be00211ef2d7cb1b98757e4e5f4c6125acdf99345759fff4484865918a" },
                { "nl", "818d8ca562bab3e37efc5c22955eeb2a0697ff707fe94b001c3992b366a6256322582da7ab30d726d1c7f2e28c6b8e734a5fa093b0ac59310e8bd3362eac53e1" },
                { "nn-NO", "d5a824e6d7dbc7881c200bc745ac37093fa2deb6b746007bf759c849e246f825879bf32c88439da273c266a1d4c5f9eaf2b3d238c7386a10e312f0eb90f5d091" },
                { "oc", "e65724a830c895a191b863ee30a78c5c215c8c8bd8c8039bd91fc7d2a4ba4ada845f657c031b61d535bf945b27d724d3f24e82a3317b25e027c4f0118c5639db" },
                { "pa-IN", "53bcb43cb1a69ce2234b5bad05ec6aa1fe52195aab0b4613ce08273e00a78dc00d1faa28527823094d93ee66f82ff8a99c5619667dadc6e48476f130dada00ca" },
                { "pl", "6a648c0ce4bd48a33abe69491b6f2b4cc5ba0e770473ec097db80795f8d17771761a67d04073146d924a0af34ae0880cbfb54f100caa8e33ba01c5e448a05210" },
                { "pt-BR", "4058dae6af9a6f66b9e6ed099d321b98bb554d20d3a01bb2ae36941cdd7f69ff3760bc1a941e63b75dd2a297e9cf98318170a145a03a8c506a4d064f7d857f37" },
                { "pt-PT", "71f0778066ee6f9f3a542a61d7195b7d8c21d89e178e997d230139cd3e7d938a2d798019655b277837aaf4ecdc8477a84e497b03139db7861f1c4ecab7a390f9" },
                { "rm", "76e0b7ef94233d7fd2a45550bd2ac1f4c66b3d046b9ee7e554e0629f332b75e42cdc1ff8ae7f3e41aba3f08a96d7c27482dd36977b07bccea2e21d97a4373c22" },
                { "ro", "a0c13ed2e518fcc8857a825b3dd91c0089f93c01203832b16c8dd0f5ce36377a5349957c0b18492ef1f5d99de44df29abe4677726aeb51cb2dd250ae5965a58f" },
                { "ru", "88102471c4bac030a26942bffc47a5881682e5488a6bfe1b6053e78a0b49f1f14791d504eb3b51962861abd018340e9abfb74924b1cad32198bd527abdfd697d" },
                { "sat", "6666426de21672b30ac65987b0d9028a00d4b443dac8addc82ca9e18aa59c1bc20a51fe0dd0ab7128390f7e053d4dea2d0806b4a35a1399f812054e65cf37b93" },
                { "sc", "0bc4fd6b9e57b189b3ea4365e9d3ba240a3a4635c82acf24766349a715be9472fcd0fa18e8caa7504517667835c0cbe9d67c7f6d9e792de23800db7df7c07c7b" },
                { "sco", "553a294a7af238ffa400c169dbc06259ebf03ba8d30db62f33de809bf935b9c9adfab2410eeb7d6b2f253777c620f6ce65ec8d8ddf5ced595232dd114d7c5a72" },
                { "si", "4c757f412aa70f0ba031c53589fd9075c35dbede34033648f66a0c328f4b3b4df5a68d2d456c98b719fc4dd12096df23c389dd321e825421f8e66809f8afc825" },
                { "sk", "b6e6592b66c3c92ef6e6a5637e5d45f4861310893076a16a34bf01958a99f32aefae04a4f6a11cef338866c416e6897089550e79a00c2396cd0c1b092192e580" },
                { "skr", "5c926fe89ea2f1d6ab79bb0484341ad6757642cb7b6e4ad2ac6173e57d0b02321f320d9e044ad6f09aadd07b03c975073f83532ca1e99f5f4a3fcd62199dc55a" },
                { "sl", "5a46b6047d0f8c66e805a8671db1f66321f3f5e0e1933ef904f8313854de1ed3fba1246a9ad82c1e5d20e03f1ad27b65874043d06338cbcf0488b41ac691da06" },
                { "son", "6fd572d3af16aec2cba4f5fb9547a9ce75ced8cd4131e3620719b02ae964a695b8c1a6dcb509bd86148563a84cde5d0a8510d9cf48603590ccca0ce2b8260187" },
                { "sq", "5c08c67230e7b6a175f963f63ac5c8cabf19d09c6f997662847909238a8c63bf63cf3aa48cde5c43b8f1e226c3298f5977675e57f42ed472e0b181d6c7ca9359" },
                { "sr", "3322d031aeee78c04b8cc92f43a6e83db8d74e711d5757a80f6bc30b7dd4318d534dae1be0f4fad016f1c259b50d4a5ecee2ab9acf4ef1f0d50fc42600097ad9" },
                { "sv-SE", "b585cdef7e1deed3b52b4cd33136184b8636d9722b2044255fa22defef39c4b112d37bb160d795254d75eb08352194ae7ae3ea930bb6adbc7dd6b246a9b1848a" },
                { "szl", "635289fe79a0a70cb20b5361511626b9c9a9071b3fee51416fd8f2b6e9900f571d934f56917f4847f8959f43e37ca12c33c14a7a9f44de4338dfe223022b3ecb" },
                { "ta", "ad3cb7c5d6aa696ccc2f6ef9c7a82c9266e6c20b7aed1431b455faa82a43e8df6f68bcfecd201d22763700c8d3e863248976d05e0db780d87a6b5745a27e8167" },
                { "te", "33c3ebf92632eaebfe40093b567efaefd94f12d1c9aeb74c2b42a7e79bc4a3305051e19e1a2d2c1cb54f7b9e3007e76b70eadb251db98d40bd180c45537e7744" },
                { "tg", "ef2f947c7377909f51bbcba859139868ae59d4bd0039f00ecc1fe17e7764b23e736c0a2138f6f64106cd8ff053fbe2ef2d4e959bd76b627c880ec2909ea1f4fd" },
                { "th", "dd5254e35526ab2c6f5963b70e47f68164ed108fe050258f4ef12d481509ef25ad97ce3d0facab7bb6cb74710f65c1721598c896f819891375c93aebb51be1e5" },
                { "tl", "1c1b80ad233cf15d3f69e0fda43ff354d8d316c397f1ee27831924b739ba316d3509912e186fd9c2f196eeeb925dadb3a78631f54924332e707d0a304c8efad7" },
                { "tr", "99d0f6b3292c94e111471da7fa7a094ce555ab9648216429a87ca0a892882657d525548b9d5b13801f78b97d3a15d117a5d9135c01af5213c29f42a8824f1894" },
                { "trs", "b45541e0468bfc584ea4e7fde5cd97868247fd81f326d76e7712b7b91728e572290b848a0c19fc1d096cf1280bd4e48f92edc7f4e3ee46877d07b4048a703d0c" },
                { "uk", "45e755b618e6584379c9b3b52d76e74a8b6d54265089ee26aaa815b63ef5725356e7e8db55af9f3cc3be22ed0e6fc5d3ebaea5059569ffe07aff7d52d686615c" },
                { "ur", "919a1cd4e0d36869c79d1f8d9d9ab6ac5fd0fc61347086356dac89eb55f44c81874b868fe8449e1f75c64099492fa873bf2aaedeff93cb8359f54a6abb0a0cb7" },
                { "uz", "dec90e2db36c770778f9e5ade5ab694608f1823f8f4a17cf5214e2fce6b5a17c7692205efebb8747eb17d30a19f8fe6f01f437719db78a1d375a048042067952" },
                { "vi", "4eb74c58a2b01c91924e1a03e92fee79d7d9c5b02b7a930fab31f861637a35ce2faa079c2a3822cadcba47062c06c6b385a7471885620e2885910dddd6b95dfe" },
                { "xh", "7444bde3a5a732629b39b37e1d9a29dafbb6453c52886193add854e78adb2591b027aae46ccfc3d78bb6366533e1d967846a0a1c5fbf1254f0cc37126eda1534" },
                { "zh-CN", "4452b9b46263ff3837cf5f3c5bb96f54bc1daa67d4d8e0b892f52739417859d84a2209d3b50e7944942c29e86b9384419e64dbf67c9b868abc309992783612b8" },
                { "zh-TW", "4c66a103870594914482c8c2430755fea08f69d3693cad13578cb66e71a6884fa661ee014878cc081603d0081fe66f80a4607ac1a22bb9dd4302e58a840a3c35" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/142.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "164c131c6e20f124ebdd51763e46d8f423deb518222a0e4eec767434fbd430a8af5b45c4fd0cbe7f9b3a11205fd0ca9b38600e1e1f0a37175ff27942d55c133f" },
                { "af", "5d3eebad78ea5aa4a221ce0f34e78ad3e5640f1a02db96bb804e35d3b59a3d7adb520ad80d338b20ddbd2963f8fb2f896071f911f00a8e05841db69e36152041" },
                { "an", "d3b3efcc374fa2d0c38a3d95a4896a84d042c6b4f472ab8c8cc6534f9f91ae447ef7c18594b355a6648df936ca18bc6548fd7f341047cbf150ce8d697386f110" },
                { "ar", "85aea450df04e0b2374de78a0e3980081a1712422c19ae5cc8b4c157791932477331ef74833b20cd713e7a716b14bbea977e0665dfce5b9e772940dea3052505" },
                { "ast", "fb39b0732844fa123fcb5a861f6364ac941ccea5b8fd8112f1792f75000e849e135b5f56d111245b8b1daf5ecb6086d952b7fd5ab8a8e79a034a56adc7b0d2a9" },
                { "az", "5b10c6633290babfb1ace26583ee83c1de3af85266756c3a08791cdc7fd7a6c14206f3dba2324bd9272462ffbb999aeb7e3b9d5b6aa4d261a23b17e78a1201e2" },
                { "be", "4affd639d1ef278390aecd31a5a12da31dac15fbce9c444d266d4c94aa81b25bed18fb4ddfc69ffb0fa85a4434c35d8b53fe888fb64da3bd70aa4e8653fbff50" },
                { "bg", "700cea8525cf7fdea6e1309e3fe46dfdc523478321b39572eb85ffa5d70ba2a54dd624808d820cd8d9d00cf8dd34c4a62aee70afbdf914d8dcb2243e8b4db29a" },
                { "bn", "1ddad0e60da9fab03e0001a4b49393949a4f61f9991705a020a5b829fa1e40a879e5649ab6d4698824a3e77d1f20925009e711bc5164a94b371659b39e572705" },
                { "br", "2ee63eb19749f31c03867a6025912d21487ade13764d28b584cbc52b86a0d04e60c2a352002921b71ef1bc8e4507474c589694e1f72c5cde193cb9478c83f5ca" },
                { "bs", "7ed520152221467d5da4b71e2f4442c82995e5878fc77b63e5438f817cb809371557f0fb6580e32ec59bc27547a9b3a5f538a8572ef8d07d13caceb991f6347d" },
                { "ca", "868d53c4e8c1786a75608444e1ca81c6efa4beaf7ede2e37e21673f8339f55c8d0369bc856b29769dfe9918cf05b21160a0e4613ca9cbf5274af6b384028d703" },
                { "cak", "c6a31f71e90e4c0491c75e8694b94e39ac6e5010f4c5f6556a24ba01edf0ba58066558aadd5f9d4a146dce6ac58520f91964eecbfc4f8d926a1d96be798e91bb" },
                { "cs", "0cb560806eb5b0a4a9df529ae8f9401c83efd4e3217503cc12d6022a97c8bd85cb07acb26f601724bd949096c079ececea981236233fc7807c9b589388786b0a" },
                { "cy", "ea0376011560403c11be134393eb96cf4e101a0a26003c1653440229bfce0c4b5620f9b96e427c79855fe07b08b7ce5ee7b1549913c3f9c146957d61db60ccdb" },
                { "da", "18a6ab8af8f14e1a9c5f0bb0ac60035ce91eec129951be266cddd69a95619c7ee3c96387d660e243bbc0d6beb130b74bfa330311cb0600fc473ca69e92426cca" },
                { "de", "5b462f7ca0ac70bb17996c027ecb326a94e1520fe03a4c789fe2226ca1131b9fda8c900def330792e9b2e938ff98a52d13e89598c482285bf112c992087263d6" },
                { "dsb", "0c9c37acbca7746b2a344bb7ded8d2e70315f5f04ab3a03cb7eb8556276308d36fd9524dde936b224b67816d496d1074afe8bd2d1cd4adf858373dd904b3f46b" },
                { "el", "f9ed14add434d16aaddd015e3535f79ddb19e1f93275be819eaec9256dd985187d8b212362cc096370cb70d524c59d53511d3ad823032c8ebe362535c23f3b86" },
                { "en-CA", "774b8334a60ba32f584fcabf6d653e6364b036b485018c0480a8649d2601e562588bf52e2284abadf14db82f84cd2d501f789f720a4e5c9936e02be2272f1e94" },
                { "en-GB", "783ab099d24e5b762a9116e63d26d97324908b856536a35cb983a26a5f1a263e9cbc0e04eb2704f600c364dd71ed21d0ca81487f4bb47ad2ddc8565777263f72" },
                { "en-US", "5e07eb71d904744326ed7a5d1429cf1474a522bfb73468d68df0a928f0dfba8f0fd10833759f18bd90277f8e255619dee4f5f334a8ca14dc7f0969bf9663feda" },
                { "eo", "cef79e234bb23501624cc662dce3de1f36f3f54b0641e8f1f8917bcced1c1df84863855f1829378b2316a64f822bc5a400ce81a97bc79a6e03b3365a1fa58896" },
                { "es-AR", "f63a448a3f54e69346f2388c9105502b6cdc78833fbfb22bb9502422accb574bcc1989e13cf60ab2fac0f3b53fa2003e5bf77725d0b758983fa581d8bf6473cc" },
                { "es-CL", "225ec48549249f813c3ae954f417758a27379c8962a2bfaa5f80714216571fc8dbdb5fa45fac4421d1b496c1f0debb3916119368e12dc66b2e4fe1fc6efdc2aa" },
                { "es-ES", "4ca39b26b335d3b33302419818796e9a43f2c3edcfa62bdbdbb6ceb9cf161bb55c2c084e72416403fa202e53b0e28973cc2807aae571b55c8c81b3e302ff4981" },
                { "es-MX", "1f4d3aa0c182d75258403d42ea6ee3f8c664c6fa872e1b73a7746c8224dbc8d81ad2d8a330411cff73afac309cf7f30415feae5ebf4939b8a2d3b44d5bbb9edd" },
                { "et", "6d4443c581f34bf09bc0db5096165d3469b65f6483278e93e3dad5d2e75a2e3c404f37aa840a80089ca3b0e92c2f7b672fb249d729f06a6b531342a7f561fd90" },
                { "eu", "09dc1081a5a7e6b04e8da686cf0cb2296ecf63091ddc561a99c9a89646c2a95040f9ed25812aef14629a93e6dec39a1dad439a427559dcad596cd78daf33b3f7" },
                { "fa", "24726a58f06421cf47d2a7c8089f5ba7b08c0779b9ae28129f2d363c6a6f6a50ca317ee6d7f5980c66be20d3f199ee9c356ec721a77ffa07d530df399fc58689" },
                { "ff", "432a25fab86b6f04b09dcde05e5d291799888357f69c4919b561e99f34cff80b9a4bfd36800a9af8975d570fb8aaecc879532b132cf6b930535dc3ef334a597f" },
                { "fi", "efda462eac21cb5d9abbcb30e673fd4b8913020f2b25b111873b00df0559712c253dabe6b91f2f94ff4be20b8f929b0ca7eb21ba4e2c33b04b97b1fd5d64e0d9" },
                { "fr", "b2419519ba68aeb173277b0901fd9a12a5a3ecd7166dcd1285d55b959ec7df4f8253edb9d8b58905674025f3f55b5cac867b8fa36c0554a97ddeba3b7f83250e" },
                { "fur", "7729efabd09083366668b4ca31ac2f340e88322b29e69d1949d81df255ad76901962da407314f3d36088b51f4900580c1b900d3c4a31fd2a4ff34f1cd3d474e1" },
                { "fy-NL", "775bee324cd1f48971323ebb8d188795850a9a02fb73b5f60678b73e270c0e4421dfd6b894debe24adceb7b63d2bebe7524f1eead55f3b1d7413c633a45f86a6" },
                { "ga-IE", "dd649a0896ebcc18fed678a06d41c3a25eca65bb4228eaaeecfb87fedba22ccd7f7a4fbaec9ebf7b4ea6653d3ebbe33c4e131ecd60d144cdf003a5c2ec35473e" },
                { "gd", "a12bd168d363fa226c6beca70dfce8daa94c65be5d8118f8a2029382afcf1c888bd1d62eb910eab5112271a58bc1aa9953f0bcb622d65980346653baebd7939c" },
                { "gl", "2be4e36519d38585cb7381df2264ff71f91ea88f0eaa4b4feb6edc2fd73e5337933bae9c5cfabfe3ab4ece4936ec26b0fdb6cea4965c933dc6def7bcf711f651" },
                { "gn", "690c6e2cad886322bbea2f0af2b181715f1b20faa812a221f6c92991f60f2e6e5555e5c417e56329cfcbfaa3bacdcf64f795a8f3328225d5be1e7a49741d9159" },
                { "gu-IN", "866efca8f59e4acb1cffade3c5bcb5ea07a1296b04d756947acfee1915af1d556b50569f64e86af017acde6b3a9e8e673ebe4a8bbcde6e9c830c01a5bcd7ba79" },
                { "he", "2137a1d7f61dc7637d439d3fa023d916d1f6600314a9f5d474b2cb0c36c3a9cb4ccc38b81081281252a72b4075c0bd25bb94d75ce6f0beec06fef539949867e3" },
                { "hi-IN", "ebceeffe6244b356971b3f93e810cf27ca7d147bc23adbb364521a09f0334fb0aeddd3a59c091b896e09c467013e5063b7c80424c786405d9fbd525d470bbba2" },
                { "hr", "38094f79fc36de8298e030fb94d1f3e999eee70e195370f1d8b90cdd5116dfa335f25ed5e42e42d768215abee75d1af572cc39319a1f941fe1843eef2377025e" },
                { "hsb", "fb95f371582e5a9d269e6a908612ae0565cfee6a80629deafb0631aaacaeb2f761c30aac9233db07ce79dcd1f4a89953f84360736c0f28456b38d56f33ce3cef" },
                { "hu", "238b40f114ba0a117cb9a8cff3885cc032804fa97635772620171c818a3f645ff4ee5b83c81c16dd25e16f86526161ffe295d988cde77a78f8f7d79f67ada993" },
                { "hy-AM", "4cfafa962483b1c1e421054037ad648724d0b3ed9ae577d277df03af8f4625269a3d440242cf5329ace18e4aa8a3b97f79c7855e12134e4e405a10c01416e443" },
                { "ia", "33fe0bff5c3efef97388812bf2fdb6e1b55f43dd09a47d979dff8fd8389bd2d60629e67df3fb0cdd676fb15f961af98584d4acf5e90cf263de96c86314767b08" },
                { "id", "15fd47aa71d548a04f84455088f994371e36edc71fa03b0826bf493f81e3629a2f7a4096d69794e68a98d65f74715bb64ef437cbe74ab6e8f2755d5f6f1b9834" },
                { "is", "50570a4a744e6bedaf945a2e1501655c435a06550e6c809ab0a06585998852735cc3cb4fe79cf3e64e0b4bad113cd7501e7bf0ae8fe0482d29f546fbb0ccff53" },
                { "it", "c3bb690f751b088d19b68f8914bd17b6721f20c919129676415179918d8e3d243e67c40b9a26a3f893b72819965f03a75660d4358cf9849c36293069a3d76f72" },
                { "ja", "fb7f7dedbea5cbf9759f0d1075bfe24d779491f37818ec33f5f979cd8b4878d70ed04e173ec150228fd187f6b8848336d0833929fe276eb5bfb8998e2cfb0ba1" },
                { "ka", "b823c02fae3f1bfe0513b050ad25ab2593330291b72be6ae04bf618540d6ce7b954a8bbee60d61594e45ea223b24add125d85c01f4a4e991d712505e9a66fcbb" },
                { "kab", "b905db3d77be3b7793fea62ab4ee2157236cc316b0033ca348da68c0b94c89d3a88106bcdb1cc597c14229972b72223ddb793b5d603d17f5e536eac5627081ab" },
                { "kk", "728996747507faf510aa42252e1889ff8fd691c8f7b6a95ce04d9b15396f0b7d56602d6b4192816b037b626d8591b757c44f005d13b79782e7018bbd08e98619" },
                { "km", "4d9c1c548125be61093f3105b118637043187a3bdaf95145217713f7d2a06f59f737298edbf62dfdd2d9a2f5c87a33b25f98fd7577bb00f6948ea366ecb9eaa5" },
                { "kn", "0e249152641600b042b714c445f5acf2fedaa651e4a5a595b5004a771051d75e89a06d1a514b0c31b56767fc0d75c2fa66bcedba2fa8ffaa3c529f633aa2800b" },
                { "ko", "b14724b767c16c3de12570a15617e00216687d18058e954fd17287de0e99f45b3b8ef870cc644d1950d1dae6ae9b9999d734ec71dae230b21d9de18045844c60" },
                { "lij", "ce3d3650e75e0b38992296bf529be3911a2f36e54cf48049c5376acd086fdff13c310075d2e91a6181fedd36b21bdb1b8a9cae286bb7e81c8d2eb43615e9462a" },
                { "lt", "cda491fc9448e3605bc3b2b1ce079bb1756e5cb3fd4c06f6c15414ef57cd7ca662dadde90b5f772ff4d61ab61dfd2d8e2713d3d3ae677ab7b2ce18a3829644a8" },
                { "lv", "4597969d3613f55a5457ec1d052433cda7f5e8fc731b1a52e881af6fd915b17629e93129d0be62da997d17b1bf0f48409216df483856372ff2bbc44b04b2d4d4" },
                { "mk", "bb8b3d975880f442dabd80530c7824cb62514f02ed34abaf745d0cdb14888bb299b7e3645b05bcf37587fe88644f49efb57f5fb52f3a1c53a254799aada6e50c" },
                { "mr", "ff9e63177d0aac5ea67a9490c16c439cab9f0f6c4ba4efcdec2830f79bb005af5c4e2870d391de9ccee94826cf5d7142c2ac198b17b9e6451d750844fe57fd30" },
                { "ms", "0d2d441b114bfaae0feb8311f846095ae05eec677af8e9f3895da15e269e475401c4a3b4822dc16ea3c69f709f32f655e1bdc0ed7318698850b5d39cced16f74" },
                { "my", "74b049e909dc4f5a0c1d4491cbcc90c38a5bed0ccd27ab659e2f8121498fc59e5d81aba1d335d891c13a8356cbc06596beff61cdc35b814b33c9463ffa662451" },
                { "nb-NO", "c392a3abc05f6f187e20b1cc4814fbbc36fd0968e3b47df4332f6596d93deb209e2e324b4b392d9cf2d5e46678df0d9518e61e05ff10de175b94476e338fcd85" },
                { "ne-NP", "2e1cffc89e2cc1b1b83fa562b4689668a8cce8e94d24c7dde23b1b57c0f762d94b954a8f7b58171444bd67a8defca021094908cd5b0ef521341f485dd7313551" },
                { "nl", "9c224405112f229506586de41cb07db635d41cd084329e020068a31d670a7d7884fda4358ea9127d37451f6e29edf7774d32a09bfdb64963c11fb680dbd447e5" },
                { "nn-NO", "098aa943e3cefe938b6b1c79b98f9500ea26ba52a027cec03a6afdf86cc5459b3325d0a655d9f2038f5e036262f94bd2fbd2e843ef587c938820db363c7e60cd" },
                { "oc", "f7f4bd1e6cb0455b0b0c58be48a58ea33e96a6462ea425a71569db4318cb51cfeed3799976f15d2c4980158830aa71fc89ae4eb0ba01e609c0ed94113d6a8498" },
                { "pa-IN", "4202e94975bffb893cd93a6a062a77c684b88c1db786af14954b6e9a15287f229109d665124a25b08c60ab357f08b93a214b63042f87f2677d98534c0088ea47" },
                { "pl", "910727c0ea4fc453b1c493f30fb96010d0f2b2dd9c3c87167788ccf95846e824fe98c7e6a5319df212e9985e6febb32ffeb7cd38f529b023a86710742adf0b41" },
                { "pt-BR", "b9f58cef746d3acacd78e3a9ffdd1c1811b474c1cc516cf43437e758c691056b29da759b8f78e196611c812c4aa792efea16a6b20de0d570c06b4e95c677af15" },
                { "pt-PT", "b10a5e2c3efa25dd1d3ab844ea76e79ee4d186a55f8dd16cb95ea5a027f4ebace97ee83cb9ee378fd52787f0eb145ff32108bdab77c9f546ab1ae47a97a7859e" },
                { "rm", "11349f40447e9da72d8589ad77a96223bf4c256c12913ad564d8298e5aea500a66d40386f650f1447f9ca4d6dc91d0235f0593df1443a9dac474d44f97af18b5" },
                { "ro", "bcff793debaebd0fc4c065913866eac5e28a28e25487364fe17f30932ee4e9a24f1d5bbbcc8b91462168228ae7c87dfeb7c955d1b9fa239a493ffdd49683e915" },
                { "ru", "6fb2c81af03eee0453a9b02beb68fe754c59ddae4bec02da6f4a901932ca53e3521c270ebe269df244e021bd15c0cbb74002eb962e8f7f835aa07f9409fba0bb" },
                { "sat", "241979fdd7da5d9d05a8a47dc5d4e7ff91f58c7cce5868fe321bded2b4f2392e4edafda1f805b21a25aee28e63e1c94340e401509a86cab4848ace3dd36a7546" },
                { "sc", "ecdc4bd04f2e78c6eacb3229e7161e9453ca772fed37bf839a100307c39a7332283aa97f86bb141ff590b54ba11677d1727d77e1bdc93e2a1bfaf0de8589d75b" },
                { "sco", "44f549fb2205cfe579022bcb616d1c019cfdd07960d5c72a5143fe9be400262c329ca0a18977044c29e0b39ab3c56e9846929efb746b685f10e1d5416ff6efc8" },
                { "si", "86a7b4bc048172b15b870267e0b7d1368eb62a44032596fded033dddb91d9f9a649313505344542084845510439f9bc37c19176f9f7cc768ab812f9d6ec00e6b" },
                { "sk", "460b2e0d36190ec7643388af8221f5fee5a739e427edd6823ceb6785279d6dab0fe664efb3a0711e4eee26de444b7bffeecf255e6c13c5208d7738c58752cd8e" },
                { "skr", "bb16ae01dcf39d755e4c34f1477c60959b72c19f04051b418be635e8f613f1cb6b050223d5914a1114cbcd51f5e5db10d7640edcacb76b170718ea05c0a57ef8" },
                { "sl", "44f0bfee45e0ca04e14b6e8bebabc7663337625d5b763ca90a85f05fdb5ff72da8f6bb964a26987983fdfc613ec77e4789bb752f2a203dc83d35591be28f6b9f" },
                { "son", "79a62a974bd021eca49de16b58258b18650f28b7b4957729efe498124fd3ea496ddceb485fe04f45fb2cfd9db5b20bcefc5e0500aeabce7990894ca7ce246d6e" },
                { "sq", "d319dd4cb4b3c769d10d886829ba06128adb1333ebfd9668f48100f80427f4b7a5686761ae4d8e71377b1b45dcf3441a4f6bb796cf24da66a235c2d337529a9b" },
                { "sr", "aeb88e1eea220ed1110a88034d212661b747ef68955f72d039eeeca1b902250da71598d479bcb6259796ac65690699553467177f8733f86f87663fba2c846ed6" },
                { "sv-SE", "1b08526ea98fe7f2e05ae66e46d36c72ab25ce5d30e09af12b4e96f7a2c7a52aa24b25eecb02f90a3a1cad52f9a8d2e03022ca44d6d665783d03c8d1b6e31b8e" },
                { "szl", "c87d3fad02e137e03b45bdd23667e6751975fe491bbd379d54c3b4fa6464e2f9b2d7b37813bbce52927a3cfe73ed445c0c17e5b264f2811915937da2d80f9595" },
                { "ta", "7362fcd582921d6b43bc49ed96af8793ba4174311528bcc1309c304d22e8f6f12edf847180719b06841c046b4f084cef1b94db71031fee22a943b1f3b4af6bbc" },
                { "te", "261ee7a233338111bc24162d7330db5ab1384882a0aa8d2ef7fa13a1e4771cf76017cc794377bd992d7b180428761ca5bf37362812781f8290977217839a91d0" },
                { "tg", "dbcfe5daeb8902325d76502ca7e0ef21a7aef7186b6a66e23b514500ab99b66c3eaf41cc9f0accda15a65c17888ea7aee41b9b920732fc6a3a9e9222a06d8699" },
                { "th", "6ffe9f813c35838b37d4c8a22363ce724fb2c7dc0bd0de561e4b99bc478b6caf6177cfc5aad621f35370d5df05873847911074243baadfa98b3dcbbf3174a618" },
                { "tl", "8581b5ac1b30fc38dec76abb156871348739eea376b29d853ff1560160fbb1880e92148a2a4be524a4612ea51f1e6c50a6ff09a88938da56ea4c003150c6ead9" },
                { "tr", "2b611159f0205a0d7649474b39a114d92bdf870f09dc011c26244201b7efd160c51ccff998c16859911542feca8f0a4900b6211bdfeef49354cbe4366995685a" },
                { "trs", "42219f9b486c414c7402d8252b84c28d39508d4b23cda9894fe12e4021255ee41f6cacffd9d50c080a8e1bfd9e32685d66f82e5c78194917b1ea6d7c3de89326" },
                { "uk", "42f9314918a25fded3be6ff47b7156e8ee26a0c7854dcb63b0d1182b98ccd67c941002ffa28692f203a2495144244e35aeceec7c466e0f5dd063b595a00ddf07" },
                { "ur", "74e2be7e1a250593d99a414fccc96b5d5fde9122038a5223630b6acfa0fa5f52ed79ec105ac9049b2c1fc2fa71f0f9920e213244aa9e9e99ee065326fa5e54d9" },
                { "uz", "7b5b50b5ecbcd410315f9b7f89a05c2f287cbe70b834347da9d34ad6e370d973e030b129698e1149ca780bc09e175a0956d26e01c0f5bf225c49df10bc50b56a" },
                { "vi", "4c04389e67c0784a52f5dfd5bc61d5ac1656b77fe14c37785dfbe555071c5f16139ad3409f9f10804b2600d74750514ba2124ed4afda041ae756c2e1fa6a34b1" },
                { "xh", "6314699613744207c4740c55e6ddb7387655b3b3cfd6a0d524c534b4df6444d5e4350e7a137fce9ecb85df6da7f29777330014bb61cb051965c25f5b2390e9f6" },
                { "zh-CN", "f8c55c70956544b142a4d9134809ac101c32890c32a6e855a1b316279d51423f625517dc8877e0f210a9c6693663e599016aa4c7cb7a9374bfb1f823a3c28bf9" },
                { "zh-TW", "2dd4cc3cc9d2efeba4d8d4e01445ec43a5162e1afe6f7ed07f67ac2069f5183b4d6f55c6b9ca33563790792e55e0001152fc22e469a94128c3c92e721eee60f3" }
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
