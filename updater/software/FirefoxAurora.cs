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
        private const string currentVersion = "139.0b6";


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
            // https://ftp.mozilla.org/pub/devedition/releases/139.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "dd9dbff0fd5248c1f8a1bf4740cf000100fe2c43a8f8df5b6740feccde128aec8e4599071c13a9cd0c08d9afc9b7e3938aed4b0b901c2af70aa255596e64c5a4" },
                { "af", "26c192f21d98f01a625e10ef162ca4670f2dd3b7343ffb9c2ee8109a43b4b5da8ebb336e07a82e28a6515cafcd9f3be00a3cb66108970769d9db59283a468f72" },
                { "an", "2491a8e07cd51585972d5278f3f05e56cbae69bf9f37cfa197ba64329ea600b4e33a2586ff2f27d874d58230e728ff3dacf4c4abeba9cc0b21e486e53f8229ce" },
                { "ar", "19c1075bbe2c02273302f811a29381fa6146dc7be124b8667e6058ba5a1d01713bf45d1d2496d8a634eade9c0fc49d26736fb0a3fbd88814cb4b095e7e529491" },
                { "ast", "be19255013f389e1c7ff3fd8de4665d8641ac562992d0e204a21e4e0446bc12330977df95f46b7e77be3e284b158a2e80dc15d6efd95873677fa1aa0c940effb" },
                { "az", "6fa0a4793556afe996486573fb94d0194417ee8164d7aa103812951f67940f179c3d7229f48f3d0d7992025091deff16382acd13843302cbf60f9d22989ab2e6" },
                { "be", "b4f9b84ee390991776a55453f4e021eca86bb77c7423d0062c7d1afaf7ce8e82fcf19a8645660edf11f24c7060b42afd28e5c2bf82e860d8a5e35e961fdf0661" },
                { "bg", "65ba57d4da604ef3f1aabdb9cb54b9d68a198f0962f0c3ed6f958710f11882e5ebea2cf325b58efbf2392cf2bb96e9fa460d3f623fb75f742539178b6705134b" },
                { "bn", "b2015cc8f48a8db45d218a68038fcc154cc4ac82f8cc8c90b6568a25ebdc0eb09f93bdd358b3cdb02f686fb997acdfc490a90f8ba8cbf2652a22425ca6a532e3" },
                { "br", "a1ae2fd85031ed8e7a6fac5300a63465f9743b1e9dd31327ec673ad619a76192216cda2e85b094b76571c1122d4cc3a690d92c91c9c34eb80b7a55025219710e" },
                { "bs", "8380b6c6370854697003b094a9a0b4406d1558063f3c2b2a665d3ac3fd92e31a3ca16f8933172e5e4c91851e3402450bbe87c3bda66580f4cb5855ee54677efe" },
                { "ca", "760bdb74eefb008b6a744e1dfc20b04bc1f2b4138a370f498902aee1ff3030f43a46556cfd6704f562509575a7d34e9d649f301a25c57925a86162ef3e64700e" },
                { "cak", "9d0807fdf85b10d4658150e9e3d54569564d705c9a71bd7bd93477ff02c74ee76e8975404ae88a974f98e240975bff255555371c95068fa1725f85bf8de2d853" },
                { "cs", "f2cda1ab0e73c16d79c2aaff890e94df5b499b3e5bcf40217ca7f8a4582c0582cfe67c1c5d1a7819c3b790db3c5841a5cf4026d6821bcd95ff5117669ca664ea" },
                { "cy", "5d92d30d102163e132f9a3e43d3b60c22aad3a9d21510a37b607a2ea95c3b8b2166181119323b44c13f8326c39b951e323ae475598f6c1d4e6886854b49bbbfa" },
                { "da", "d3aa4f0c409fbb6fd47a78d0bcb274700875245e4e5e2b5ca478007294a1eb858aa2a48a35daef213724a9ad14423c79dba936dc1787424706578b17359f9faf" },
                { "de", "f8e1e500f72ff4c1ce2a1e227db2054875fab4ea91f65dd7f5bbbfb48a920531342aa61b157cffc0826fce93f0b81d220a04928e73b178729efff260680f6707" },
                { "dsb", "6ef61bc6e47dd3c86aa5943b36845e06840e6990ec876474f3de5e2980ac5fd63671daf37424dcffafccc9318a14f81ac4b270cb8ef5088f54918a7a110c0b2d" },
                { "el", "ea309c6ed7acfabcf5618ce022d2c2ac525cacb574248ad2052e70c4de5a167145c8c5c15e2573ff06299eb930b89b1f165761091774c192f2791b78d614e1c7" },
                { "en-CA", "33890a5985b2ff6f1e3aa7671fb5de013719e3649997647a936a307bc54050ae495c3afb19946d5b46669e8fd0a7c7722b291e332dbcfb151b40461a3a7ceb9c" },
                { "en-GB", "76c165c96cd3981daf4fa455b2a78fb256b840265b3f3714ff8a18b89a1f12a49a892dfc3c677901195c9aef7ce5ca81c0d9500678e15d371cb67d58b3c90aee" },
                { "en-US", "d261b9a0016377f82d6877f9b377267c9c13f2a033b91ee1f7fc465293dfddc884811bb5d58c0c71acd8ba92d4d90479c34b462ca4e14d9785b66baea32be811" },
                { "eo", "fa2937a439886112d4549cb818de95935424cc44702df283ea308cfa9bc76cc7a0c48d2c619d182c3f42d422090b272a7bc668058133bbbb7d60426e965bf608" },
                { "es-AR", "8c244d8b58c3289fcf83b60af045c645eb74b9f8cbdf619a2d85ed7d4ce128b35749519ca0e435820fc7776bb5c9d294d69c0964a76a5f06eec8e0e5cd7ec83c" },
                { "es-CL", "2927881e846976948d94804d3c0a47865d66cdd6644a08c64d656cadf2ebf575bd25064fc0a82ef382b668f29299024832423961807f205102f53070052f4970" },
                { "es-ES", "ea1c8cc31122a404932016c1c9a9a8c6c986a07d3f1cf94755b581b84617d206c8c24ba9a460219cd06affe38446c99acb1c9753db0aa575c69cc3cdf5a8b5a2" },
                { "es-MX", "e121ca29b944faef8589e309778cc7a924683ae5a72d94828303ed5b8c535cec7059a8cd6c7b97fb63a5644f1c71284f673787fc48a99d80adcb3bf3b415642f" },
                { "et", "97103b3b2af3f78d90a6a9efa37750def4b7e141c6af1e15ecde885429a297604de0863001a0ebd04858013cf83e16644cc09ca53f6bed0ec6aea2fbe858c60e" },
                { "eu", "c51b66e7d468d3bc80330f4e46d3c92e2f50a9ce5728c0e8cb6edc0281905a428f635af4899bb272f94381c07400bf03f58ea02ef15733a327e25e81a28328ec" },
                { "fa", "1c6a9ec9baf8fe6c76e695adc06d949d304fa718e50d3271eedd35bccb3859dda31355c0963691129db6e7ac3c29f4fb84c4747212fbc663093731868f079c3a" },
                { "ff", "0e7cc335baa5dabf7a1eeda8559ea28af0977c31be0daa3cd401f0ea6b27942250c25c652b208667394d323f144cacd2b5bf35e4c1b7bec7865308d9f2729c4e" },
                { "fi", "08665cbc8520969bb6d20637f11cb050f0dcf6996739246fc2cfff3290c4e21ecf243c653738d8d831a37488f2db6c40d1ac6457c7b95aa820c975431a30ecab" },
                { "fr", "9c3b918b26879b5916436970dd9c97675bf6c4fba0e960c9451c613f9c7ca92311747bcac3a4c99d788f3ac6df6499a5242c97b85d7b9539ea49e3393f504e5d" },
                { "fur", "f155378efb83c8a3cf570c5bcda1776bc151bd7e2c769a02a7165a68185e5110c31b096f0b44370f9424ebba24a67f4dbcabbde2c3a2a1a139d18a2bcf6c0d16" },
                { "fy-NL", "ef9deec065acb060f74e0693dd3a55a18c60cd45101d5dd7f074a353b7dd8ebc2c853ea0cb16226823bb66f2222586820a730ce867500814f445551fc381eeb1" },
                { "ga-IE", "1dbfa780d4b641a08c4a98d7ca46693afd23dcba35af7cc653abef033ac4d495da7c12261cd373e312031fdc15f77a35ba952f03aa68052b64a3fba65da9a40b" },
                { "gd", "c37663c28f86f58e8ab77c2173b2df1576f8888b9dd0c1ff8804f98502db346f0c9367baf9aa5d7626c62e2ca69b4bee1aafe73d515834bdf547dc8979a521b6" },
                { "gl", "7a274f1fe2c39308752e37a80ef6509a137e219ae39ecb13ab15342037341548fca84f5ff50b7dbfbcafa56c745780941328c7da47810f58f5b882262c637730" },
                { "gn", "a35822488f8e3fb6ef9bc64348fc0ffd514e2c0da207ed242de3abb91f4d2d32deca668b1deb0ed8b08393632008d7e37b450e030e0c2118456570a9781c0f29" },
                { "gu-IN", "e50b94e33ffbca52eb03e5c58afaef5754c79acce9f4b190868d3b16a31af564a52a7a7dc43d03cfadbdeaa079595824e87a5e97d8509e6c97aad1c08028e2c5" },
                { "he", "5b6f48ab8ad80f258c0ffee3fa3c0e75840e3aee2898575292a1ae040fe55cc1e11cb0e21bb817a38c32cca58d8e85ec9cdc8b595bb7b19c4905e41d87c9ed6a" },
                { "hi-IN", "b980e5e993a7dd81b044f828d12899b0ea10ae4b42a9c1683d4ba57951c9563d67c48e74e076de745af6f771dad59b523dce82310e04aca03c6a6526ee050ce8" },
                { "hr", "677ce5723398d217e6fd8dc6707cede569bd2511736693d66e7ace1fa77ba95079807744bc02d376b4662abecacab4454c6063388dd5dec87776980a9b55785b" },
                { "hsb", "b62a33c50ca4032ffbc7fb997c24e78d038c3a40f3180cf07bd8ad7209e15168bcb4746b91aed34d9ffd400a91e85b907c6fa361053028a23aa3018ff40a5624" },
                { "hu", "e68aa8de88b5276856c092aed11337019a753cd69c8267a2d5a4a64906f5c6367abbd6795287563191813d56c4f7ae31d888a7e796fbeecf2002265c20b7e178" },
                { "hy-AM", "94234522c2cab6870a5fd17b9a791daad80232837ba7d450a8afde00070c4834202c4e782ed9c56f99f648d830f38ca67b0ad2950ded278cba7fb1b533577e63" },
                { "ia", "497c92f21bc32adddba879bccb8f6b4348e51c2625bfa4649d62eacb31d75dc284f5c4c37c17017c8b47e9f59317a16fdd531cacb947157c7f229947d0662219" },
                { "id", "12dbfc657054d27454018834befd1b6776471906f62af20b8b6961816c92f1e95ba4003ada81c8fda23cb3268fab3c770e69169d47d7627ea59d35e732cb0381" },
                { "is", "ee3bf353ff47f45070a42bb2b3eadd43446edacc12d98ebd9c2c66056bffc9a541c6e5fcfef11bbe3562a4f1a263b38717a802d57ab94ca5a17a58c7d54e328d" },
                { "it", "14847b43378faaf4f4424a33ab95d6eda246ac80b041e031d029397c1bbf56b661c423cc547e257ad46fcefec7574c81deec3b0084ad1737a445163c7628f90c" },
                { "ja", "67606cea5e54275041a71e26a6682727b5ebad4ad232ed13e6798f5139a9d4209da115461378f4891212a488428e2cec31ced05b464464b0bb782f04039c17f4" },
                { "ka", "b4b98be0544a82bad2ce3b97f81c6258c735e24733223ee04691b15a71b23a88b2fe801b608e3762e667c87dc2845e6d4a36a914cb719a7851e7744b7ca0d1c2" },
                { "kab", "27d6312891b5b40c4e5f5911d0ba26fa876e356de8e140a49c60bc57986eb86bfb1c78314e3f52070e44bef6749fb6063d79227303894372289a482745e08496" },
                { "kk", "cd7411fefe061bf4eeae77acef3555b73e375508442efc502bbf365ad0ac3e86e04113e0d2fac870caddc2ec13199761cd26c79d9586c4fffa4f29991086472e" },
                { "km", "9d219050726e6f1afd2e4329d1229ae81bd3e314b8caa61947d06796ecbb4581cf195a7ba00efb9dc09436ae63540bdb3d4fe73b0c88b2db4e18c98659b86047" },
                { "kn", "b10f39d3a850d44f9324219bca7582f1a3e815ca683da136d688846d1444e12c43332289d6f571de93c4ed73a38b5315d44ea3da75f80ae6da3dd034ae22f137" },
                { "ko", "3aa75e994866cdb42fd787d9970ac69f5f6e17ad551f47ff52790769a72dff873bd575ac28ee531dc16a4cd983b69a22057a85547e51adeb7081a14a2703eb8d" },
                { "lij", "0634c0c9ca9f563f512ae14b08117db751110a36628d0db34c786c5a0e8a6ef8b39dc765648434592687322a49ac911c4d763cc49e9e7c6d18a6482b2f7b5363" },
                { "lt", "459d34b70c77ee21e2487bdcd3426006199c304575f2b5c4bc95985f54eb159b9c52d12c624c45f4fc192f5eef12c8d188eae7d63683a9de68f01d39a144864d" },
                { "lv", "483906be4966ec66dc6ade35d9368eb639518b71c1a22ca2aa41c3979af4210748b090b08a430486687455613c590ed654c2da6e6527b587f13870852daecc85" },
                { "mk", "69b65137aac8c765ff232effb8702c7dfc2e50d8333fe200cdc075ee2878bc9eaacd42733cde982ea0b6ac92df02379de32bcddd3a002b01b9e7ac7278ee8c2e" },
                { "mr", "6b8c4b3548b704c2ef8e5fddb34d0fd3b8c12380e55a86e19f9bc10bfdafad048197b68e75d7756ddd997a90cb0565a757486b2fb6ab567cfe0db5d55fdf285d" },
                { "ms", "0d515081c7f3233acc8a8a9a86482557d2c9797d0f904f44c06f5d9c37aa151d0ded8f4ec073136ee905f0f6fdcac8e605a5514ee46ba5a82454ce20b140658a" },
                { "my", "1dd30df923f54127d13d7f54124d3f2bbc6dc3862ea8444faf85c7b22424f462a6dea4891ad2f24650873964e4d0daef3a703ebfbb4df5d4442f82f02cfc08a0" },
                { "nb-NO", "54a4abb757357e2d91c08de9ef9e72aad66405cbeea73e46bdcace301256377bc6b96041a5401573e76c6bd54f2bfaf06bb2d1ba0357bd4097f9e1a13171010d" },
                { "ne-NP", "1ec2083c6e0f02fd3719f90c513986a91fc0dbb5a21e03263126f430213ca2577c98c800bac2a95039b578169f9bcb925d95b5aec6f749f05cb1abb1f46c4f59" },
                { "nl", "21a5a8d766ede78cf84ef6a0bc62050063ae2ad103b02d6f37f0b9d27aa5d107e11fa0db45924d7ce3b4325514f5ab829246a8374396cf3333fc26ca5539a649" },
                { "nn-NO", "3521654cd8277875fa0068db5ecccbb58495b734b72ba588d320f883efb3913208e3bf40eaf0ca6cc3c8e8f0d9fc0a1f0a324adf235c2ffb03263c3e0559b48e" },
                { "oc", "172982a0af5f9e5838e3fad26dda177512bbc0abe04b3b6029e1911fbaf057977f104ae6d39b61355ea8a86871575efb50451f90170313582d9689608daf4b90" },
                { "pa-IN", "877612c8ed6a655a1b39a8360dec014643c459d0b19bbc60ec604fac4015b559de653960654fed5a4169a32a88ba8018cdaeccf9789e361b22b4ee6d20cac73a" },
                { "pl", "f3e6df4a22eacddecbe8de008d16a5254a7b09a594af202490ff4ab82aa80311af1cebc35636324266db069c174d7147b3ac155be30fabb1316b25f2061c8e56" },
                { "pt-BR", "c72dce5b782663147a9d35041981805e6c76822e999bee8784bbbccd4f4a7bfea47c5477fc23734dd3c0eb5b2dc8adfef0203a749138c0c068c24d315af2a6de" },
                { "pt-PT", "353ebe521e4c410727df1f577f6fcedeeefe006161925f4d91722f0d959d2b4d0f5c723049c938da76236d7bc1a0533e43f6c63c028e9fa70eeecc2e6d9882c5" },
                { "rm", "b2f57f50d2dce201834aea8b4bc68e05f3eeb7d90fd8a4be173dc2758295d3205d8871fbec1a29591d56060a2f7635cc1e28f74952977ef7378d41d48b83b94a" },
                { "ro", "83b60c355ee477690629b9bd6dae3e83698401d5817675a1778fce4ed27abf4a8bdef6f0730bafcb695471353432257985b92b4f5ce1f314fa794fd599df188b" },
                { "ru", "a1e499d5e5d8776855cedcecd80d16f6b921fdd7732ee229043b90ceb540d157507f0d1217c0e1ede5af8b8c784423c74d9354d18e8f9f3551d7c729523e1cb0" },
                { "sat", "a128866fbd48a26dc83fc30cf0f7f73fadbe844fcadf9902788315a3dc3f92624d4a913f4baaa462861297bc32be4ca74b997608cc76d79d1570de5c9f44cd60" },
                { "sc", "b8dbd71c0f81c97f55fb1b47dfc56f7a20aa5fe617ca88dd4f60999f0f5547c31f23ab456117d83e1f206222dbe51982d17dac5f392fd13c85b5bb3dd6f156ee" },
                { "sco", "caee2b27230af3cf5046a7b3ae675a44f9710c7f30b353cfeffc8be14cd61d32677a435cd63a54a3bba2f057c42838643074e73c9319de57dafc627ac2f1f985" },
                { "si", "db72a5f761c4ebdc2c4157047156fbfff42ea58822b47165fab73e5c42060f65169e08e62925d2411c4ddb4e5e65362eb3beeabd68a7242019f08280001dc21c" },
                { "sk", "201d3a81fcdf32cadc4ade8d1c5e70e76f76d1b2a35b19d5877bed8a99a2f9f165d135e50a98ac13229d9e4ab311d974956960140d5f04e4f1aa7126f368565c" },
                { "skr", "d5d1a80a9c4fb76d179e187a192efae6f13bd95d5ecf8db271895d68035eec4c18757fdb8774f084f60e6146f9d41e2edae3aa421a876a8fb5d220438803159e" },
                { "sl", "95f6fa1af6ac2558bcc044bbfdd02f1282769f7fbfa26b3fef6aa2d9f4e62d2751096fd8030d16ef971ea51f87255902ac1f377f9c19e854319ff0afdb557df1" },
                { "son", "0ba7683633e06f9a08a9d11a7c22217492a7fe040c5ba59962685d1573c71240e2c2dfaf6b219af268b6e7809dee84c5afcb09170a83efb5c2c5573ce4116913" },
                { "sq", "a244d9f92e8aa7c24f1de054ee77298e23caac760b4b34b61b2130ea1e1f4129cf9ee04666b138e6fa39531bcdb0e876a8fa193a44b01e7cc13093eb96135a48" },
                { "sr", "5fc93e11665a0f0bb97735c65a416ab9c4291a1ca8ab58bf0342a180d6e7ee6500a665188c28c580f10b5ee078719bbc3bdaee086cc4e87bf95251c390b2d910" },
                { "sv-SE", "f2cb4a82967a733e444690706bfb38644d79db94727222cf8bfb49b5686221a8f5abb412ac145a179e68d545c45bcbe3e0c9838a106faeaa7d367f29d1c3cc8d" },
                { "szl", "7b79995596da9ddfc9b5cb6de120b2df2f4930617a299e91235e0359742819c205cb01390e60c02ab55899ed9e824f457421ccd15441f5ef93f4b39b53982daa" },
                { "ta", "43ad414835c056021b2272df078e4136bb48dcfe24ea45075f47222150e4883424bd643972c5dc971a88a4e39dfa3d1a4d92eaca83e0ccaa796d07d774c1dc4c" },
                { "te", "ae2c907f1d06f0af51176487fbae3b181b2e750e89aa9106bc721915b98b4bf3872871d1a062ba4fdbef2cbf1f918eefdc0794ab977619d148614ddc8198ee2f" },
                { "tg", "7b0a454fe3ddd89ea8e6fd9cfaecd9d925b8870dc1afb674e2e26d6ace663cb8b2305dbc5e5e3d166667440855d19eb2623d7cc9f49afe62e6d10046cea0282c" },
                { "th", "f13217263fb40cfbefb2a4a1dec8fd88925ca9b19094e32193ec673eff5ff794ce62f605cd80144415ec5e958b593d5e72cb697df5408ec73fd05dd5fef4c92e" },
                { "tl", "ead398fee084c3cfc876bad479d10818531db28beaa1213c2ba5766a0b0c89b2dd4c82c0bffa536348489537940708fa09eaeeded5d03c1e88098cec549a7927" },
                { "tr", "fbf652b7ba7a3d991037ba16738bd7abc2d3544e4fcc157870136faaa08a64dee972853044119c7150fee1a3068ed5fea2cbb2a630879742ffbd8e2ba5f33a82" },
                { "trs", "400c7a32a90ffd62679e3207a97008bbeb78f759adf9d74c1fb516b06cb1cb16370229585c79d7045afd429e5f9b2a790d2e63b231c65158bc22a6ae0b649abf" },
                { "uk", "89aca4ac145b801ea77e2758b594101569a4136736f076cc9d4b19420786bf8eb406a631a471d9232b6218b3e7b7d25a9fa121657f4a5fc4c93451bf80412325" },
                { "ur", "604435c043f5b3c13b92656c86cf74a6dce6501e141a31fb21940a38080ef8da10efe555c62fd544d182d1003bf7c2490191c91c44c6d5519e5468faa4959c2a" },
                { "uz", "bc7733a995e97ce1aea2750b18aa23b9529fca660cff5aca148fc700ed472b38810d1bafb418672b159d29f3a0a19a22351573676456acc66c48df4e0dd961d9" },
                { "vi", "b63abfdf8906f9734d55a78bdc0557bbc416895f9301869a719ed92fa74298e58c4463f917eabbef3366c02d2f8e729fe0b16944b079837e05b51f19a3aa36ad" },
                { "xh", "bd606edd973682d51559b565f309a36c07a46d80b8141d373f03656d7e747767aa08ae1fb11564179c3990568bee5c5843af9951488b056c794d69733feb129e" },
                { "zh-CN", "698b3e61590b20d20cc40b647065bbab4a14fa51b5f088d7a1764f19817d16bd630d03311f0db7c55445ec0c1aed32bba977a886e67e87f1b443ba20d1653cb9" },
                { "zh-TW", "4049ed76b1045d9a4b42f9d2e3294382a70506e9f9181b013a685d35b5db8da9acb755f70cce8aa2d39998265553df4262617d3d44ccf33747015f91c19e07ec" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/139.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "ebfd9cde0239145e4a8affcaf6f4a0adfab3852b03999ba4e95aa43e5147b1f06bed850066d6f135a9c1052cdd5af916f92385a65c90cf12f77554c31fd38d28" },
                { "af", "2586fc846c71abd463d8cfa7de4971d884b45a4c3b9526cded8d2959ddfa04b21af194a4ce8279be0cbd6855a72f4e4eb29e866d02b3369d79845d1dc28a3666" },
                { "an", "635979f6f50228ddc3ecbfb8a72460a150a66a042ae129f9353f1046fe8ddd89d67d810011692d6096fa8376d7b317c0bf904cab58b3ed6b9948df6aa7a6a400" },
                { "ar", "3cddb62fc495212413d45a1bd9afbbcade890b2a3e229509dcedb5e636d86dd11335c0ba84e146c1b474ef5ff7e88f3b56d1e790f2116650bcf205707dd78758" },
                { "ast", "2a0c81681052be1f7077fe0026e6cdd34f896617b36c66c9f586d2dda1ab01b1b2385c309b4a1abdd5c69fbe26bf23384179497c928a90ab7bc5e5243e126950" },
                { "az", "a6363b40288f0ad23e2610b0d75fe986909b63bc39dadc30180ecbf72fc585eff0a708964d83cfd13248a3413e4facb2580dbdcc6821371edc486dedf9f216cd" },
                { "be", "6aa4c0762a7b7696cee203869021df2cad73ac5d913ebc248d5329a44f3ad88b91eac0738f0f5cbc7f9776508e2b60217303636cae1bff14cf610ab86b5f8a75" },
                { "bg", "6b8b8ae70b31b342a179b15edcc2bb575fa3bf6a59bebf24275774502e6ef9b7f023f2a524e2a4d5759c91206a00ef07855bbf581924b426aad0e37dc309a170" },
                { "bn", "a6b25a05fa5d84142d1b8549bd97c4a82f37d1c29c3e3e22a7195c19e13fba7af9838e95613a7c860d0d1b2d76bdfe09f5d8f88abb0899fdf6faeef4f9a2762c" },
                { "br", "c039e6380e04eec38cbceea562135a15cb6086b1bfc7740eb3df3f616eedb88f96517cd425fc0c912f5e93ee6a2325c1388c3678538a5fc5279be127f04ace3c" },
                { "bs", "7b122e5d9fa1b9fb4dbb77f5df62c5ae83b22e03e5baa1cdf80527d6c7532675268ca1124f4db7c74298f22fde21015cf9b6bf8846535c67d37979143008975f" },
                { "ca", "8e682cc55095766ad19333bbcd5d84d3cceefea1fc84bce5547f5b68c7c7a50917dfb0e4fd99dd2303dd6de07f0705d9789b1b830a5b52464bea7c61e4b95821" },
                { "cak", "89bea8e37df8b5be99152c0cd9cdfda1f46a53f0f9202f766295cca084c4272deada620cff71925d4859df9a65cfaf5a85a6552099bdd56d11f2d783eaa0878f" },
                { "cs", "4e4f472b33d957afae45df70c84783f9202b4fece2d60df8351edeeaefa68e2dc124390a690e3cbaedfc4cf24ba86bcd509d555ba058f380c4f2dba6b8ecd305" },
                { "cy", "587ab1bbef50966b4e9fff672f551a0d73a7e5eb09949e148f8f4cb282394843167fc170262cce37326bdacbb7c90d6490846f68bdafe075bc7ab7e747761276" },
                { "da", "d8b15dca3d78df5de5cc80411ef067d89a9f5c9c4efeefa5af1a29970a62c9cbd9a3066222d15490961ddc49e4933df832211149a199f8a82bb6f49223f88fc6" },
                { "de", "4c5ec4dda92acc590689ab2abd38f216ea171bf1a45cf59612d9a87229d591cee93e52234bb3f95bde1f401dcd255289e5fdea3b179b9423f9f2f6fb6a59fee0" },
                { "dsb", "70b667cbf80fea35afb87e661f52a4949fb827fe073b2cf3b60636cfe41477b3b28b4e986a5f5639aa2fbc59e012354ddd7675bb29c1f52567336330f736514a" },
                { "el", "11b1bf951819719ef73ee1c24c45c3054d62a0e8bfe88dc5558af6cee2b8a9302c6d3b5b392eb71a3042db327022a2bfe786685cadfa628c167e1adeb651a683" },
                { "en-CA", "ed8a5413908f64ba9fb02ca0bf63f895123a2d653178ed7a5e18d95e522d8fa0d34a4304c4495ec9ecc808a20348295248ef284265972e6d7d5232d908cee5fe" },
                { "en-GB", "ea57f82c42bb4afb9ed8f10378efb8c6e1989539fa468da95a608d2ef192d6d0fc33ce5d9f38240e41381c0ef10367b10aac38a70e9999cc8b112787250792de" },
                { "en-US", "290554edef5e86999f452c968a829aedff448ff386eb25265dea79d64a99a99df40d2845558744c452fb7a775b67bed3f8f43467b9207c648ba0493f7842628f" },
                { "eo", "5dc0d13383af524ab529df139984dbd545f38ad753d9255c42bd683d133b1255a176b196df216776a768a98195ad1aecf984fd93c52e66b06c0d6e7ac15f2041" },
                { "es-AR", "70013e9cc5067850c2a1e3e5df63ee20cded5817e9113e301006dcdf06ae412a7a282b8c46bb4868ab4f5178a0b487601871b7591515f3da995bec1e4cd90b64" },
                { "es-CL", "642d4b073f4ee935d62924462799546d9b0d81351a07cbc844d789c2bcb69b0b81754ed8cc435605360a9e8c2307a51529e0c9320819ac5bdb34a654c2d680fd" },
                { "es-ES", "a45008b23fb4f83c058dcd7642db6ad9af1cfe9215556dd53b555d91a0dfda27da76c201ee5cb5bca8a8be410cc85637daa5d80a86b45819110188c23860f860" },
                { "es-MX", "aa1327e8c8da5cda1351b596e7e8a2efe7a2ece194f020cbd215783974e08a823f9d66fa1e3d1878655a76deaba8ed5a07522cd2ae8644fd44380940abc50acf" },
                { "et", "f7a67d23c76414ef1b77d51854207edbe3dcd9d199ad4811f19ec5f1247610a3564a1cffeb70761768b4660d2c17df0a668e48f4ff6132383ff6dfb4ffa44923" },
                { "eu", "851b3e4731636e284d87fd39fef8dfe0c5464871a2ef5363abf40c67bf16b569f8485b44561fa7d91417e6d1ced58a9ebd42edd9892cc595b15e525a43b5a245" },
                { "fa", "12ae133462ebcdf5d3de6437f7f353b508e05049e8dd6e373e757cf6e33c3004ef933cf8b74f6cd4b9b9a0bac3452ad82dd21fdfdaf7c83c610fa3dcb19a59f3" },
                { "ff", "f96c5999c318a0055faa6cee4f9bb75afcfb77fbac8d92e9b6648ca10abee66b227c1d7196a83e538c5f45769de1cbe7e7d5b0db3c7088906bf98f98d7b77b37" },
                { "fi", "c829780c0990b4c7323243d877410d24033c395ead322aef739d298839b875556f161fe0bda270834f646508ecedc6d1c748d1768f6ca3610ab69932257a6f1f" },
                { "fr", "338f67de1b543b05ef79a99949f77acdef163ea8625441ececf04c01063fdbcbf0088546e244d626d1402cd6f2749a83b49a97c673b71408da156495a26d7efa" },
                { "fur", "ac3a768602a851cf12df0d86261df8020432036f14e23f12b18b85752a6cbe381d0a301d7f9a77fe49beef8cd33154674b5f3fa75af86ac276c557e8adf9b848" },
                { "fy-NL", "c011e5f4645336b6ea43365eb032944179b83aeb809a723e6f6e1e0b5c26216b9133e258304c308f3a87ab7c29265970b564ba6a65ec315ee7a19c9fdacc69d9" },
                { "ga-IE", "05c3dc9beb90ca7d3f8ef403933d4fa7f48415982cf75c92f7d9e46b15b9fa483c94330b4e4fb652dc9dbad49e45f7a74948b8038fe32da9faefa187fab5ef98" },
                { "gd", "fbda3555a604d9ecab5a5247b28f170633bf6223907be54e999dd619eaf5bf7a53791e34c1058dd9f52fba1f713917e58a6ea1bef5068632f1bc8fa90f6dfbad" },
                { "gl", "356b8a1a5e5a70ea0dd95265febec4ffa2db86ba0763548f537377195020cb4ddbd8823148c21c5742846ca51b0859a834943a7f660cf55af129e1698f7013a0" },
                { "gn", "c849939d8298c100f62776cae10cde04db63f0bd1ab8202d6946d44cb250da9c6c6a00e9e2976cc61418afe04d6e50f4c1b356057c6e9dccb876406cafd75b24" },
                { "gu-IN", "b7dab509a1ce29f1412b01c3f71d65b20cc62e4db7b2a2eb261d7c896d606ac709cb1ef61be1b4749e490f41fe253a33fcce5c558164eef8af432d2aab2f7d2e" },
                { "he", "2f93374651c49a0c4042cc6dd74ba545a0882089d56d864901191b251aae0c2aefc1a3f0dee19d6c748d32a378cff6541c2c20e78aeeac3758b98bdec7db16c3" },
                { "hi-IN", "fe12251d83bd67a014963cbd06fe551c8f2526c0b244a00d93523b9931fa3056cdd85a1054df542d74724711a939696d66b3be58f62e5488840044960be9f8e1" },
                { "hr", "1cd66b3fa3be0b22de2f20afaae424e90fa0fdbd8f5654e972773f5fc360641ad7105d295d213d30c1187ada348c61b13d204222f67be5df114969b2c1c9bd6d" },
                { "hsb", "f3a5a397532bb7c14a37697205fac4eecb12ee2e3574d40e3e389fbd382b605b8570e0ccbbf1e5630d845919da2228e6adc31dcd1fa64d44dc3041a120671726" },
                { "hu", "53bf9aeea1c43d22d7c887bf8f3f38034869b742b30f6eb7876937fbffe844399b74280629eb3d6ee229f7ce79f3ee25b95b1046e9d8eae97cb5c5971241a958" },
                { "hy-AM", "1c976d37b62727133fcbc050372d5b2e81e9bc752c1dc11783e6f6db15258ce8bdac198488415ade7a5d8a406767074e0df0a72d3ac0096bc5f26e18ef97647d" },
                { "ia", "02d6ce515a56edd74b5e0e71ae2b781707692271f805c4b6878ccf184a25e49b51e2013e859aae265d63f6e464974bb4b9490883f1f9a10368809cc0d8c60192" },
                { "id", "28167dd1b47f836b738ac33ed9c8e8e89cd6869ccdc677f5807b3fb7073bd8f92b6800f19ef563745cc36ebc5a994119c523b03f3232cbbe4235f3cbf0926a56" },
                { "is", "c479971e82b28c9e9fa1d4183e27e82b845a439549ec5157ef609402440af10bdaea12041f96cb1f5b88661d0a2648c0ee1ccd84241c6d086b74c1af5280ee90" },
                { "it", "7fc49b73adb269c9a85a7c61f112d167b9f1aa9085b73be66809341c2861a2b3845e8b401aff1d6d2cd6c9b894edb7fc32dd5764c4c1cbe6b40e97c57de63e04" },
                { "ja", "761d625cd04c7066ce48273b9b24277ec725e6db8e8082d38abb95d7ba7743471bfd826870046bec4f81a1f5513706a8e7514fa8ff2c9ee7b82e1966fa342c92" },
                { "ka", "5ed878f71325bb980caa03556b73aed09a6a865946f1e18496ec3e92559a73097eddbe7ab1c99a0d5f917759460f160d830e8980013fde87cf03ac2db95ba341" },
                { "kab", "f3caa2899a1a8804008e504195cddd4e16a0bf37119c91541aff8d8f1f9c040c4e65215a7fed51e08365dd886502fd0d21dde5d45c705e67f3bf1d84ba75a054" },
                { "kk", "2af3c76c8cc779a28511ad3094da5f8912dc320d10f9c38c73638b5a6db5e26c3bff9941e6ea9ea1ecf12206e5bd4110075bbb228bfb16e9b98a0ef3d3b99389" },
                { "km", "81ddca54ebfaeb3538ce2139d6ba567423e4ac022f203ded9b2d51164248ca7ae08df32846e13950ca3b641bd37ea41ef7063e765e22609fe49bcf16bed5a7da" },
                { "kn", "3a495d2b3cd99debc9d5ae9bb51b13bfff9e83df0359fc5efe954818e70e5a25c4b78b8de6994a0d0d77e5ba7094ca35e8719c2b992c4c54fe29f587d1cf3702" },
                { "ko", "922da80fd40f6aef1000311bffa8b8f26fff31d068d3d7d4a290b3e4f674cf82bbdccf54daa32a02cb808daacc1cc7ce2f11b1730ab18e14e3f5c76977de6829" },
                { "lij", "aa0b6595f65ead7d392ac4286c362fd63f15a71f260d11e28ac02ce944e7623679d40509b54ab937bc91a9bf1a2062f2921bd4afe4d8886fcdc7c6c7b996cd40" },
                { "lt", "8b964334623aea5716d41e1b862067f40dc3d8e6c6a8752ac6004a7ca57cf1e11dda13336f27bec3785d0b3d0d3ba105359324af71b0f52d0a36184a47081c8e" },
                { "lv", "34df1c929b5c5830f7eb99d680a3a24da47da295d8853aaace5dea5d9b761c4bd940f8bca0f39f18f05a4467a8eeb826eeb52fadc33be9b7b2fffeb9ee8e5d34" },
                { "mk", "8535db4ed89c7fac4d3366cfa25e1d741e1ed25321707e9068ffb9d14801b48f0f82724aa102c9295d1768778a795613b4ef88810c4f1a9c4bb8e33a5f81b1de" },
                { "mr", "05544ee627ff845442ee22841b5b2baee37efe08b5dd989bd38c1e55d8a3137cc699e6347f8d8c6df52807c5501d937c8406ef18bd327cc49dae17c4b5e3700d" },
                { "ms", "007705616a8b4ae8e64663b6986c97a3ad4c583529f370b2a332a6ed5c1a5cfa4e340e89db11151e16002577d6d3731868ce4f738383b7ed9bb613bc1dc115d3" },
                { "my", "954ef03cbb02e32601496de4acc74b81079c0239a5705ef8c4aa27dc469c864adc75f9289c3f39be0c7e52ec849a52396cea81b1c0fa88d1bb4b7c9f5db523fb" },
                { "nb-NO", "a49ce6e861494ddb4e8657957937ff2d4f61ea821f34944d86a2d0d3c5a5842474b83ef317bdb2607cd045564c3e382c8c3676cf535c29cdabdd35091ad8fdab" },
                { "ne-NP", "d5290eebd36121452fbd0672f45c6c6de85eace42f118498ba4748795485e2f235d9dde52f99c897aa27207985a45ff3ae2905291bca285cbb46def3ab4c957d" },
                { "nl", "974d17ca6fd332e4ff2c05001e801da1ae6e90b091b2e68fff2b1444b4a21ab61db8e3cc07ba4c9ef40cce82d9eaa0351808f0acdf6a7d1f5477aa029b6df8cb" },
                { "nn-NO", "540bb018be75edd25001ee9f15ed18d8c5e1424622c84e60348859c6856d15ca8ecc71d15f01d160a97895d442b40760069998de0112284e4f5b55f4133db232" },
                { "oc", "26d474200c884a58a1532a9e38cb670f81853a65a23f0a878f727b0dd5bd00b26abb2aa25e1f760b9dfc279f1a1d849ea25917d96aad17cd702f7452fe029bfb" },
                { "pa-IN", "825c899cd8a8ed6b940d27a881aae258bad890bb758f6603a8b975bd4f8341a22a9d1f1c6bcbe7862ffdea822c9e0b84992c8cdcef9dc6153a2e5b7b16889453" },
                { "pl", "5d5ac9bec9e84b99f1048255d59edcdb22bfe4c50bde7a72cfbad4e162a66a92f8506398f0da5e02838842f72cf737daedc54abeb22657738e3fadbd36866eb1" },
                { "pt-BR", "0345590e533cd5f19caa497096a9be7c740b77455c17c856ef434ba4f9d8cfaa56a4207effe87c7e3b01473008a17daf4b0c9520e014a8ef318f21e438392070" },
                { "pt-PT", "c891db23cd1c996dff92870a1dd10bb410c6851d26039cd82776ee74643ebb761f9d1cfe423f371719320fca82976abc8577ff42b752fd1dec0d3b316b41b253" },
                { "rm", "806d6d1f2620e3341e863e8e397406f186eed398b2b620d09ddf66edea4f6966c889f774d34f4445fcab107069ef068097623fe84a5fc8b9ea92855e9942dc3a" },
                { "ro", "a2ad92df3c5dbb99161854ff1d26ac5735580c7028588aeae130a3dd2b2f25f6f3864550544ff3aaa1cc9d2845d7a1b8d68090ac9dde5cb95e55569c2adba16a" },
                { "ru", "81fc0cda14c1703e4d825c304c516d1865994a7ec09f94f5343524ec3feeea824901861ed89eb5ca7006a92e549a1a14ee6bc131b67546cbe0c0684f763e53c8" },
                { "sat", "0c33f39e8c54b9c7aba3128c9c9e5c6be201dbc99c82341104ad873c68beb29c46351d9e8e39661a073aab6895c8ff22fefcd3e83d1e595b500730964a05c9a0" },
                { "sc", "ced5b99b26f67730afbc3b388e9c2e5ee53efd8d836bfa231d7e7de404b85feafd0856c196c396b9753a37f079912ce1d2e6107a4d9063eb1c2022bf9d009679" },
                { "sco", "1204c51632fd567672cf600e51ba8d0641492f2610f1581e74d67bd5143bc22ca1ae74261fa0623cb864ba6f887b801442c092cadc681a9968e1cd1bf4ecff62" },
                { "si", "1e7c0395effcfe2dcabd15e8e42482ebe72e89fa8125e0d24b7ed08e9dc9c9b0bc7b43917808f2f977e999d43e0769acebf8ad5a896aa34cddb188f92eb6a725" },
                { "sk", "cd64237ab73b30e12d1abe4f7f522ac669003c1a05157d3e7abacbbc188deaaae6ec89ddd9257519700c494c26df74fa5ff8ab385d26fd634347004551ac028e" },
                { "skr", "c97fed820df279c9b4f0637313f6e3644d2c330dc75c0d4598e534ccac2e9a03bfc16d26b613333e1fcc4a359a4c6e64b371a6931efdf5c859017ef7e68ae4cd" },
                { "sl", "8801f479584b780e5eddd4097acd6e9e4f925b8cef3b47a88bb233d073e91ca8aa4b304148ee41573e84549d23447983567e1db56f203d82df39486cd4076f53" },
                { "son", "c4f3d932fa823d303f88c642966893bb2011d7b00b95634fda34e60d2f483cb9325dfc25b196849817b2c53448ff9aa0b62e71e9506f0b5fe29f9a99725b8e04" },
                { "sq", "009a1314c7cc51ebe91aea0e1e7522d9481fbc766eb7dba47f3181c7c225df78151c8d64b93a91634ae75281589132afadc9e7502ff35daa8ededbf96b3ad7d5" },
                { "sr", "728a29776b407895d553fb3f503a58bbbf4254328b52fdd0f502affcf416d6b4ee89e4e7965b8a6d56d161262676bda2e34f81071a586fa51fc1d7086320a307" },
                { "sv-SE", "eabe374ea019c94cd2f8d747e1576f2a8d1d8d7b66908ffa8a82446f14cf87c86c9338af5ad7962babfb85234d83c0b2e0d2d02651b3752506fd3327f53c3534" },
                { "szl", "23aeffe2a05217800d058f63afb73b8c6bf4929c561d6c2793c21e3934814d30a448cb76749170efd45eef576da19ba160e28f7898f787c6f12bdb602b288593" },
                { "ta", "35a2ca62afce3e27f5f2c58c7483b51f782c74f1ec037e85b1b3f3ba6346f3de78f1edc17cce02e9589cce737742c0c646e73a2b7555b70d8d121a691431232e" },
                { "te", "1c961982177ce73cb9d3ba2032c92ba8048c4a783941003e4c0bb1436d441bfebcf988b215e7ee55526ca2d1203fbd6a0736ef405abf229b756db0efcd48aab5" },
                { "tg", "525d5e698a760950b3a3ed03221df786e018f5d66bf4ddac14855923c26e697c8ada6f4f37d3534dd7bb54d946ad9fc14076b0fb7dc84b564c255bfdda6084a2" },
                { "th", "40f43f18bdfb19a206a97fa77382a992fb263685031afbea01188814ef6e48a3ac17d6112897f8113e7ae734f05d63b0dfd7e4c924471b92afbfcba038bce959" },
                { "tl", "1a99e6dcb905f66b2b2a94e5851092691118b148284864471c8246be539d5afa461d03101bb64a4176253b6af8bf7237ecc09361baede0683d49ac45a3c8f0df" },
                { "tr", "3d56e790932f5c5f6d2190ea6aae77f9df58e5a23668924679fd886c33a04dc43cfaae6915e44c573abec32ec0c69df1b3187f646c65fb3386b6e178a5bc893b" },
                { "trs", "0116118329c02e271ccbfd1e11d3a70be22cda63771d70cde70c7ea268cafe15eee497e088b55a5948dae6346a07a3540e55af8185a6f9fcab627761ac60d8a5" },
                { "uk", "0e257e47e049d9bcd630aa65661945c10086befb9293a52956272fa8bfef2f58d8737142d9ce7449fdcdb0cf79d8b968f5a2235359aa9af2f50090448b13505a" },
                { "ur", "0663ae1e260c90e1e693c355608d09ed318afb7703bda8adcf2580addf43cc1211010104b28561c3d48d181c87c5132a0d9ee11f5062a2c464323bb69cf4e924" },
                { "uz", "4a00e37d6ae7e16c522e7d8dcfab7f2aef6a4c8fdb7e20b2437b3a38625df086940e32da4025e539d0bd54e82281e42ef365b571d1b3333c20cc93dcef792772" },
                { "vi", "5d9a6675e3fad2c792b478fb043f91d91ee0a5d0e5129fdedad5b82ca362d52d834252eba7224f2afb6b7d7cdcde150ce3d32c348e381f5a3d7f83feed229a87" },
                { "xh", "055b33942246f1b95c80a3572cae32c04cc521484504614c249282df5d4a0cf1206d4726e0e45813fda14215abf2dd692be25e46de34b49ee211c2d8cd03c0fb" },
                { "zh-CN", "4d5059e660285ebd59e9be79be4ac8c3f10d6a82d298ccce860ac034e9c26bfc2d90dc3e4e91c3cb4afc324604ab857d08433a62eda0c830d256b6ba3fb6bf14" },
                { "zh-TW", "13019275369fee30b7dd7282c2f48a7252fcb795fe0f7e324453c3321fffaead231fefbb7c3421e78296af2e88c0651e3d16d9be92ef9a2206bbce714f016f45" }
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
