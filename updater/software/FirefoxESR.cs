/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020  Dirk Stolle

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
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "E=\"release+certificates@mozilla.com\", CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


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
            // https://ftp.mozilla.org/pub/firefox/releases/78.4.1esr/SHA512SUMS
            return new Dictionary<string, string>(95)
            {
                { "ach", "2e7d08cd0fb4549b868ba03f900e097140114dd38c4f69da096e364331f9104e711cb20ab3a85427fea62582e841c8403bdcfa79c12d8b0b9809a43315440ae7" },
                { "af", "65a20a1250baae097f57d0d1ef8045fd89ae7de5ab68753505f1942a7e44fd559599d1a7424f6e64da074e1e964ca96af13245a9466cbcc9cd8f7c381ea70125" },
                { "an", "dfbf4e2141215a94cdcc029e28e2c5fc3080809e3daf1353ed1c8b458942974659469741edbf6f65e736a4ccc84dd43aa2b24d270700307fa72872f0497c28f3" },
                { "ar", "025d630d6efb8375895b815359ceb4195fe765f0ed0f933826b511a273ef72e82a4fbebea873633750aa657db99becee31a13b0735fcf8310d98192d4785bf43" },
                { "ast", "2d5b54abcdfc9c18bf266c9f30938edb5b0286440fe2598f5fd0f41f3f4c27ee9efaf1c3742e90dccb6060569654ae5e541e2a37406594173e983f89d1e99a77" },
                { "az", "1c5ee0ba4c766521c22abb06fd30979dfdc2f247f7abb5e43bb9c42a8e352466fc0812cf8d174fb51c609ed80d0122ce49e87ca917d32633a48bf126c880c047" },
                { "be", "bff8c5e0c5d92e492b10e24acc96a4896d02aaa971a100db2d2c013e397dcf47dca76fb9bad247a9824d6811c4ecac81e86e4c093da91a955d93a0afc6fd30a7" },
                { "bg", "b132475fef962ad0c91637e3ef6b4139926d2cdae0b7e6bf3f014364499f6406e1797e806897758a3ca6dc4c68744db760cc019a39cbd23753fe5276b9d2fffb" },
                { "bn", "c3f263d2afb8bbb3981cee2ee04c20f4ceeaaf97dff87077fb9455625c181c8417e3c04ddf521b3f65a68d86539656265de00b63d9e61e68286cd9f75c9257a8" },
                { "br", "0dd930d4f11858390c87fb18b031031775655928059e5a50c3839a40a98cc717083ae535e39f079a0fee374b3a2ed591a1aac4dbe85e1ce8b0ca443da4588abc" },
                { "bs", "4cff5939c7ea5b6e75014698739e1266fe387b863475fe9d29869c7bb3f543ebf18187cdcef473fd01df8458965381ccedf9c20157150b2751a1ad46849feb24" },
                { "ca", "1af5236267ec81bec193a93d55c0399e0753542e23f39ee113106083c2c232eb3275b5be1fd6e7872bce133e7fdec45f59d1f4bd39b7e1f4af414322aa308062" },
                { "cak", "5cec196cb148e133f1d60f8f712ddf5dfd58c53c9aee6bac9a21e871d9315ec01638eb7fd84d24f21d2b0cde1f9fa73f266fa1322430302326666be9090bee47" },
                { "cs", "9dc85cfd2c525c5dedbb5af363ac9ed7696ddb9c861b0b14bf398679c22ac4d39a798dcac0a46be5b3da28fa362b2bd272376a939db9739364929e7eaf30ceab" },
                { "cy", "0cc526288978346e8792943d3a7e83538c10a3cc4a46e725f2ae8a29e4a7ddfad8fceadf5ce77bd1bb139f82ce52e60f3b215b68492928f954001d8b6af54294" },
                { "da", "3580bfebd45039ec772d8f9d6c2da16e507f74f3d067d765a58316e76980071c4265bae2885103e566b3c00df475f0390c29024e09f393e0ad3baa37788cac7b" },
                { "de", "4cf4b82f676bbcf562f5127ad0b1a3ae432b378cbb8f649d23c0697c50bdc4eb10e16b5b82cbb10ac285becd0ee3de1b159c6b9c2abd7d241a8f00ab3d1457c8" },
                { "dsb", "68b96915ef37f3eb3e3373de13c0fe158f59d0a5e6466b585c1376c1b0843eb929484715e4f9a9fabe573941b4e23cd2a47d929ab9c8ad7c239d306a668bfab6" },
                { "el", "538fe4eaedc298daeaba223547acebfa24c61a8283ebbf4c43ab9120869cc5746da3f05a57a900e38568d2f3ef255ccac9030bb27a9ab6a2ee79c51cc18e58f1" },
                { "en-CA", "d64f2859d73d5ebf7a6925ec6954c347195e26b64dac94463e30cc72bad3b04a545ff69df631e52c6b499ef9686d41cfed664410948460a8bda3ccb581d5f3e1" },
                { "en-GB", "d4a4074aabeb69a672ab7bd0f434b4dea030a2db37117b1bea7ab507767c43311efe99ecde711f0be41ae5dfa6e64aec3081053388bc15f68b8942d3ca0456e9" },
                { "en-US", "dfea5fa9d000ac58c8060c2812f343d2a21f0c579c0f6c35af495a4138224ffca9a71fd32751bde2f7c807b827af0bcfb75fae24b8ce1de2f908b3eee5e4a11f" },
                { "eo", "4b47a9b6975e4f240f788d9c7cdbb484d85e60da4b4a877c0c185ed3328c92871505dff9611999e622d86518e79dbee671bdb12fc5fae2222d45bf332f901fbc" },
                { "es-AR", "d8ae7c51353c0574d92ed53f0e5b1be70470d45a8d78e6a7d64bdc5e7170a1028fc7cbfb813a843c8986733d0cc80ada9532a2547477fe5900631b30cb479411" },
                { "es-CL", "11a45e318335c74b15e67c8824e1d7584f31cc350ceb477766ef92ec2a16030f906937a3e2004cd44a6fe6fa9b8b7cafcc8fe782e5629b15f1ef8d0ccee35ce7" },
                { "es-ES", "4e61dfbab10bb2e2e10e95b4dca914f88fbc18cec2eabd19c5dc6da7e51c75c875e497e1278e939d6367db608ed970475ea8bb9d3353cefe9debfec54bece767" },
                { "es-MX", "40ef9ec7404869ad94c865d58a5327e3cb3dbd00aca96600914db0f9828c289dd1dabc02ef542f72587c8e3a7a21b62d249d2a46e51d665f491e1d04c533fba9" },
                { "et", "9d7f34da40a04168b9847bb2b781554dff8c30d2a20d57d4bfdba404283ef58148690550a81e01ba5e3d76f783ee985b5e081a4d3bbf1f88665daeb8f51b69cc" },
                { "eu", "7da92daaef40f8aa65043bb695b35e4f950d035c1cb19f17ba43d4f201556b43fa416140b322da31e1a34df77599426f693943426a019b6b94cdf1fa06042401" },
                { "fa", "d1af256c5d7419e0097422b25e2cc085e6a3801eaa17af0a7db6be7063ce2b166b65b1bd730d2f645a222c83dabbab74a2f7ad3395afc86fed3223b0b6db8285" },
                { "ff", "1a1ff5f2bb4c2013ac74ffdd9d8f524feccb3dbbd8c77fc724fe9560da430f3c9162e3b129743086c00d37fcee2ec917f820bfdb91391768f84f1702b20b9e54" },
                { "fi", "b5aee90c556cebd1aced1662b009208e1141133676e3f5d39c01ffc9d5daa4d2bcbb8b4ffdd99c507a5eae23fc0a48e0afcd138b5265585dce7685275b95e566" },
                { "fr", "7ef9b8aaeb37a094e9419fd5e15c42e844769299a9add1ddd945f0747c57651155c6677e1d953a34ee96c6a6dedd9906de17955aec1130158d2a6ed02e6fe622" },
                { "fy-NL", "f5015a04146b5f602030a0b9a3d9d7007cde8c3dfeb5cdc42e59c1a27c41baccd0a473d3cca3d238df7b05361b9fbff63843d03e1f636164d06c0aa59bdf9b10" },
                { "ga-IE", "24e1b9ded14b014f65aaf609d8798269f2ca72174d5c0a8443dc026542125c517e89efa84c89781a8acfdee7a5e7792316d1bb4af4aa3cafd85146efb6af5d8c" },
                { "gd", "c87a5ee5248c390d6d18da7972246aa90ac48a74dbad40c6f2a748122157aade3c60b0dbfe9028928fbdc10344a0c0fdc59319321477d200c6517fe3f3831e97" },
                { "gl", "be94ede8a83656a1bd52ccc49d914ccd26496e944e0a9585593d0260d2ea38e190afc12d5284b966a548e0c12e16cb3830b33fc0c065ac76898f50c3c45b8340" },
                { "gn", "b6f9853f15fdcd0304b18676e39541f2cd7e67527cd5a86331b66dd243f9bcba3fa795ccfa16ef49fe58fdbfd0edc4d880ba4ccfdd6ecb0c6c14015da7fb406f" },
                { "gu-IN", "6b9dacec4f5ec5ce1f019b2e8f203531630cc4ded393a1aa0ea916fa1910d1abeac6beff31d0124239f0b202f1ae3da68e18820cf6ea58432e6d3c0c039b6d1f" },
                { "he", "124c617765168303e1e6cce0469bc04fef55c5ca3515be4b3ab7595ed4397e6a4f38455afa477723471e6274cf11ebafd672153e7de85540b974dd63407a2e15" },
                { "hi-IN", "ec7d80adc35074bec135239ce2ad6ba9dd73c4378fea4c0114f2657854f9dd3a08cc0c32cc3d1c5e8416b571a80f61c3efe9003d1befca88ca8b54649c286892" },
                { "hr", "f5046ad52bf28b01e2714a13067798ebd061dc83772af34d8ccd31de6a8b7cc30474af4b4181787fd37bd5fdb803369f5a0a3e27bb150a423f14675357de5c42" },
                { "hsb", "f0d27acf65981b8f39aa93140c6d68e6bf4d8fba82862c5962854fc717a2c0c67f49f891dea8e19df20911d9c6b5a399cba8e738a245802ae99ff80224d91682" },
                { "hu", "73cd4f258710686f672f44554f3f45596b3ee3eeef2eb75dae8f7ed8d44b79f0eb649692416e517085a6d22a0b7c2e2604a2774ccb397d9415aef1bda50e16b7" },
                { "hy-AM", "63d4801f24a91bc237ad2831a3c18879c081f8ea52a2ab2235ecdac9fad0dcec7a9f01576c60b77045a3fdab5081b24b4918d98fcc225c9eba0be258d8c73444" },
                { "ia", "e776e49096b0f4f525a472954b8cb069600445de9c7bfd1ac41fb90745f7458d3ea916bb384d2b5a813d278a58b559992fa9cc1746952151eb9b4ef4ced10bad" },
                { "id", "344b4c4eb9da59672b6ba0b23c0ecae042fd298b48f5a742ef4769310652fa6407f41fac4f6449124f3dddc4984401391ec469b0bcbc5f54b4e414fb0d3f7697" },
                { "is", "4b911a0ca154b42895f10ca77b0424134ee7ab4c5f3c6a5b86ddd4c16bf6e91b5b3336b8239f08c98318de3871e2e66e7678fc5c4e4ce4c754246735bb839a21" },
                { "it", "afd3107d98aa6d3aadde4cafdc6ddfe1876a6dee22209e91f36940455bc6572faa426ca9689e5c24aa0afb3dfe21b05d799ac2b83f3aa1a62e752be06759e3bf" },
                { "ja", "e4f5009dfc85f83bea953fb1a08a547ad116e7a840e9d496058afbc226c7d5a9f6319f029f1c557512ccff5d69ea39183534315d3ad260616f770751b7faa388" },
                { "ka", "fd3b83f3d17a274f18cef54a0b62207702da0ae537387a330d3c435d4cd088d8b2815a62723f2bbe1742b59b69fc23b0067384cd9cfe142d6921065bdca64b7d" },
                { "kab", "cf4aa9705a221f612115be75c96bed53e9811b555d42d6ea9b9a52a66f04d9d612358f7c429e0f87a88c565d097785c53dbdc3163ba1691671f96fd4d45658b4" },
                { "kk", "f290df50922dba0b85580432ac50753d9d0564f3d5731f8d6ebb87b6cb39ba39f5508291865e11e71d7fe043cb4dda923ddad329dd6a9b11fa0f8932eb0e5d8d" },
                { "km", "b9b5ad014d784ba7a6ef10d96c6d4d315dbe5a574f0743a1e983f339416ef016dbdedc665570a645de5e86176f6d0bacadf1a1ebb3e82c06cc1341cbe71f573b" },
                { "kn", "23a086f5e671cf3b5a50af837e6b1d063fac578bd444154460db782666ada9539326dae9b957147a2bad2287ecae1e35c0fd1aa97268dd98e0767daea53d6227" },
                { "ko", "32a2a4af00cdbf0a0d34ecf2d2e31771a8e947eed95e88877e4df7a587e6ad9fa9b16fbf4cbba96117ed10ceba6785fcf8c5b21f3cac27d5a25626197e7ffb2a" },
                { "lij", "93a9c70414745eb1a03a0370808259db8797ba27442a8da14151e873a879d407ac19bf36e50f29a870502ca05bd6cacb83938fb73d62bdab3cc618fc84604003" },
                { "lt", "552e564a9d9e3d533a0a256bc2df35841b7805d72752a8a7f799f9e8956e2ae7a3acbe4c29650b0aa433e80d25b4446a64e23e310654fafdd9af01a2e2c228e5" },
                { "lv", "a9a11ae6cc78faf32e78f62e2eae2ac45f2b5f5e2b3f94c60e33aa29246324c454307a5dd6e77fb43362e50f8d84f91b9feaf2d8ef14a05731f66e7238cc0c02" },
                { "mk", "f5fa1cd38986ee98a1534752c66f7d599e05da7c7bb0ae677e7400b6f37311334e0e8e7f66d58281fdd094f51d65323293677ed7eefd3e0df09143aaad732c3e" },
                { "mr", "ff71f06d4976799d9e81cbe6e9037a2096c87226919a98839151fdbfded41c2366a972f4b7b347e95c3151b7456c7e11adbaa66c7e8bc09fd1912910219a9ee7" },
                { "ms", "fb5df613dc56a120ae1b1aeb2ec6ee36543fc995b420751f541e15777e89d067058c5eafc09f2bcdc9b63cdd575e96cf96756f37e7d0a911d20356a16bdc6fb1" },
                { "my", "f8f3d21a367941fd7e32b2ddf56d5c5b1342d2d3ec85c3217c25994f1c9208a4a6112241a6fdb35da7bf3a1c9b5b5eb3e165f271f979f6a850c29cef9b0baffb" },
                { "nb-NO", "9b556e47d133d7353055111711adc7fc189e332739136d568b56ec2a1ffe2aa8882a876184d0afaf0473015404b34913dd603212bfc6142dd13f6ac700816d54" },
                { "ne-NP", "f7e24a67ee76de1f3981763cb7575971e4cd9351e1f05ff65877a0ae3fa08d3f297656c01d7205ef0494c3817ba3350a0e321a71c04bd2229ca9c843fac784e0" },
                { "nl", "3e34ec9913ad7257799effac5984129e1cf372ddd94d1aeea6b231345d4a5deb8d8ad38cce13a7945ef584a7929d9bc2fabd6f829b2bff416fecf7efd4ae2582" },
                { "nn-NO", "62c4aa6e3535baa768bf540729cc652cd19e9fa541e8f32c0da5f6bfd19b8d422616b69e1830e49f5df788bc139ae0f69095571c99ba1f8f76a2806f51e0b593" },
                { "oc", "78678de56b5be8b79173eba5bf1f6f464ae0c3fc251e97b8a4461086e59f20f6681af8e594e2bb92d5b4d4cf35ea243ddd40d580eed133abe540a823ec4fa3f0" },
                { "pa-IN", "def00d08fdbc5cee72f0b7710783dd666aeed008ee362b2ad5532e65c7afa70ef0b781522bf01f001749ee065bf8760713112a869c8ba8e9d0c0c916062c6981" },
                { "pl", "11aca4441f2b477258de3f13e53eacc5766f555adb43cb22170378218c41bf54b43354257ba99e32c085012880d90f8ebe6f8c266caf27d0ec772160bc1f6e26" },
                { "pt-BR", "5ae52e205a1bce087b2529a91248ad404089decb34b4a6307ae550dad04333b90dd8eb22792cf899211758f4bd3640c39bc4195c3238fb90c4faa0e6daea1714" },
                { "pt-PT", "520975e7208ed2b315e4cbef5ecc92027b434811d819e4378180505fdb51108033b1c758429c417324b891c7c2dece943c025d873f79fa5aa9bc88eefc32e53c" },
                { "rm", "c3a243f7f06ecf58d0c490942ea0485eef2be41999814c702ec975898b0b921c3bffde94b73c86ecaf137f7215e5b0e9fe28ab6161a1638a780f715c1febd262" },
                { "ro", "4b5fa22649e6db8ce349fc59a34896e97a3a0d3e12ad9129a0b40f3721d5840e7d2ab0257d4953461260fdcc5b73a6a13e1732e2aeba7fe7700112363f720d79" },
                { "ru", "1e931992cab6a64f9284916fac8516965f53b4852de10e3d1e6a5d4a073d151adb804d8ae887e34861757275a35e62c7aa7be8eb6107e6347cf73d43b0d0592c" },
                { "si", "240aa9e2d44c5aa63acfe258a207211ac996daa85fde91166c9cec9d00395e09871b92781962f7ea12356da586a5a0ae8ef1d64d3e7a971879c83e38735752f5" },
                { "sk", "34df2c132fb8229b73a319fe0cfddb64601ea424f9b90c6ddea908c8d28889c6a33b9389a0868658b6fa24a18a6d91ef50a40c99611b0b95a7b6de8e5fb0dfee" },
                { "sl", "85d7cf0711593a3fe097c51ae34aa9ad1169e2ff87988d3bc3a746b81b8a76800629e72dfa1f37942ebbf7299233da71ba55f47fd5adbb809a567079858fc99a" },
                { "son", "5ff4fa58a3dd119280f9e4ecbd17ff59f8c23c0cda07a8a01ccd8f4bf32a78dae01a6dfdc730c7abb3665dbb3e64bbd8b6b0599523bb1dce6b7b7174cc89fb57" },
                { "sq", "43cd44d00c91359ef8b3696e45b78f3024e33622314a09cf6db3dbe7e1e8f9151e5b6c38dc6f78188f326d89052bbe682a1244b0e6b8ff42177b18bf64e682e4" },
                { "sr", "42290d0b4f7a47cfd560ecbf6f7c32cff86210ad69c8c9148dcc2a414c2ead722b6bfc88c8cdfcf1e9983f2cd9712a203b1c9b56664c7d5940a018b80177f3c6" },
                { "sv-SE", "b04021da2ced9249f26b0c49ae0cbf5f5549ff2c3acee2a96328ee8004e770456cbc8d184b4744eef19069257462169f9a793d440ee76e145189f706e78386de" },
                { "ta", "0d863f782cff539d4a6d71d1db732c90dd8862c894aca347ce087c314a8fcd56b8a6867b0d5d2f9403aaeed634bfb0f16c4b57066919917f983f6630b54f54fd" },
                { "te", "5af4f7ecec9d858fd6abdced5592875f52e139099044366662dbe848b5e5791dcc49c20c0ee5da1c7534ffd7384bba7e8aac98d598ba34d9e6d91f03e8b0c19f" },
                { "th", "17f34af4cff262fdf33656846a484c1f843b41d2966cc9b79006307e3b351354e3bd228e885913fb12da3bf1217699799d62bd9de889c6e766d2e11245ad8b1e" },
                { "tl", "cc1cf7a78cce2cb52f15dadd85f93414bdabfda246228b0afd8c35253f65ff9c8dace9e35ba33b753ae1e698e337be8a3e3d72482bf00b13c3f6e6e5393d5b7c" },
                { "tr", "40a89db9afbf970742f3eec3304f55be98c7f3032f9c1ebc65176e031d3f3b047f8407088d47f998fbf3f58873d0d0cea2f92e7d0e4db03bb1644320202bf5a5" },
                { "trs", "9d44537f62521f74d359cb67cd124ae76d7ceefda537259b0f7fc73e00ae9ad796d0f62c0c26b2d7d2b06ed764cb076e85f5eea5efdddc284801ad6c56d8db8b" },
                { "uk", "dc233de0f67b43654af39e1b83e1e7332b5f3214d722c22177b34d246bc9a688c63e9fa91273f5b0c7810cd0b9598261d8901e30808d88c29a62c99b0f43cef5" },
                { "ur", "e532cd80de17a58c527327732bed3dfeb4e7e54c1c51a4f4cd1fde1d83bf11d9cd0c25cb23d8de35482991519c7626a2942ef61b7f94d68fa982d1a34b684d59" },
                { "uz", "3ab4a58b1ceebe64f88ebccda4894cc1822d1d070940202f6dfd9fab612cca93116b1d9a7e13a1c8456fb342d5c9a1339a1d6568a6d3e81be6277b17ecfd245e" },
                { "vi", "6bb6662ba7b1373c5b6905bb07da9cb99e02eee62d7962e160cffa30456d914136df82c9f7ea3213b114e998212034d87c220354a464f3c46d7b58c1538f7a81" },
                { "xh", "12a86440eb26cbcaa597203d0a904734caf4ef48af95ae3ebbeb5e8b90d8b19d9fc7bbca9d18c4187d032b338b571c0390fb3fa89ed56dca028e2079ef314376" },
                { "zh-CN", "f754ba276aeda1c6aac4a10fcd905fb7e22ead615109fc2791db7241bfa1311fa89a179428534e421ce7338d56c1a8a6cd8d9b05d8d203f72bac07b8e5b5d0c9" },
                { "zh-TW", "a2b13ff5da0f7dcbaa2c723f0997871de5400fd8712d3afcd31fe9b068932df4a0429e91d71670ae4871d8dbb1b2063d60e0547f20b34a3b8c2bd44048792558" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/78.4.1esr/SHA512SUMS
            return new Dictionary<string, string>(95)
            {
                { "ach", "f00f646024e239be7a21f4649e68eb147ccbd825e8b051acda9edf8b1a33f445bb3f18f848dc5135ca549eb6eac8567dcfc78a1689dcc7c164a075a3f97d76a8" },
                { "af", "2dc58f9b04547738f0a04827e37d51a8edf53e3068ca5f84816cdcc4f172dee909c7816de24b4968533214d4b65e68101f13b4c43aff0e9e7fcbc5b990c02ef7" },
                { "an", "4e9e2b59c07d7dd63b87d7c64d339c1e1d61b45226e1b6df23321199a215d068bf9332ef6b80ef5e755148e1fb1e538059e26452608e4c09e8a30b24997acdfe" },
                { "ar", "245d19c0325a8ea5efe4d7e26fc8d58dbb64c2e53da79f2288d8e9c6b8756c182f8c23d8950ef89b1a3c0078075b7fdca320565c27a1c600542115e5f7bc6b08" },
                { "ast", "e2fa929a493ce7f0bfb88f30103afea770395c1caf01903c7f02a2a5ad074a5e4295bf17d439d6b222ebd9f892867afc893a232b61532cb9e424dcedf3cbb956" },
                { "az", "3626e5e76bbc5405cd53e52c31febafeb141428759acb48a87ef22b1951b6b946dc96f872859dec0e778ff6170493c6a93f15f628a55ab61b3a29b393bdaf681" },
                { "be", "8cc1edea05a18c61fbdc6e4d84199539f000e469eada5e6612f5590ee90917818c49ed7d2459b7564f618eba1c441cbb1832fb1eeca2c8b3681f1053b8b6795c" },
                { "bg", "b6937b4383640f897b00c15cf6edeb7e0a6c72686aceb5ada2b818891b0ae833c7fec4f60b4857867236db3ad1849fe7fa384a8422de6f3d07485a6fce494dfe" },
                { "bn", "d1713c32fbe78f41fdd0c9837e89eac1aab10621856f305923877d2b6637c7576769a5bc685ca7cf0beb7a8fa3729e02b5483606ee7b03d7fb46f3ed85bd03f8" },
                { "br", "79790409f4bdd9cde2f78f98322ea57f4be7207ed6b8385743d865024558d3ea2238e2a5f8fb8c09164f4fc51a5c55dd6894805123f907400100212d0be2e28c" },
                { "bs", "efad889d425426d0ff167a81fb6c150577fc8703d50b96bbb5b8c8bb68d044843f3a31b3dbaf54a7b1625ccd6f09098ed29f5a12cac340d9507fcace8b71205a" },
                { "ca", "b642a8ea0b5f1c42877a00b3fb0619b1f92f03cc04f3a37385910fbb6aa8070ebf6edeba0e9a21cf5b54dbaf326dd812e88b359cdef600f910ff747af0011e3a" },
                { "cak", "b23c32083592102d2b869fd96999683d1afe9657320c97363d7956c9648689339967d4a5e61716efd2d6f384236378515cf339eeab9f70bd99d0ed19ef977c9f" },
                { "cs", "44e90dc730e995c6795faa68753560bf904c8f2ca81e071e975adc3d941a1aab8129a3f52974ed6e168810916ceea9cc80ae6c9f1d4e382b1a21fb5fab4ca0b5" },
                { "cy", "507b06ce2eac09d436541158a9c820a321ff2164198f0f36ce946ca771c755fd120f11a8d0f71e9ecc82843feed8aa81a09cc4bba2c559b6b9796cd0393e733a" },
                { "da", "29be8e228ddcbc3d9caefd08b7792536c370d991fcf50e84892b9f3c389dda1489666efc7a0280eb0bfcba259dc970143bcc5466a73e6bbcf6bb1783c89e477c" },
                { "de", "3e29c6a633456b6155a46dfa40ac65fd77359f80e3c7d110da1a76e4e28fadc575555f2cb78603ca849ee5ee49b011c1865726bc3c11f19674f1a8e0895fea25" },
                { "dsb", "52fa0af9ce84fa2a6dddb29c06c510237550225b3101724ea4be1e280c037cd48d35799e07b2fd17df5d114a7ed4fdab78911d03e691d586a542d658eed6ded3" },
                { "el", "c6820fe792addd15da6f2b4df40ed4280929e50086b3d93dde56b49108e6922850976b098698d39c582bb3f17fe4a7eb5b2bc982464fa7bf66a60efd1838ae9a" },
                { "en-CA", "41d08b96cd393c0f34843a1b00abefabaa5b93546e7c27f21f9757a851a9165fbf1cfe1392aa363092d6fc3f62c4587e9a77a1d41613fa64241e8b1e85c0184c" },
                { "en-GB", "7d612bf5071bdd0d4261ecd71afa003bc26c9f2406889fa250af0e123e168894c9a4dcd9ee5bc19d0223513858d60342d7080adfb5cfc3015628faf9f879a9b6" },
                { "en-US", "37ea86571252b6e2cfac49c72f36e1901d89834f6ec798954731a043629c5f82a3f253442d177aa9d958f0ccfe3ba56ebea57a40eac47c4305e47d6decbf075a" },
                { "eo", "c81717bc9c6be79175f7831c6a76f3ad4774c770817837d49a9ee3ba762063f008aacbfd34195fd347851f9b54d2b8caa7921484fa4093c491709c41a507e51b" },
                { "es-AR", "edab042d0de8a690431655c6f8d43fba941e7c44604dc78262736e0a40497a1955b12ae2e2c24858e3fd5eb0c5b7644571e2f45a39486de5451adc5930323371" },
                { "es-CL", "21c51ef98082579176578605af976910dcf86238d3e233a387a7be80dcd4d02018cfa5d3922f4678812c88e170846188174cef90def3512e9a1fdc5546f999ac" },
                { "es-ES", "e5d4e9682848da44b19fcd979694efb2dfef93ff795944be2e9efc6756d1f80a43550e9cd6f62c881951ef4c9a58b599b1d123c30ed0586b95cf71674b0c7770" },
                { "es-MX", "10db2bfa0b39329330d5e109128577aca0c8569ee1214db293068efb2a9c5519f9edb9ceda2121b5f3ca53ee4276fda403deb43cb2a09949b2ab49f526aba4e1" },
                { "et", "c65bf47b8c7aa7a1091f1f5d3591ec36d61a5bc9f30c25963e75a25c705ebe10a518c0ce501b723b884879ce342d191f724a0d849189f96618406b1f12720378" },
                { "eu", "0fc079e03fccc4d4b2918f3eb97d3dd6a2a10b94bdd4b65aeca8bfe66649b7022a47d8908d94e173c0655dbee38d1cf0b7bf539d6bc352e2db6d4da86fd24de3" },
                { "fa", "f4bd97dd5b98344758fd28fb18a200821073b9ad9de8a2307898dbdb04f7926ee49737cfae384597d81833a3c49c5d80e00f60dea3f6e608dc97621fa38c5da1" },
                { "ff", "a34e74c3a3ddbbcf04298a32fc6c82e48b3a19eadc6d2f97d653ae4d798d6b9e9f50abc5af14ac1542fe3d4420545f08287c422ebc4af48b8151159419ec0d4e" },
                { "fi", "ff3e04f4cabc802ac6ba58b4b4ce06c8a056f307de22c1f3d596ccc693159697b1426f21c500a2584a0d522c7640562668197af14d1d0a9fe85ddbc5fdb12f21" },
                { "fr", "66a7fd4593f2685731593d6dd152a56b42920c9e4877b1c910baa09fda92d028f898a5702f44936b4834b4a54d0de7bbeb5f2ce93adefcad79d8a3664d13bbc8" },
                { "fy-NL", "473f89ade95617911235ff0eba7e88acd2ffae73f0571af8b6a14e87c606e31264758f0fdedff125424197059967810aaa3d7e3e7363f3748378ca4fc9a3adf8" },
                { "ga-IE", "79138d0ce1f5779e78c41d4a287ba91e62cb47054b9d5c4307c667452a06f926eaecc8d081f7996b3a8519e9afbfc6bbf3070b23ba22ddf0b715f8e19b3a9df2" },
                { "gd", "d3dd5364b3beeec62e09cde648c8c0cbdeae448946d8804382c86bb015e6c603a3515ca4afcef028859ac988bccc75226008f04a57e4c92e6f905932583c0c41" },
                { "gl", "51270dd6e25cddda76c02b03c37cbdc1fb6fbb4fe7c15fe1fbf35bf5109aabb929d7a74cd741fa28a5d142bb821e0d3dc3a24f1a9b3260f619ef8ef5fd9bd061" },
                { "gn", "8416861038d16f0592e3efc8217aae1ff73d9458689fb294312643b17389b816fc7331acce8bdfc38289936dd6496cb94dfe1777a55a5515e2be66d36fdf201f" },
                { "gu-IN", "f8fa812284d7ea8323625cf591218f302340a9c0edc97954d32a89bdf7d15f58daa7d5884c4dd9a5203a7e49a8d0326855a7ebde9b61cecd14319c6b48ef46c9" },
                { "he", "6f7b3fbf346d343b455447b2ec3373b8e036e1129e77727be3bd30c154a79208c8bc4d8f84daf14d782d9c1613dc01520bbcf295ed047e509eb6f036b7ae11ee" },
                { "hi-IN", "4083110ab701a66dc385ff87e009ee88a2c8f5f290d5255ae9828e7ebd418f12ef0e858802706aecfc9069fbd3cbba46f5fee2ac87caa326201c491652f4e879" },
                { "hr", "e7afc7ca07e1d060ba04edfc682abd6da09d5d144d3f2c42c58622dff6b73620f306329405722c90212051571911f085b3c5c154f66491ac663a6b4b0f90a73f" },
                { "hsb", "23d0a991114c50f0baeebeeba641435be6ae494746306d7de383eb837aaf05a88d559485aed742452b683c20bb03266e5e58e293c00693cf2dd2a05aa6fee4b8" },
                { "hu", "2845fb676e3d4e5c6aa23946e89fbc4700c379967ddb0299b6082da94e8151718f45faa272b5a0d47b66f57bea76ef4a0ec4a3edec6f5a3cdc75d6ad653f5d6c" },
                { "hy-AM", "dc25c9c033bc169cfd242c0b2f5fb2646c9dc4617616360dad4d22e1b7d1e30138addd92932e24c3433783992a980025f5ebc1d18aedf02f92d461f2f9b1c0a4" },
                { "ia", "c497a54ca8ea57b51a89208533376a14091b6b6a5b7fdd548224602d00ce486ac5c580be3b5287f1ebd9046bca5b6860bd40baa2ad97f41f20fbebbd2afb08e7" },
                { "id", "5d048c2494cb48db56ce27750998866a0afd978969323da1e11d63f0141dcfcfc04d1694a6c122e1be0ba6a7843542c1cc71720134fb997242520a006114feaf" },
                { "is", "3f8447989be86f5ba699c1b08174e9f048b40927232ea86dc0f824f7e5d6f54c679122db27f71a715775e04057bc32daf1483e986fa309f1394af042530ee1c3" },
                { "it", "4eaea430857ef84136c0ec594acbe2255aa4f7ba7d61645720baaa5f9f7621c830f99f0e6649ecd90f4e397e2290e20d021c5c6812826ec192996fe5145a8c0f" },
                { "ja", "1131770d2ce5bebb1c643dc09f41a1ef42d60f8a652a4cccb161cf6aa641ad941d82f844e8361c308f267b800f9a668205c0d99127c9793a435e6bcc38f70f2f" },
                { "ka", "a12a251087460c2042709cf7c763ed141364d95f92f5a5a4c60a70f38311187f2b781ffa12a22070460722ce23b53af4702cf9ede31ed13e8c872cebc1765996" },
                { "kab", "75c56f8203407e4f69782d3ee1d42401825a66b4528fabcf5abfff96d113fc316ef62b14d79fec8c226dac9f701bbc9f185dc001af975efd11ed957dcd89a99e" },
                { "kk", "0b0660ed380d0aa332eff23f7318b956a0b8bdb315e182ce9f92243e58c4249590a800d84a5715ae5d8aff4831887c4bcc8eff3b292ddbddd5f028b2f767b35d" },
                { "km", "4af51dc9ef726980c0e2bf618642cd9ff63da7264b7ef30cfb0937e6eeb726896273e2c8e64d22a0634b74e74f3c280ede7388c8b4e5496002dae693a890720c" },
                { "kn", "3f667d58bc8840a79f42f17e3aac7fd6e0ff8c40d29c8e1e45ae496efd68c0d9c8948be5cdf68930dbafd9790dd251ff4275cd177f02787bcf68fadf6fbab7d7" },
                { "ko", "a4ae7356d652c94a8fdb5090d518a2e1286d755895caeeeb29797979a67ff0eb6227cd63178242cbcc7212d147297c5510bc80caac53d80cbba893f1b06ad2df" },
                { "lij", "b39a377a836a3c0857b09b8ff9925025108d9d87a76defe2f2f5310187b4fedcadf75dd5b0f058ee1e1d8bc389642a32ca70ae147f9b046b5c03c334a01e2455" },
                { "lt", "5199cce241ea78db80abc5410fc49ac74048f5e06d7f9247b790545400c43c5064359278dcd5fd8efae3a8f6803ee60f0a30cb41e5559ce915bdc2a36ed1d3b9" },
                { "lv", "95f459c4424c4d3991eb2e01c5f2489a60b9b506337d1d42b95580d68814a07c6710f3d2db38d8e004cb73bfff3a32b71055cc16789b288428ad3b3dfb73633f" },
                { "mk", "269270303ff11c1508f2f6ddce6f4ca1e5d15d6d01bc5c71ee7778b0da7b6f4b97423a32b6710d151ca617037d625889f79ca366733a9900a1202a9c22620c90" },
                { "mr", "1bd4291cae719c608116a2ddb784401118035d06c1fc1f93e043dc71d1be7f7e042d8ba915f5d3daf7bb56cf026bd2363ef21a0117268c454a00c58aa72fd258" },
                { "ms", "a536b77dd456466ed156a8d2f8cfc6162c52e92aa8f197305b4c6784752ccce8a0205666bc9174f55884908f24e5160e036b20baf3d4235de9fff56543285df4" },
                { "my", "3d4414ac139d6c3345f6917fd44951ec7e0d91656554ddf0bb9428e452d3db1c57ae60d7615dfc87fd8fcd15814b8653a19a426c8300f9004efc0793067021af" },
                { "nb-NO", "5fcba9326dcc082e34b3a4e146895e2ed74171340be4dad3ab31e7845c9057990c91b4fdf3c4083dcdb50c0422870f3a54fdd6ef653d1984d5018367c0644b84" },
                { "ne-NP", "3630669beb5fc3a378abfc776a7f6e73caaa4f4728e18298d37afc823b21c80906ae2fd66957b6118253d963e61561e88e4a09bea7ba934195371a34b8f2413b" },
                { "nl", "0da97f510324ae10c3736d6a4a728a7e6326a40f0f89ce94bd531d6936fab77398167d776a8628e3c8c8065acbff2a5f45ac92ca7c9978cf4b3302671d8e689c" },
                { "nn-NO", "9fb230d802a97b218f988efa8a15e2a16aa6099204c6652c67401c1ddd01587fb738dd867a438b8ca2bbd8d7f8427d9effdc2f32318291f63159c912ad5f2f6c" },
                { "oc", "94a790fc419aba7a8623230033674645c9b9ac2d8b0bf7cef5a7710a1d9af0b4e13c09193189dadcb1aa2acebb39b53a3c524c0000d3d84cab4cdc20b01549f0" },
                { "pa-IN", "9d56f98419c4a6b42f5ff9e28746aa25a2f1ebb5c5e4af7205c77807226b7f38e598681d830bf3f32c254da4695e3aa3e6e038c4e39aa560c34b63f9185f416d" },
                { "pl", "e631482a402a9c6f876b6621ce39ab67b26a4d7f9986caa41d0caae01b9e52984795873876a153e3064433649d8ca42c92020980def322684283c20ef9677da6" },
                { "pt-BR", "636c3a0e34affbd29f51878888c9443e5724528d20e2453e11d6ae5d0f5c1a43c1f395fe1181688a852d615e59362a6e99df68ed34f6ad9b6b7748da1352573e" },
                { "pt-PT", "d87d61b8d79e9c81ce090757c404b7b2d827b36f7166519255780d4606670eb57c3555bce3debf2daab5946b2c5a8dfbce1a7a69562432d7181f23850768aba5" },
                { "rm", "25a305bba71938bad2be0fff12143f026aa99789eb1f93075cca8caa51ce56e7d8436555bd532dfc407243b9dee095782ceee3e721cdf5febec61b966a133590" },
                { "ro", "3fe807e30de85ea5185d0cc4d09021a47e70010b3a141bb7b47b3390c2665436e5ac384379e3672968d76e6c5cfbe0999f38201107bbee915d952bed354dbf20" },
                { "ru", "b1d0352a88f3e757562dbaf5479dc24f34d65a9c3a3fe7836927275fe1412bc490b4c09fdf180989bf570e808df428b133bc7545781e5adf97fea802fa09a935" },
                { "si", "9cd2d77123a32fabdcc36c7b07f0e6e98e40602ff9b181ac702b904b7f49acd0a6a0095e03222a766e268190340ed547124f2a2a2eaa70b6255afc2f037ecfd3" },
                { "sk", "2fbccd9c23b7a8e8aa16b2f69ab06dd83f293361feb4a5790f303676f38a9bff8f3c2b6ec1f6fc6b862e462d54ec72def4098fce1d0f24b40dae76ae4da63116" },
                { "sl", "c8129503558643395cdd609701511fed7db9ee8b0d81d07baba224227a24e7d786d803cea2737bbd6a0778ed71df04842f79de707896d10b64f158e882c0a493" },
                { "son", "2041d6288c7e2dac0a499503776a392fc6da526dd4efa1a78fa6331cdf095eb881786b8438d1612a7e7479d7b0522c2773b0fd25c75358ab92edfc3f0f27f8a8" },
                { "sq", "58e90b29225f63945b24f95c4d352e41d8ab9cf90d634b46ac7fcfc32a9eb7765d62490f6630e675fe07bb66d079c1374c7d1638c8cd9d98b97287f9e17fe48c" },
                { "sr", "96356a5b97cb37e2e1d673e9c04fce86e1035e072b488098da37cbfcd4fcb80c3783a56d7c68bb878bdaf0ae3c3be2117d024cc1a7326fba5c35307d8134217e" },
                { "sv-SE", "1eee24408eecdce54083f30023fd5da491edee4a4a09447813442e87d836e3cc1015092cee56fa544cb774f6c6d7ae1b7fec999179f9cdd8e69f1e7237379347" },
                { "ta", "68b0351b7d50c479a02ab99dd15aefbcabb1ae119695f356bcc35e0feb1aaa0c0257f1a821224c46df3ccac746f7cd331cb540e452b5a4f842ace40caea5e919" },
                { "te", "a965759e2209d4d24ee719471b734e56979edba054180f32433a666c8b06374f71dbb1d0cabcfef9e69ac83e4e3c157129062db7b24eb08a2f842084d491d6b8" },
                { "th", "82291a70b5cbbce37c1664a95242003dc6649cdfc146476c38f68008df2883f2eb498617a80c1105440b99974134a9b48d0b635fe9f26e7a4f33e49e9e60f792" },
                { "tl", "a2d8e0bbd63781e600a687dcf68e0447a221463a111c0319f6b988e77cf2a65c3febd1c62d666b9d1e92b729e92f771bbb1f6ba5be7e3c9f274c40fa8f7682f7" },
                { "tr", "45a25bf85c2d7ad453a673b5615f83e8e24932f07a21c9e714b149f34c5a23be5995368b9742ae62663723c754244ed82746af9418562b2c70bb54faf7b6993d" },
                { "trs", "bc5209861159245269ccf987117d5d42c92011ea0466fe7153ce3a83ca59f5a150dff716ca50b601a72f5ef2f6d5b9c031b52f44b41f0b0d2255f138d011af42" },
                { "uk", "cd0915bb4c460baeafa3e754375c6a64b2aeb384ea6c38f8f7879a9a273b6d8f8d75d87a19840b8ab35f30d8abc580c16dfb66f42480e1c291f3c40ff33b1470" },
                { "ur", "74de8aa14e2f5856b2b57a650ec2d48b4e53a5872946deb8538c5bab122eaa1ba6b3384f3dd189daa1dcad6db7eeb7f500eadb9036d14984eb922c7b09807125" },
                { "uz", "4688b66aee6a418e1e296a86f1a4568acb6365aa3cec20025db2be256efaa60698efde695a0fd2c8e93063649dbe66c7cd57bbacf4a4d781f0cec994efd080db" },
                { "vi", "0dcddfab648494c53f574a6be97309f00ebb07672309792cd23a7928097d28e98295d8735a4115f51f0c3c9c26d5c57c7f9492992985cac6b589a7ddfd283618" },
                { "xh", "4be5722ae1765ce01cb964c4b0d8b89be915a002da07a264ab4daef6dbef7cfac6671d87f1522fcbd63fad964af8a39b925d69ed4109782ec8464c603538b64f" },
                { "zh-CN", "713581b306b31d8cbeea61ad59cab9002edc2d82b12be0417fdf27824f1844476abb6f6b07485d45732a0e420566c5d4dbe7d20faa227a89aa48ea392808fd04" },
                { "zh-TW", "bcb1902587d9ec27b71ffa5dcc3833cf8d856f1ada6420778ab9d116427399622b09d2637f819dfb672f227510f26d8d9d0acd6c61d00e70c427462bd7a5ff87" }
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
            const string knownVersion = "78.4.1";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox [0-9]{2}\\.[0-9]+(\\.[0-9]+)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox [0-9]{2}\\.[0-9]+(\\.[0-9]+)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
                Regex reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
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
            logger.Debug("Searching for newer version of Firefox ESR (" + languageCode + ")...");
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
