/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2026  Dirk Stolle

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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Manages updates for Thunderbird.
    /// </summary>
    public class Thunderbird : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Thunderbird class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Thunderbird).FullName);


        /// <summary>
        /// publisher of the signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "153.8.0";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Thunderbird(string langCode, bool autoGetNewer)
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
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/153.8.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "af8c6c6df3d1d26aa49b3a1e9a2723fe9888a7ddd37a93c510c085400ef7b804b2415edd7461a82827087b6d7965e4e57ca982c93b886ce349636fa931742710" },
                { "ar", "b012dfdd4092d4d9640492058fb7c312bcff34feb9cbd17e83b0ed4626240b37ce1271a3a2f402d0dbefc4dcc7553386bfe7da86f16002826067c3bdc24412b9" },
                { "ast", "95092b4be6619e46fd3af868d8c38f355e07cdc6330dad7b674a55acbd28a91caac887c1cbb0854752b1c2063fecb7970bb4419415ccafb06522d4b08b14900e" },
                { "be", "bb0dfa737f70d748a935a56223857e5065b97a2c8fe04b352dd00015ad10bb609ab9c39a0413fc76f986ead17f00b3ef68baa52a2ff7f02d7d271d740c000607" },
                { "bg", "beff38fc8993e722cb35873a76ea0569bad8c63896a8878fed1c05848eb91712b4ea8c69df19a44317bcbb4c6ddea3028f7249e335ad74393bd96f14ae5996c2" },
                { "br", "4179f92a03db59708a3dfa1a0664218a4ee160301e2888d45e3573228a0c85cb217bd309842ff90f77b71f722086ec6cff2ac809d120988894e167ee9c5ae61b" },
                { "ca", "4645fee832b16b769bf3e43d96629361dc89f400ef09386d14ef492e4157b37e429b0641d9c2d1345659944efbfee3e44e6d40aca909afd50835824abea7290a" },
                { "cak", "7a7fd4093e708bfd1d78c458a6f78a2b9652abd82e04c548f594449e4e654485b5853cd6408dd6898bc0912c118f75c390211c1fc2197dbd41d26d174eb83d0e" },
                { "cs", "129fd2fa5f57868e3bd8c4d22d19f4885c47d02c8f0abe8a09aa249bc4c83ee0c3badc9366c699d78658c6856ace6ff942bc52908bcc5f2ef9f4d8f7a4084850" },
                { "cy", "75a4a9e7b0a1e2ace1e548be750178fb88f39092a7633126ed70e6ecd3fba24adeceb9ba0c4b427c59aa8288ec95f5f521e7e8b025806b6e88e15bd999dd543c" },
                { "da", "fce79b4c975275d839f11a4ff33202eea408c7162b41515e9daeb24d15da9445554197470d03b6334caa6de0ed12e0fb01abd71cc5b451695e085a0984d9a05a" },
                { "de", "33d9235dd9235775f8b6053817ca3acd81008a04ddd4212ed059461bdbaf354e8094c4e6b26606a880b3c166c061fe0fa91260d7f348b8129640ac697184378f" },
                { "dsb", "c60810076acadfe70db4347a0cd30ee33718c75576a850f16b43aaf0f801f62b2ebbea1ec66ddf356b2b6ea993fad91bc4998a20f37a7d9150ff4c4938e2c322" },
                { "el", "ed80372b44418d7717b62525d859819d6dfce5aca8368b2c4e67c15e783c5431859d48f0a9b43048b3b868c888a73d7b446298bde836255a4c6b7f5f0ece4a53" },
                { "en-CA", "c081177df008b8d2f55226cd473045db5940b0745eba4bec53fa43729326c20838b5482bfba5149612a1cdf3b16fa934b250ee1df6a62dd04891559d26d92a97" },
                { "en-GB", "1421864000db3f85420805f0d655db74ff826c6f50d7de3c3f781aa8c02a4228779c77e4c75ef40fa40a1d72a88d122a40dc1aba2a4bf77c847719204ab3b869" },
                { "en-US", "8b4f8a7c9cf3ec4a3c583a147a3803ac01021670611839f14ff13114a14abf0c1075ca36cae2e438a8742f81d5780df85f192fb5b79e0bc56c0331b1dcb57e5e" },
                { "es-AR", "6e5356787fd58dcfdfe5e82463b21f4b14b460b12f36270f6b62dd3be1016d99e19b9a7b0675148aa245a4193ece6e1d909b12cdaeded01081a20083a26e13e9" },
                { "es-ES", "d608f4b46065dbe04ca7d04f014ba2d2fdc9e9591141f3d9527f168ec5b85ec85e0699efe905da44f13b2c1e92e44ef14753cb235ddada82f64f071b3a8a962e" },
                { "es-MX", "4fcf01fd120ad4bdbebcdcb137e69a7f4489eabcbf6321360d42efc78304532607b4459579e36d81f22ef398279f518bbcd77a4e607244f6a4e2a7af0c3998ac" },
                { "et", "90538bb4fbbcd5105542e9a210ff68d0cd74a7c30ef1cd5ea1f40d2cd0cc767e818cf48406b9f325abe9225f4b612b6d1bb9089cb302a0defbd82cc18d98b7d0" },
                { "eu", "5c43638ab8d5b0df07a8e5586846658ea65067594760eb02f4ccf54bbcb7ceeb3dfc0be28b4078c8a007cebfd9f8c9b613aebfa88467838bd0132ebd0e56d2f4" },
                { "fi", "fdd9d85f67a581555be18f3d043a9335c5232ae87b139ecbc4f714394df406518da433e745d2f3fa6d11aadeb2fec1d3ee9296c6da2431257a54761362f831c1" },
                { "fr", "c3ca8df489fa3d9b0f65d6eabb082c900041c47db0892779001891389bcbc2bf6623504e80c63b8de8a8ddfe3cc6161518b095cd0a219f7db69666ad5a7579c0" },
                { "fy-NL", "ddf780a33518a40b901ab754eef77bf488b10796a382168c9eb164d998101fd8fa38ed54b5a2f71cb378af0946a38d110b18cdaef73295a0b70664751d8da749" },
                { "ga-IE", "428a85eb576e2f712372354de3bd3f88f6d781625216f133463737c1140fd22b111a9d6f60c040cec47ce8ecd903783861ee9c9e89c0a9c44eb243be752f153e" },
                { "gd", "a873f1fc8065bdea3e1165c5541944c040380190494e05c8ab8065895987d4dabd981284cb6cf1a3f39bbbf5939133fe01e6c6da47935fceb683643586635dc8" },
                { "gl", "2aeef4f1ad169a24140b30f488c79cd7c402d2088155ac69ced800f4891b9fd73af344e0fc756107e5cad6c5093ade967918b64857aec6d5d5b7fa6881ae937b" },
                { "he", "1ff3b6bbe431ef494a01f7ac326bbcbf3684732412a714f69ad53b50fb797d2d0da8e47694e9015b1fc085bbdd82e7920f93a100033c255e8b7e10e5bf64c647" },
                { "hr", "75bf96b10fd099ee37a321844b0e5f57d043a90f727659a0d207167c39d5b458ea8e7f339d6aec6b145867afbce2af9dcce99cd409628bcd99a17b5d63e41f82" },
                { "hsb", "2bd264f124bd7dd7b9bf1212b8b687ea8dbcca0101d3fd60f7108f807c30e69f8b1a18d22570fa194900682fe3a8ef5c2d47d059bf700a4306b9a5844d800595" },
                { "hu", "baf610cd8d1f3df64317bd9b3900a238d814aff33f89e3e7bd2e0ae87adb7d2da54cef9f3d3b9e84ba983b7f990bf144dfa3a25e9b3ee79cd51e12b4882365cd" },
                { "hy-AM", "c5fe6c8527f2aa6ac7188b59fba5d1624400e00e785c82a3833783ddd0b38c22e0884718d0920958737cd265a67c712b3a00b39ad112d306c281ce9c54088651" },
                { "id", "50ceebefa4dcf306e5c94baaeefc16740b165ade6bc4f6f1cb5261f811b1354d1f6afacb9d42dc926c407042bd92146c82feb9c430e1a40b7d1d0b993b399783" },
                { "is", "b682d89b12e1aab358fdc246a8076ceb9455cc4ad4c90e4b44f75f69b74e4956b622d3228019862aa561918afcb55e05259f86dd279604071b1a9d969e0a0e34" },
                { "it", "8af86a17c37176c8fe5096280c267637d8c47991161a11dcf710581e672881ca06b68deef3e0f632c6fe6e6ad1db97c2f0aa2c3ba689731a33507d98fc3abf1f" },
                { "ja", "314416aace05099d0895cb27d0438c21a5af4236fc8cc829f1de6dddda2124bb6be3d93111878a2dd3c33ade503e4dbd6ecbba76cadebd799a637e9b9bd3d87a" },
                { "ka", "f2b1af996d94158935525eaf20781d53bb3fd45cbfd8ff15600eabfc9362222ec865e56990158ab3bfc951d3c1ba8d8c0d2ec1c2c9354b9892552b259e635a7f" },
                { "kab", "c330ec06fa93a9378b3019b3d14b51b9cf3d36998f6525fbcc36289759ff957aa10c4295c9b0452a2d6537023b927ff809de2bfd61c22c5a11c820bbeb2e9032" },
                { "kk", "6f5628850619a0056b8e608182da0da4326b02c432eac77a7add6f0817f2a45b63f75da8fa74c778758d02ee0f889861a03c93c1a37e69f7f9e92cfa1d59ab5c" },
                { "ko", "884b11ace25af0405c75d535e51f345c3354c44e1eb88d843f517005578f349d548120a2d077f1af63e4a6e63b0bb0295f197b8e5ac85b854d057609c554b419" },
                { "lt", "dbab3ffa9659888a08cdaa4c410366a51a5b7d5d828931a7c258325adcf075e11f3d6a6e54a4238c69e95daae6407fc77af577174a18cdfae5e5aa1012eec737" },
                { "lv", "bdba50f86f31e56308b4156c2b1e6bd3acffed570835de185b574428b6cc59b16e1f4567765edabf62230442973d1dafb2fd62953923a68ba4148b2e9580e952" },
                { "ms", "a53a3a78d915664d94d971bed5664eef6ec4654ee489ed6ad846313474d3ae06b1f696851064b405c679722be261d3a382a0412457c10ecaa1c28c14a93cbe4d" },
                { "nb-NO", "a64672c03478d3c335d07fdcc1b0f7fb5a7e8a9ec7c5b1995e5667b7de845ad053b44fddc7536f65953ef8cd2f86dc714b0bc158bea2eb407fe0135f3c50fc89" },
                { "nl", "823f2175dce7b112abd80572ebe2d526e4fee6750631019577fe6e4c314e3f7798d750eb59e44458e48287c658155c4891e19aec52b2d7e136f3bc931beaa596" },
                { "nn-NO", "21e069255bdc63b5c28e6e7b2414dc9512be860a9ae9d3d5bac5a1d331bdb2d6d16b18d46db3eaa96776cafe837d02114b09394922f23a3d00ecc2147c4c24c2" },
                { "pa-IN", "32d49edf9f927cb75d236117b67c321ca54569033f526b6ff4ef2b4d2b359df512ea1af1de1503be0683327e7620a3240abedead0747672e9b6bfe5ced90a43e" },
                { "pl", "b414031f3028f652f4f0fb845a2791a9366048fcad1fdbfa9ac784529eefd196f7bef7dc6e0c3b4f98004c18fc4ae17d2c2f44f4c133a96b6304d0138146cf10" },
                { "pt-BR", "587c8f46e93a8dd0adaf2e963c1d85dbf5a9e6b5f165dc4980d3199ad4e19a09e36f34eba942c4f460567df91a4d5939c127b7e1424ca8ca85f4a2a7a0be91d3" },
                { "pt-PT", "e8b6f44a4df4a16e00e6f67359a560aee601ddef99cbb7976d3d7cdb26ad8acb5a92e2a045e6e1c12d28abf30d686f2077ba7cca6d1cf975402d416fd59c7f2d" },
                { "rm", "1c4d8296fc7e352146279a164b75255036404f914b1bc152b67cf789a74742b039329c61589f0af0533e686b7e26f41b8c54f1c5eac9fede6ac46c96c587d726" },
                { "ro", "53e7a373287b6b9d87ae7ebcbb6eca0146563d6dc1e086ce43f395087b7e69c662eb82062fc05ec4a31f7a319a45a3282aa8924467565c9235efb14fcd68a2b1" },
                { "ru", "2c2a3f55dbf50fc4d24331d31b4fcba78eded3d2f5347385518ab006c3e812869477bab9a3699d531efec5bb73ac28e2e50d00a345b40b586c6cec892225a446" },
                { "sk", "50ca76f038ebf9f342181d0f932f83b7f8240a0fb21d305c026484c395844844805bce5da7b91baaeecbc75e650e00255498b47ff29a99fc908cbf808daf98c6" },
                { "sl", "d39046459a3ab18cce54282b8dfa12d28b4eb1a89a24e9fab9150e8562a473a05bedcad3d181034809072be0247767faa65558af8fb03fdec5c7bbb8529a343b" },
                { "sq", "fd8358d9e2d4cfc74f98dd9491bfe8b104ecb5d8000c549a22ac522c2dbb4ef0934d275a03ca179c473a52532d5be83e5cfd2decb105dafbdaf758fc2ec27555" },
                { "sr", "a5dff7e13d87dff7ba7308bc56da4e345ad9b3831163a67e34cf1cb41b31228e9e2c9a1c36c5d4e48f9d8599046717ca05c993ddf877100bea203e3996ff089b" },
                { "sv-SE", "ec96e02f76427a9eede2b65c0ac575594262e757be4c6dc6539056a27dd2c048b738069fa7aefed6a841540b3d9757acaffaaba59acb6583af0df02f38803255" },
                { "th", "7670a563b4063000aadf034b88fdb8c3b90d45f7ddc724f569766e756d0b9e68a3b5a7b25f9f31a1fb81c707b4db57f727cbe4def9026ed694035800f33444c1" },
                { "tr", "3f2c7bc58932844d5edfde83224c580775d2d36236968d7f11f0be555ca77cb6bb5b0ae5b73d5f70b2663a252e36ab4bcf1b564cf8baaa00660f0579e82b7146" },
                { "uk", "493f7bc7a296e5af4c85a7700355a434e5fd2d180879009fd51d7c036b1e0f17db039f8f53c1e7d8002ee327c32eb3106c5273c334a9b2bd65c29697ebd3e154" },
                { "uz", "680572706188a9faf11e5b544dd80b3ed976bea24c2e8e779ea16f72941bbaecc68a0b3edfdf57d62b96858f22d47cebb1f65cf7b636364d89bb2a72d1a0186c" },
                { "vi", "1a82737fd91bbd0f2285d2956736bfc1f330bb5cc650a0189cc95cba6a81c10cd1e7c372c73847a8fbb23c712425eab40a0e98b2e728b9a28ebf51c5633fe545" },
                { "zh-CN", "f6d4df5a1d074d66b5e5b2818af089699344c68bbf92cea07bb7030d0779262f3546b1bf6bd61d24e6b0b2c56365fc22c95285fd1b3b1c0f770fddd36765143c" },
                { "zh-TW", "3535bac2cc40d197f5081d83a2fc5f01f20ab92257a6e777cf4bfcba610cfce163496ab69c13daead688e0f69220c3a45fab90783f4f9c7168d5e7640efe0fc8" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/153.8.0esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "34433e8aad5d270d4c23966fc09b300e2b23d4fa5e6af7f40508dc34e4d75020d77a29f0e504f177dc230f525d7f21806fb5456509c739e734d1f38c0fb076f4" },
                { "ar", "55a367bae8b73e4b7f47ec4e17ffa8f7f94852520a0f1621107bcf29ae3b7985f6b8e8e34c5c5d0d9eaa957084e5d455d645eece0969fe51af09f44da1115ab2" },
                { "ast", "fae89488df78417a537a39c2ea0302084bf646bba992d9f97b02bc88bbe3d46157c83fb5907f80667a45516cc49ba9848334ed0d9a8eae4b8bb7244ef9e8c4fa" },
                { "be", "f886094973b81457632da0e758f4f36ebeab240b90540bf27d7a35afc3088601abf81e16a2de37ecb99388a582a7619fed134f0f61c40a1532fd24ef8348651a" },
                { "bg", "710f629c7a8b9e1de7644c702f6bf3e546ff54e28108163b9b00c886d74942a6fbd70530063eefab0098b8d1aba455af6a16fca725f2b914e1eb316b136fe4b6" },
                { "br", "f0e57ac430b393b2349a82231969406dafb705fed7c628bb6a4615ac6acc749f99225258f91d45dd362ae630b5a1ef6156c6f8dbce482a0002e890d58cbbfc33" },
                { "ca", "c755996be9e3cffa21d0011d46cddb76c32ebc7478f09655df7e4b851fdfe941ea9dee26d503ffbe3fb3c165a841d9b8ca4b97b962096d651e90c4ba6d535750" },
                { "cak", "79484b066274f0819af0270a6f8eef32fa8b77d8fb33387678915cdfe39925c05ee4a6078419ed6066b2effeaebd26a8a27dbba877e8b9e72971fe796dd54b65" },
                { "cs", "43e0718bb6bdb7e4e0b7dd626162c8c5dc1be844cc18e47ee63ca5fa990a0da147415bb17a77ebe19d89cdedd66cc43c25d893086e2708bc849e6013f8429e85" },
                { "cy", "cc8b239e02996e15fd574e1deecb8d0b6801b5525166952f271089bfd141fdbd50f8f0f5e7fd6feec8b56b8427d2c723ff1ff1d89c0aafa6d5d1e7d4b3ec7ac6" },
                { "da", "4e9e95f372da2d0e385cf1a707deb3be887791add89123b626907d7c3bf12120785f98e3b547c38249eeaf3a9ff5123473d0b064e7cd08b5e903e4dc87a14d62" },
                { "de", "466551eef065ed2d3e2d437e8274e0172ae829f9192f157dc5e19957d099fbd6f4e21fa66d0002aa89c0219f1cc493b6af1254553ccf5b90dcbb90595c55ead8" },
                { "dsb", "09ba7651d2df550cca6933a404cea2efdcce421f9c11d46e97e458dc300c2403c35444006002e7aa89a3e6f4a4beea31cddd07738fc02fa7ce45fbfca6d74931" },
                { "el", "ec3d6a147d715fe8c61c2076fa5d5a0354454372e2dbc57e67ddae6ebb2ae293199ea8f474bb6dca3322eb64697a92b33bdefa11d37bb0ebf0a2edace7429f3f" },
                { "en-CA", "99e4d2218988cdaa981e50e3aaf0af936a50923a42630a936930cb71a6e39cab2e7a0a2f1ddbbdb5ff6a649a1eae63534d90f0b419e5b8213e6dd2c337ef650c" },
                { "en-GB", "65ca8a6555dcf01c4e07172b805c37618a2bb5617f47e3cc32dcb239e76829941300c1bcf3132b7c09ab07d66cdd8f082e008c3d782eafbc94579c4c9c93615e" },
                { "en-US", "ca99841af51543f3afb9fb5d0952560c7cde70104347798425277902ffaac95f2eb7428c9d05e2ca06e02a6e8a54d01a0547cd213dfc6f982539280a168038a7" },
                { "es-AR", "f1c7dff8e95855252efd05c74550e8be04d4398332689fbf40a05a95f54a76b98b0adcb72eace3c0bacea685ffa3169777373d13cdc324bb4676f2561683ea6f" },
                { "es-ES", "474d98f60068d8bdb7d9264d7d714fc53c397e3fb48a53b5c50f432f6a877c2facec5c49cd9c6ae726bb2259ca034ec19a7c4d98ed1ded25b0db4ab9c7801782" },
                { "es-MX", "0be77828b4a300db324b2a4ace06483c606dd5a532312dc406bd9bff93f8f4b702c0937fcc061866483a8f060f2e70954e7d9e34cef89343847d0659b6a8493c" },
                { "et", "f7d126943aec3a9c6c9ebbbaabb54558c5d18d0497330a2e64edc9983b5a92247d72879668a8dc6c0d63932784dbdecb612be3961c135bb2e9d4a0ad8776d6bb" },
                { "eu", "5e8e5fe535bb21d93d629c73edfa66d417b637f1943ead29dc1b5dd8e3beb4a67f6efb4c06eb8cf62113ef026c4919aa9b144f45214a27ca0e814848b390cf21" },
                { "fi", "170c523fb1c099e03bfed8fd39597ef07888a53ec0aa7680c0692a178264bbb8444593f43c70f118fbe689ad18006a8d54e5dadccf3f44ee7868a734ca266e4b" },
                { "fr", "f0f7fcc64879b46ec3361d37564a87a6218c5ffb420dafce9267afba81b19d1039d3d34fd6327f429ba373f543235205c8a642e56991c36387f6a8bc1c9a0f3e" },
                { "fy-NL", "ecce00c2d51ea66c964c7ccd5dd698e620f74501c7347db9de7d4207a9a49822c08aad461dc13d36c82aa380cebf2610d32e122948c954eb2569b2012eae540e" },
                { "ga-IE", "22cf6a798b260e3b3c166a8ab776de1fdfe1d3485ac843644800eb15206d814c50d2db49c12d99655896f9a9e12caeba48fa2f6d3b786e17c8f1875c50763385" },
                { "gd", "412090079f00d3cd5b31ae75f1204ddb3bf05de98bcc832a6f260765bd946fc900bcc4ff2ad508639fb191012989d00c1c02b4a23e6497ce1c1e4f2d7986517b" },
                { "gl", "6553e2671f06024f82108f2f919a9abcb8a396c903f8510bed735e677b3779a0ed92b341ff867332e3fe510b79d0993b4eae699521a5521c76e59352b92936a7" },
                { "he", "e60bbfe8f130dcd4f9357915cfb2392e1590962ccf7e9432ddda0e85fdb568560eb5ab1a5b945f31b3bb5565877cbcee9280191cc2befdd69d8e5318a39afea8" },
                { "hr", "333fba21dad3aff2f50b04e6a16e11fa679b00526c5cd9f3ac099e040d3fb497e33a9ecc74d858ac8e8484d3e7614c70efb48b741d9905c551391092a1ded01f" },
                { "hsb", "4cabce2f2b8e2de96f26d80f3745eda7f0e253e994fa0f004a3bce0ec11e67530e5a27463eb9c246ce73cda6e130869aa3722095ed12d42bc78d9a9dfa5ae2dd" },
                { "hu", "cb54ed723999786d8bc50257287b2cf5455be7c4174b0c5ae58644bf599b04efa0f70dee764224e11554053be63185dc79bb2fffd027fec5ec11a550ce6b7ddd" },
                { "hy-AM", "eb365d39273867a374098735cde6861bece1e7b5f42e0350747cc2e2ed8827fb3ed6fc1cf4191feadd7dd54118e6a7b0eeea1cd1375694cd1de0d0a7e4b27b30" },
                { "id", "89760ead5a2af487d02be6c9328c8e46a3e6306c71b24df9ee3ad6c4296bde13f60975ecbfd51073a6264a7cf1c96ad856562972bf73acfd78aa41d2ec9f1d0e" },
                { "is", "5b0164c814192bb7cf5092282568e2d75f99ae5f2b354a7685db7e796e9288e3975cbf58c6764b77936c518ecb397b90b7064defaa5f0390561e87492f4dad6b" },
                { "it", "fb208bb1a7ddc85e2441929a0a00c2d1c5d22466a460c8f34437a136000b70b30c4af1f693b6f0b231876dbdaddb42f2220de50a1c4ee81e197476cd60419b77" },
                { "ja", "26a0d085ccd8c910c60ea5a5b5cc8a4cafc21d9cd3ecc95791edee9195c593fca56bcc9b4eff6d75baad79a990658bde510336c0a02e06994adb6f9514399403" },
                { "ka", "d7bb3fac7a10ba4ddbaa512cbef16b471ca1294ef57e3cb1ec6953a71c0fb54bad649577443c4af50c556d1a639f842acff35b0d84a2ad81cb29443c1b22ec7c" },
                { "kab", "62c8fbf8dba0647c80113720322291596fbfabf9754194271f1346e7c7b79212d4b11888ff902cac69c0ac7e98360f524636825d806ce9d4a786d12fae6a3e9f" },
                { "kk", "020f3dbb0809e476961520de65cea4351ab191c4fdfbef2754a615d9b7cb7a6c06f5b3f30d7171d7396f4ff80da6e189c57ef06d86d805f8b299cd700e6536c2" },
                { "ko", "0c670ce0a4d72ac2c9a023bc4567acb1cc25685fdc65211b8a0174cea8c735bf4540fb84456aad9049225c140a3b38b3e1ddfd7e79cdd4d1acaf111966213f4d" },
                { "lt", "16e5b53f55033fac8b3c0f05457b455c252bb7d41c21de5e588f9fcbe7aeb7aea4a9fd834e383c958309b4ea979e185784182157a9ad1dda4bd18c9e6524d2d1" },
                { "lv", "80161436e0cec69113ad41ac698fa0a57900483965c3c33b727be40121fd2b6961a19b3befbb672d67aa3685956c54da6ab849a88046aae2474bc8381f9f257b" },
                { "ms", "17164820372b2e17057dc25d221cc4a3531a18337836087120bc14e4a1b023f288683a2e877176e9966264aee5039b10aa376f63e72cab5068fee9edeee5ec86" },
                { "nb-NO", "c8e1b15c7a03488bff3ebfec6f169f3a52517256ef05b20e31826cf82ce9f21b4239596f04891148ee377dcaef32d8681d434e9e28a7c7e5bfa58ca261a50620" },
                { "nl", "27143c5e8831acf157af37902e798d02204c0e323642ad56f9fd74ccaca35375d2e307ff86f17fe20594004d7a4add357e8731a9c4c579ce2c14fb0444fc1b7e" },
                { "nn-NO", "01e0227ea41e13509ceb010c3fe744622bb0ef0c866d4a5641963978cfc2b9b10c7bae1461f3fde9d56a95cf6cfb86f5c8bf2515a77b50dab4d13c4b46fad0ff" },
                { "pa-IN", "6c714cc5c5ed0172954e114b0cdc9ae29b90ea14b9e80acf145c57d5a360bacdfce5425ce960c7077568c8e6955b9d159d07c3f08f21df85d2604cc084f396c6" },
                { "pl", "1ae4da74953dd08dd6db009591ab6b1be40fc054925908efddae7c82a7db028161d2ccebd2f306f113386b4bfc4988e23751fea120dcb7f43d9291220d85e275" },
                { "pt-BR", "fab3cc0238597d4b20b502c7ec3bed0879267eb474affe6708d301f13ea404b049e8b4db670e6fb3eaa0a2db672f63841da92c140ecc30bf6342bfba4b4c4519" },
                { "pt-PT", "4e389eac802026acf95773745f9f1a749cc00baddff9f5d5af330b240f6f81139de22e4a50217a9a20399f318ffa67931269b174a58ce45906f5bd72a14bd0da" },
                { "rm", "a82e73e7b920734ce428ea2ed105d2f2874fc3820f52faa051106f85be598e89f9f1f99b12143340fb84a7a0f22be7c913ef4688d2f0dd787e9548358ac8bfd0" },
                { "ro", "45a68e14fe3fc24c7b658bf414e70d7e43cfaac902cf969c1452a1dde805a2c8e2b759aefb6a9e2ef0af4ff82bb98f5f9ef6c02109fc2a44017f80a926db7e46" },
                { "ru", "baf5137960ed3b80ec542c97b308ae0cc37794a9adc4150e34d8296f60dbf66cf48ed4c8e9c561e8c0387c8db1be6f74eda1fb782c4bf64c85a8589d1efbd976" },
                { "sk", "1dddc1ce7a2fa47a8f0a3a95c522d941ddb971e4e4f0abe4dd3166be03329b97ddcc5ce441e6f123b3c402e43be46ded6a9c242a9776a401e31fb0507324547c" },
                { "sl", "f0898afca06b3bec06371b8a03107cb5309ba53e77bbbc16f35c2bd30f9acea28154faf16ffb7614984c92b47263a857b1d31ac0fb1de8f23d3b489dccff0cd1" },
                { "sq", "fafb6069524106ebc52263e2b0e08cbe02385841a7a59d2bd5d065f6526837a1bde33922e2f1f94bdf5b7ba11b896edd32758814597d47264622ca0fba6c70ae" },
                { "sr", "e4a42c28e7d3463798684d37ea60660510b2b1e6211da916bcdbc51a1d83683cb1439e3c2e8836d1c9fd75364effd4dd84dc1f1a11b9b4d8ea02100b6ad4b1d9" },
                { "sv-SE", "7789fc9a9695bd1f1f1f6c06c0296818c5b847c7eb0859a4865c33180a5b2c8b12d6852d73256814f31f8e8fef5b3e9e98a0fb4d556566c1c50d945cbb02f23f" },
                { "th", "0e8ec6fc8b003d4e4ba9705ee10e119471e4c2f6a9138f81be101105a9f286c84a112d60d6c80124ee7a4453fdfed9f42e52cac0baaaf981e395f6f567c82c9b" },
                { "tr", "54752abaf9659a4b21598a17a774877ae7ce1265d2a9ec2e5041cfc8b51c385a58b55dd137d685928522e2a099479f62bc31bfd9d5408fd0237ab407d6938e1d" },
                { "uk", "c0637fdb9f7b746356af8905a200bc443bd123adf063fc830be3d42cc5fdd00c0689bb830130aa0fd65705b65f1a5d934a8806317313d555ac062217f49c23c4" },
                { "uz", "c1d2cbba415e5ed8b4f843cf7db73407c9142d0c9d1383684c77c5e68e69d93e51f87589b2b64843821212fe2d10e0b26a8b3239c8879c1a0456940cca52a024" },
                { "vi", "c699462e106989e92996e72ef48fd4293e236cd334823dc07f17c01594f03efce2e5bde26d50c1037c6b3b2665f1a4b22be107b8a9558c799dbd3642f87e5ce0" },
                { "zh-CN", "c6f47e5462bd30ce007151f6014ca04059350fc061fe727f2d989ff48fdf95ecfa320128d051e94552bb3c3f1903797f0a209d3c6aa433e80ab99d73d4aba169" },
                { "zh-TW", "13f580bd6fd343e5f67d9dc1b50310acc83fd9021d2d1860f80fddaf48ee8fc665204a2a633cc3a3baca82b2ace3924931f5ba7dcca766a1d00855eab2084877" }
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
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                knownVersion,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?(ESR )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?(ESR )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win32/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win64/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma"));
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["thunderbird-" + languageCode.ToLower(), "thunderbird"];
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-esr-latest&os=win&lang=" + languageCode;
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
                string newLocation = (response.Headers.Location?.ToString()) ?? "";
                response = null;
                task = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                Triple current = new(currentVersion);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Thunderbird version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksum of the newer version.
        /// </summary>
        /// <returns>Returns a string containing the checksum, if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/thunderbird/releases/128.1.0esr/SHA512SUMS
             * Common lines look like
             * "3881bf28...e2ab  win32/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 32-bit installer, and like
             * "20fd118b...f4a2  win64/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 64-bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "esr/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return [
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            ];
        }


        /// <summary>
        /// Indicates whether the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Thunderbird (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if (null == newerChecksums || newerChecksums.Length != 2
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
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
            return ["thunderbird"];
        }


        /// <summary>
        /// Determines whether a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate process returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        public override bool needsPreUpdateProcess(DetectedSoftware detected)
        {
            return true;
        }


        /// <summary>
        /// Returns a process that must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            if (string.IsNullOrWhiteSpace(detected.installPath))
                return null;
            var processes = new List<Process>();
            // Uninstall previous version to avoid having two Thunderbird entries in control panel.
            var proc = new Process();
            proc.StartInfo.FileName = Path.Combine(detected.installPath, "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// language code for the Thunderbird version
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
