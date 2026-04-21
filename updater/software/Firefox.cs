/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020 - 2026  Dirk Stolle

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
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Firefox class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.TryGetValue(languageCode, out checksum64Bit))
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
            // https://ftp.mozilla.org/pub/firefox/releases/150.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "2d018a9ee6313fbaf53e787dd1b4d28353894966da3de006e80355e5f029e4038dbc2e316bc15ed21462c9ace28a2c3d7bb4668107ffff898f271eb567899198" },
                { "af", "1194dd94eb095937bed2e34cf7ac1723f86d6fec6e2f361fab85b81e5962db751436cb6a7283eb03b3bb65c5f1fd3905564f1453740a3e88550a595f364f3344" },
                { "an", "dd298311acf78107679cefe1b0692f0757461d1e6207f4b611ee07bf47698f1b702f4cc9b3da751e2fa92431f6a783a2f9d28a9a35d1a4fb4a3c6f0753e14e4d" },
                { "ar", "ed41f0acbc3af1695d000f3b7bf6e8e26d72a0e3a3787be827f70489824aaf114e78d90cbdb760d9950e13ace1d0266edf176e6094989537fd896631b37c3419" },
                { "ast", "56c6029c1d3002d21b98ba587a3b12a29c5c0458b576dd8068636ff13fe36bbb4e04af6791f4f864034b62e634f16b7b26d90dc8e0bfe57637b5440240970a27" },
                { "az", "36b8845afe3bb05f1aea73bfbf22ca49fd3e5575b2b9d35caeccc3902cc6041398d3424f97036e0382306cc3b42713d9c4c8696518c73c3d14d7a00f588ac67d" },
                { "be", "b20d73c79cfe9ce2e984cdd6d7651d95ebc0b6c7f81be6096cada3b98c8b5ce5a087e6b3230d9dd03fd8ea969e54f3d62de7112760d89898fae99ce66475110f" },
                { "bg", "6b294b00923f6f3a6b8bfd7a3b9d1a64b6d6d12f6d2847456b9e5e29ebd98dbe3a19f02814e0c3898724453344406b9a88c1196e606c5f19d365a8b013117ebb" },
                { "bn", "9937583227784831f3b30613c33fc219c353ed9a73a1340181cea0f323ad75e5a22a996e6a295df15f094eb23641f5783974bfc50b267ecdb5d76fea971c8d71" },
                { "br", "f31f255db21259d33701f7f53aee24b0719fd25eb71ebbaa4944080c07b3e10b04025f5a5923c514a996ff9bf93531c2e5c897f61139b48862c9b736f1476437" },
                { "bs", "dff79ae5bbee7383d3d5b67193c0fb513f55c44cff30270812c42a4739c99ae4e4c1b8b6a9bf1e0083b97565334d72863cc34814bbb380e2039cfff85f15ad94" },
                { "ca", "40386566b9b33136f26916abe872254f7e79cdbd950635a519338c24e25b562e1abbee7df326f420d7db2935bc875b53780d9da308ff059d079f3deef51fec9c" },
                { "cak", "7f199c629814c5fb9e3eb8607569e2b38d31c57b4c16eafdaf14223f61dd8883ef7f0b67e0991ffb9c77f75965cef3e9a0fb1b5c62b903186b95e7d8ecb6753b" },
                { "cs", "5b51b9e27926e100c0f5b3c4482f6b98e8b715de6dbbfb1a58439ba799ac37395c3ec57e8c598cf877c3dd1ecb2c72307f4c60a5d65c9c7c29f64e5e5f8a6a20" },
                { "cy", "6ae9e3db81f15232e0f8e5a1ec685e4cab88f8f9a7d0f3ec48eba861ce3d6eb687ffec2049e7debe60fbe66efe295cd6ddc1c7af2f956ee4f4e45435b2b767da" },
                { "da", "5c21075fc0d2168ee8097adcb9b5cfa929f77d70a960aaf3c4f60b5c426a52c835d17a91f245e6cb5cc45ab1cff400febc9066d27d95e78b3fb73bb587c2f479" },
                { "de", "d19742ceeed754157a152375bce8d7185624091c7c3a28754bb566dbb8587e8a80537d3fbdc579e556fd8d2721c5a2d823ae2ce7ceeab3373cc2a3f6cf737e2a" },
                { "dsb", "32c69a314304b216435d4d5bebd7a57aa4534a338d900a3912f145a8f7c80676b6699e1fe19ff6725c13ca3e7f09b50b9e476f663ab28975a3fd98e2e3637a8b" },
                { "el", "15ec2587ec3f29da7813d1b7796a4b375e662175094f5fe57f09e50457e56ef6efc02be1eb7052aff513132868a9a4fb6529e4a0e64cea43ce202dfffb414e5e" },
                { "en-CA", "35f715e906c7292f72ff2ba4f692162a5dbfc3940c9887b07cb721e860776da0c7c991ceced621735fac3ac62f9e1ae7ace47a5edbca877a0f88980beec32b0d" },
                { "en-GB", "bdd4b0465dfce4bee570b3c758b868455f13d59bab0baeac803773f3a7cc5f59fffa0f6bff0a2f26670ba90089324ad27a92c211c738e4c016e11f231fdec21a" },
                { "en-US", "8a1aa69f97006154d40f8f48316743b63a514c956d87618fc18df1c3a52bee977475575caeb4c17853f4b4fdfe4ab00ea8a2743992b806faa465df1c8d866023" },
                { "eo", "9fd68bd4043ad7c4a5afdcb8fbf43724cad3f8125b9f7eaea9d16bc77bd5810424dc922c4f45f9311f25057c20eccdf9268885ebba97b1780a1c1ccb96ceb4e5" },
                { "es-AR", "f05a77609f73fc3ec1f432e1e03034e4d00704be76416000371c587d8f3b69edb8aaddd199d2c3d440ac100e170af5c2a14633a8e86e8b69f9f1c82558af0aac" },
                { "es-CL", "f1a46410c57f959fa09c3f9fbd4002ae5220f8c63dc4f8c78bced6a18d8f9132fc8d310a6c162de4de10c5cb8035e54e083054dc3515efbe1879aa092e80def6" },
                { "es-ES", "482454a20398d959e563bd46f2eb9c5b0d20beadfc0aaed641431309d590e8cc6d5c58fd71014d81088ecea0ac380d0dc8395015db209756f494914e61151b02" },
                { "es-MX", "20006653fe3c72ffbbab575c605ff325955f568a85c5ca3a79973762c0354d468fbc984ea90b96f699af549cffaca4f5eab72d3e0bd6f14200c9ddd41642b79d" },
                { "et", "75955a24fcd7d70aa265a0e84b3a81a9440ee606a36eedf791f7fd473247be20a89580212ce54f46df039791ea413489a5fb9fd1a3155f46111796b8e46a0630" },
                { "eu", "e3473e3d62d43626d34afcb239e61f3169c5979724c938a4834b7e6769df0d7a78de6a977b3c96aac483449fb6ac36c6db62a99636a9066a74d9869f8e661e7d" },
                { "fa", "a18edf8078d7a473cc17f0333edb6fba95722de6ecb5ac1ef6acfe8a95bb7dd99eaaaddc2a18ff9d1c3c5c1edeedd79480703ba9f2745b46b03034c3286a33fb" },
                { "ff", "83e5094312f5743cb578c8808c6e3494dff9232ad4096c8a71fb40ba9a71aa7bdb3edfc1c3f7d0f6509ce4468cae38eab7ac5e386f6bb5be56415273b0b39f81" },
                { "fi", "23300398b230b0661d9c7570d10740563fd9f3973fbfc0672afd478b72cc4cc36f7f814444aaca40fae5f7796547c79cc81d64011d230dc39a3b850df9bcd9ed" },
                { "fr", "fb245f4c95e07bb5e75ded28320244ebd2386e8faa3da5c03fed41117abedaf325e3f9349eaadea8ba3c47d79f960072b2c78898f12ef9e1475d1b9c8c10edb1" },
                { "fur", "e1e143ba62df7eb1066966b9a5f0be14f27e878e38fe7a42fc0bb15844f49d3b0e0784a235b3b6a507c4d2e2949f038580de0980df5a3eb0b5df4bdf677a60ed" },
                { "fy-NL", "f7bb83d614e8aaf942547e26bcc18f27418b9a7ab592e8f1c1b0ac48bf826f7e63c0b11ba75ea3d3fd77fcce2c4eb3441558508e9aa06095b4bb5bf0821c04f1" },
                { "ga-IE", "6089066bcedc1e7869baa03c524a1dcb3ad8352f11f7d1da6f2d68ef9b01273c0d3ab6f3786cc55227303616633611650f9d246980b1bd74e1749e3a96d8550e" },
                { "gd", "5636e22205e0b39ef624b09b689ed09030e052f72dfeebe8f720f474333639eb92ad8f01f3b7e4785dd490a1320f7a710fd6e7e98b5d084896e9da6abd3ce49e" },
                { "gl", "948cc6e3c77f7d81a72fd54e0d4e7af5c51eadac71ad73239873a2879eebe3b6a369bf91626e24973eeeeaa7ae31ecc76d7bdb1a812c2e293c00944e5837bca0" },
                { "gn", "33644492bb758563bb0403925ae111fb1336ee01812ee143cd70ecb528b497ab7cc285c6889c6433a486edd29aded8cf0cc0fc3d8f6fba6129dd54c0ca53c657" },
                { "gu-IN", "b47a79a17598d394d05557ecc1a4cce9b462466dcc049dd9fda542b840e118723dc5be96b7c639529ba6834ec69707030110ed6423789e60fa42e14df23d1688" },
                { "he", "527253943c8e3db8c72497896b0c7d1d6698023077158e1fa3fe0f5f51eb791e80058b9e4c7ec401e8efc26c7d3dc52ffae94488c5e2ed492ff35a103177233a" },
                { "hi-IN", "6d35cb47ff36e96287cb4ebc6945ac218eb0637e9614eeee9c2f7c661521b203c7078070b1bd1e8629a8e6d1ad116dfa57333d5becfe7177c290270cc02a86b3" },
                { "hr", "4b8c2995840292269c4dc9832e153c869668567040061f278c02fe7a793c82b3fea41fc1bf115d6ee6f5cb60908a7e413725f1d3cbc12ab4e7828060b10c16bb" },
                { "hsb", "a68b80920b1e377123e9c8bcfdd716e97505fd8a96ac05fc6794269fac40a3390d97354c216057c4007bf6d6af2085f90f15cf3e2273d771abbac21666553364" },
                { "hu", "8cc580323e0f22195684b3cf6d3f8a3ae9d443cd099c039344afa41aec4ce37ffaf2753af441673f7230aeecfddef2728ee0322f6be446b183f8483f80ed2156" },
                { "hy-AM", "6246a2bad4683228849a53f255afd98d411ccbcd757bf20447421a4f08974f4d8e3b0ee08a93935b80184a26c3076f94d3c650440da4f8b100b3e052ad0b1549" },
                { "ia", "08272f21e062a407acb24a4d19795dd591f8bf7261765a0e5923976ec1cb544a241c26cc4bc5748bcf8251a5aa70b57079b186b63ef74f765981bed32dd1a355" },
                { "id", "35a885587aabe1a03c2423627c65bfc0a006adc26003b0d894ccfc278d16c53553798fa64d7365e8192c61c89ba00e56a5951dadb6d17dbc8a1183583b974c09" },
                { "is", "fb82b4c3fc4a74335d3a35e6cbf7e8ea113a06170af717b50fb0e13a58cd97da0c55f6c9bf6bc29578a8a3315a900693db682be20417ab711b7a532a86aeab7b" },
                { "it", "cf5a40cd800ad2c7f3287da131bf4679ee3f96a15795dbcb888d455f62e2a378d8e65995f23a35b477e7b859dc3346064bf19ff8556b32f737063ea11f074d55" },
                { "ja", "ec268fcb3923305b75c981e84bfbd0c938b1185d73db7465b7c6515c699d0bdb640d6dd3360d67a6f0c81977ad622670856017c4ffbab478f7c4669e1619cbcf" },
                { "ka", "1c3478ea953d732fdfb7d00c9952e800e1458045a19e1f8f5f978741c7b3c8de98c05e8106399786c0d723078b26c40678198355c9d927f659315dc3b14f1486" },
                { "kab", "cf2d88f7dd5e19b26567e6e6a221460301365bb1ff466ebd291bf9cb0df6b4d52403ec45027026396e0b025dc05423a459ecad93543577ee3a5b5e4ea2bbf4d7" },
                { "kk", "4e8375afe03347f67045e94eca478275a0433742b28cfe3693469f115d7257f2fbf4d9dfc15832f30a6c734f04d74fa79b155e51ffc1043d832480bf4ecd19e8" },
                { "km", "0b6b494126740b3aa4c1eb18fcbc35715f0085816c4b14991879ecf46a332a574f54d88f77b91efeb0aadd0ed8ea3a4761ce96c2a8a574b915df2dcbfe7440f1" },
                { "kn", "0aae32f9ac3656b01eddffdb01ca3d06086e9721f6217fd41e2f3bc9dbd5e3f55b11f9940b8ad635be83aee8331c694239cf6da611986c2c13313a12e0730efd" },
                { "ko", "ea611dc9c5bb0b2fe217b023d37837800de948170c1ce02ed151b81e67ba7f475b40370706cf8a3f0b7aa53e845181f969f8b338ec1d052bd628f2b3ec1b14ad" },
                { "lij", "ccad9b8a7d5c2efcb57df63909b863cd4eb8f13013ab16b575cc95767b2c2c8a1bdcf438bc70ed7a62a7b73954c853d33d2098b960b041cc0133c365dae642b5" },
                { "lt", "6af0e0f1c348430bf76b7f46beb608825bfca2a0698e88e0e045e995e8b72c166fdbaa70c4407b8cd200c986e54a7b3bfba551af1197912c3ddc122e9a7cf117" },
                { "lv", "9cc44f42092611d9284efbf24d08fe6d53b78c5b2f772a9c184c8ed3054d035ef76adea05e5588c9cc1be8ab6fa10c3368411dcafb36e28c8e6966a99f6b425f" },
                { "mk", "c84708c224747b71cec227cca57b190c24d3bdaa5896d14f9b22c67add4bdf26cdd3517e41df8ef3b980832c3a57359e06feb3684791c6527acbd8059800c452" },
                { "mr", "e5c4ce9c5dd288dfd45ebb706830502ac0c86f48be6768c14826e68937333a7d856cace1e5b338cb64317e0a8f69466bf6f176e24f32be7505b57e3112af18ef" },
                { "ms", "6854c8848b674321472e28706a6965e02fedc75fab29828c1c497039ce750dc32f6b77770acebbb12c5934c1c50b023a60f0be24538a0e1c638cd7d6fcf5471a" },
                { "my", "6b1dc719a0a8f352f4da5ad84f290e9b9ab1a16ba58835e6cbe52ab0d5cd33064895305547aa36e219e9b9d1131703051ce86b25c88f793bb1938f2304bc31f4" },
                { "nb-NO", "fd58b85be97c5ee5e0510c157a5109ccafd0f2ecfb49243c4db11184a27723a6a0cfe01962d2a9c688f435d4057913d657d453e3c947ac52dfb36ac01568d914" },
                { "ne-NP", "20de0ad744df0b3dba0f8b849f38e7f2802b523a12516b0c3d2388e70759490c4d45be12bd0d5dc089e9e8daced0ea66cabab18f644557d3c145780671f6801a" },
                { "nl", "ab8c7ce1a6a9d01c35fa450a582e38b2154d5d582e17248c931ba41eae0bc9fb858cfa88dcc2d44f3a1d9122a8975c8e1e85452a7044350774f95eb63f9ce78b" },
                { "nn-NO", "b28cf1e31f783ed995b3ac8de82b7ee98a91846144d672fa7f2eb2d98aaea720365d0c18872cb4e75b10a99459f0ce29f55cc5d55fddb7d75d3dc609fa5a0d86" },
                { "oc", "f411fe728e51e8534f8b7d54e7b063668b1e0721beb234f52fc9d417246882772fa7355165ec512d4677a47046bc2552177a81fb7f8b08da11e66c72e38ed725" },
                { "pa-IN", "3ad36c4481538a94f24786ece8a4cb8b46079697122b00ce6194578ce2fe6c3d18a7278024b2183b23f2491c034818d63dba0b98c17515ef592b175690f6dc9c" },
                { "pl", "afd0da062073bc70ec158533d7bab7cc2dfd6db71f4617c5c58e3963bc5d6077caa1d4124a38730078cf2013fc8a8b0b3e3c3d820d31056aae440b8eb6fea69a" },
                { "pt-BR", "92861b5a33b577fd4e773d30b2e14c980771a525a28be0d9a98e7f0e04b6cc99d3f482af7f186d5c47a798ac895a7e78b83f426a71d57c5fae89f546446f5a8e" },
                { "pt-PT", "ec21386d8c75bb70ee8cb8123e814fad56e0bf96de29d8d578667dc57e1b03c1f07da2259b662f2d2e300901793010dc480455761677f7ce92dff31b9fdbac36" },
                { "rm", "80bbda94c12e7d716d2e78753bd11cb4f482106f63b4caa175f87509962d56ad2918a6febde271556fb1fdc122efa840d457dad0d540847bc87dfa7314eb2a74" },
                { "ro", "616a2d8bdea4f0ebd36090bc38afebdb9897e32c8ba8272e94ba4b15dcfad426f979adda65fc7466a19ee106065e359493290d3b9a2abe2f84abbb7fee00dfc7" },
                { "ru", "b19dd23ccf17f2df3cc8340ecb9e9f842c87474d33c83c40aaee318a5ca2db1300542f1821fad35f8531b6eae55088bcbf6b1f18ce530a7c012c68ef091bc4dd" },
                { "sat", "0ba895e23847f8183ab0cd4a2645b98fd4c98a34c24122bce5509fc138a163fa706f3fdf47bbec40cfe96c1c066300d362432f40075d6c850526d5a38030ed6d" },
                { "sc", "444e25d10280174887131354bf9cdd37e8c175c0b7b9a0e540bca35381bfbfc5e25c24e96f27b26af3be3371779c85d407ebeb05dac3e6b32bfa81cf3a8a8d3d" },
                { "sco", "1acd8eeb7f374deb99735e9bb0f9d2039af13aefaa35115c54e9617d2e2e994917ac33240783b0a3f8e7067d308c9e6da81651326b5cad49384ed57250a139fb" },
                { "si", "22a7ed14df04dbe4ce5763070ad2660a370fa666f13b0c456234659551381b63499f70eab2644ebca84c0aa26670bc9c488ecdf067c665826dcb8e6102e8606a" },
                { "sk", "01a050dfc9bab67ed5d0afd1886e7c52da1d085fa39aef5a21244ca747d0b65991bb8fa15f6778149dcf980c64c11e917b9f67c8a2de85f5482b5519702f6bcc" },
                { "skr", "fd4ef975c70068c1bb0d2c26f336b0290202a8d075436f56575bf65e6f8ed24229927c876db0cadcba067839477eee96521a3e4f631d4093170d17ae077d7c9e" },
                { "sl", "7e2342a2d16fb440cc08865e38d0e7c0b7f5bf13e364e55143cf44b11e64d6f4a9dd0e5eeae2f681aa6a7bee2cfe4279089e6aed1529c9c8d00c4758c906f8de" },
                { "son", "470a9e612f0088a20da7fb5a23fa580774031e816464d898685c7b4ac9c08095ea67f9b0638f25b59063bc01b0b395618642a85847cd0a53a98198b4874de5bf" },
                { "sq", "32e5f09990f40062534bfe32d50e32c57e758c36d944df9d84736580eb7623a2a267ac1b6f9b70bb1008d6628ff2e021d50d878306eecc6e51f7290996b5d7a1" },
                { "sr", "23c5d7faea56416097ad33eb17dca00aa8b597e3d3ee272f1c7815b47bcc5abd811fe1473842871ae3cb7a42297ece469ccc06268e23af4907415c9a4c00dde0" },
                { "sv-SE", "706cd7b598b83beeee5bbd516ea8cde09f65e20ea59cc7f69f199727c7b7fd701bcc4101a8da6b32039b754ccb7d10660f21a2f67cb0c5ca9ccf936872cc5bed" },
                { "szl", "8dbb607c347a3000baa8b3f7348320efb26a8ebc78afcb0b11851533e4d4f113c097646a7d67f97f96abd9f69cf54579d11e631a6842e6d42b11568170bbb45d" },
                { "ta", "80e0b14929a8c49dd58e2932ccd1b422a5b5dd8c1e3bb7dc1baad017ca5a3cf81cf945feaefeea8150dab0ae75bc6790d5f30874098db5cae149439d11c16a90" },
                { "te", "7afc562cdfb30815ee19ec3b47f489c55ff47449c08906aa71e356b6e629b831407e392b9cc5107b53bda2a4c9fc203f049e2a6d939a94907041f962a6c63258" },
                { "tg", "22d4b9dfd0d7182e9dcc8b5d9c78aadc853186210c453ef35466fd330ff9d656a65e1e8c5b86836c2efd1c57588765e4614833705ca5e1feab79972daea230ff" },
                { "th", "10c420abdeb93dd3044b467cfa2fd210c4d7bc4f558cc97cef63e6c8feb082d5964913dad37fca3a1256d15d7690e16da41cd7b235508359917fde3137ec3784" },
                { "tl", "1ba5ea0b42b4ad4eb5e2161547143068773ea3b41b0c97d690a59d9f7b3ebb9456f497e579f69c7f6b65048ae8937a28730a56559f3a65cd161aaa19d065b80c" },
                { "tr", "53317029db0d9f95f98d2a43ffb485b3b9886dacf338418c48d2706c480be24e614c4c33590772daaa1ae655908bab7fa7d5297ce26e343c8b34a0bed5efad22" },
                { "trs", "f35e8132cc5594866ddc06eb64f10a840cc2d3dfeb9e93c592b78cf14df4e5c5939c89418ccbc4ce6d3854038ebe8aa6e77b16f2e95a6886607d128ce1971374" },
                { "uk", "2b7e6de0cce70fd7167262857693fba2bf564ab959818080d6441e1b0dc1fc08f4d047152a45d8855d06880913436587a9ca23286a54f0cc42e833f7e64c9c04" },
                { "ur", "7087e3e8ba43f63a238e462635515214abea677d68e9036b9acb61b9b8bd3a418f40298d2b31dc0e53d9c4d1acbbe47f410caee77f0ae33f884bcedefe102a96" },
                { "uz", "2431dc308a001cb824f1967a484dcbaa8b274a4a48b763aaddb0c2355b1caab0c33a214928c32aeef109fac8408a555e5d2b3584a5c1c641f8ba05c18637b2c5" },
                { "vi", "95d69b0fc4c02d03e359ff4c9d582c0efdbd1fdf9571043f30b52a0296b7a0807dfdf530c7893c3ab8292487826185e2abe793c07ea7ca1c744c4d1b02d6559c" },
                { "xh", "5873de92e000e9725651c56be63ec1dafc657d42954b73de1318c28e39c659662b379573415755a22984f23d73b0e03bc6e2a35843b7d7368e8e7140c168aa05" },
                { "zh-CN", "181007a4a9c1c18068767720eb752507533b59046cc3cc63fc14e8a28091f83cf35a5a500af794c7b19ce286e6e6bcc275dc4e7e5e9d3b9fb3306ac719f3d2e0" },
                { "zh-TW", "5669c6a452e4ee760eb5e4ec28dab31ee6ec66a140c973ab66e58a0ab46a9b2b3cc6f8c988fa09ab883f87e668bc5d20cfa24a81fff985c1dca2096de5ec4e2a" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/150.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "ea9ed29c9917c195157a9d953f8adbbcd3b31163271085d1a32c931aab8768ecf6f2c49cb4a6d9dbd7301d41132b2f866618317f03e89319dd92edf2e9e67fe4" },
                { "af", "576f8af4e3ef66dca245f7120ecd3e1946164f8ba94c24ee22b63ebabb582b7526f01433cf8add098360cc1d552e609bf7455cffb5e8d90dba40131f360d188e" },
                { "an", "10eead4df23953e260f3456305ddb2416b69c6a5571bad937ed4a18ef39a111a06c205de830ab215575940be9a0379282e13b3c893d5f781ab130ebf9d7a0a4d" },
                { "ar", "f3227ff321a930a010d182d57b6c0ca292f5205cd0fd336e0024a9bd48a97c432e29b507ffdcb55012a0b04e2cc98512561113dd5fbd45ae46190f9bd0a758bd" },
                { "ast", "d6c005a64becabb8b64af96ff8a16b46429301ef6374eb0669c838339be6c0bee2c9d052f9b657d588f2f33f334ee6667952fbdd1a0b957cd7f77b8e2a2f39f9" },
                { "az", "b04acc62c33b453305171210014a7c0485a13120524a0a9400ad69afd6a5eb1dac0b436167b1e0bb96725413fbef8fcd0b4c2ade5a3fcfecd683d8251f549d03" },
                { "be", "598a8bda2dcd488d6d33397b1f8c5f8bc7c3703fb66d33ef1adf0dce74613b4fb6be2e6a0ca14809373d3168c5b4153f9d5b77bf78b4487048915d11e760f34a" },
                { "bg", "33b985e213c6c549838e1b85cca6f698d1e8db29a4f13b0abff2a84fef7451b2f31c36f0fa1e1697d5138229ada7a8caa3f2e6ce8a1294b6f5b28e92eb5f2b1b" },
                { "bn", "de01a10c449f5841a55c468f1c4432d9e633cd10c184670944dde42377d94e38313d0ce844861001c9674eb10bb0c2c10c6a2d79575a89c87de894d5e6cbe042" },
                { "br", "c48551500d17c0beae9769ea4f45f77f05b193fd57c8dfecd851b0729a9659b6ff1517f1573faa2f705341690f9a02d78f44fb500d339fcaaed2c76001abf367" },
                { "bs", "ec7d2eb78119d74cf5eff38a11ffe55ec1709783ab9ba9a7f61f6945592a0998e936bd6de1aa349e014e34a895374595276c357d9c4703ae385593477d54e8b9" },
                { "ca", "50c61627f85863b283dad7b96cc58f04917a2df9cecf477c432dd95ab09b874d2fd6dd98d0218da6cc5cc43baabc510aad3d720461461fd22567b96fbae9d2f7" },
                { "cak", "7366335873afa49f867f86898676dc5a2f5ff8b2cbea8beed082cc626623a46fa3ae541986c09f6347ab31aea015a0c594239fe7c4d4433c83b756bc1c5d985d" },
                { "cs", "d76ba58340f501c98615649a7f0005945b415d478b4a12cbf9ce8a0f03ec21fe5606cc47843e617c2e696839d10484b0800735545a9f0f8573ec650d14648cc2" },
                { "cy", "ea7b84e8ccca416dbaa8c1072d0c63832454949e46fd67cfa1c073fdfc435abda895fc8f5703647468e7397f293779520562c4540819ddba8649fe86b889f067" },
                { "da", "53f689797f5d6b584c99d0a911b634ce3ce348202181484e5b2751d37192ecf00323d4cb06a8b044057e19fd7758cb4ce95b42f4d0fd3b4de894879a0885ffa4" },
                { "de", "d03018c36be559e56479de84a82ebd4f9d3980845fd399539c7d0abb7b468f7903ea667d48dd24de6536d6e2273eed19ab31fac52a272c242879a96a9e36e10e" },
                { "dsb", "b83d30bb431e7b1c23cdb375bb7a52046f30bcfaeda266824e03a93d4fa6345b4cd12df6c71971144b30eefdf541b615e9b67e2300fd064e2bd45fe45b67d026" },
                { "el", "8d178ffb3d64d012367d1be5ec3add06ff8dd346bf45623a18687a4c6a2dd68d388d845a685f2a122d80d1561c826cae362f4d8d48200623f439a0130f228402" },
                { "en-CA", "da51cdea108f13aa8f4681c5e1f4f745f92117f95201639c7bcb0a304d72144704fb2148cc5098cc0f0690b787713a04e810e1a1e5356f4296f99c7051ec8337" },
                { "en-GB", "e8e84698093346accf1a6bf09043dadf5ca5d3d5874afd29328cc521c8f2c38483f477bbe1a027868359e0832c514aa10ecdea29fb4055f0c249f98c079e4776" },
                { "en-US", "3dd7908eb8c137d497f77ef58038b92cde1311bc41b4a04d8998f42ebda7c82f8a47920f9ffa8356dfeee3594002498c9cb4b00e4ab7469498b48956b83f290c" },
                { "eo", "c3f12003ace5a98cb532d8257fae3d7dfa71ae4c2c713e8f1bd2bc583447523e725e8438576a57bcd3b1cb89ba8f9c4b32053ac50c063b266f8ef934d1117c47" },
                { "es-AR", "1cb942b4b36f6083d4cd7415f8cdc5341d3ff2a932519fefc16f7c64b7f0c4a4d850f08f8940d975a8ce5eb400537f75f2c0f6bdfaf66ff52b73609c07ed27ed" },
                { "es-CL", "3d27689557417cc0e6b78e34d8ee4fc88d8c63adbe48222257bd54e5a033179b68b88466f5fbfabef99486dcdeeb195f130b48ee209a9b985aaa98e508fe504a" },
                { "es-ES", "31dafc33568c067bc64b387993cf0c93a0eb1c5c5b59ee01a6adb2c424a7fe96680c8b006384c8945a0c6eb34c93cefebcd4870a45247ac635926c5e95f40b14" },
                { "es-MX", "23655fe335637fc4642bdbc6a3a6010e1c764c2975ed0af949c664abbb27dc1cd132d4cb219bf8710c5aea776138fb5465d7cf767c5684caf71072cb810712c4" },
                { "et", "238526eb83b93f729e584a3392ea51a57c0a8b8d1d88362d553b0f002918d9222a9abe651498c8ffaa9850ef63b94005761d7496bd57015020d3fa29b04677c0" },
                { "eu", "c92501d895f695736780c3268fa22a6a554f23e77b19e15990d77f7741ecfe3ac4a089046647e7eed10e03a8389811444d5c2f702c16e3c103866c6f85a77639" },
                { "fa", "771708dfb622967942ed413a0f8c91e28e58025176f4988c979d2572e94a4605fc15660d5278251bd622e16b25f1670993cb555c22f14aff79f376e089f2b378" },
                { "ff", "59c0bfcdd2d5205b6acb9da31e35b054bbb75b35eddbb81c1793871c08b5abf43dddae49731ef6e321fa0ceba6c0b0ce2340558c7f53b0386c44b3fcb2195db6" },
                { "fi", "144f4b94676ff182c7ad901f717db5fd5773d4ae478ac1a4ea7db60d6294f212d21ee55d04bbaf265483ef589d3337381d911b59454a9fa6b53087e0b1f2533e" },
                { "fr", "ea32e54dd7c39cfaf387941a00cae501fcc6442fc27524829dd28a3049b71ae0ed52502884e58f063e4b7d8d4c38ae9980eed22fb2472e344facd7db5cebd775" },
                { "fur", "a5f74d6d8dac70927bf8408df5bda9333579bccdd33c7ced5b535758663dde3f5bf262b8855e36adb65382b43661a3954b65e31d47447828dddbd61521547c17" },
                { "fy-NL", "5df7e00192934b5def1b9788d9a446e601249e305fd5cb6433b3310d99bf3814f7d0510f30cea20ffdce39dc7a7727bc1fc7770ca8e05f97826ae60d25f2eae4" },
                { "ga-IE", "3b0e0636156f7d3bd54b606931d1670723157b215ec1f9f34d592187c06657570322d5027966777db01828a022fe3aad50e6346fd21ee7d2059e4193f881d5ac" },
                { "gd", "cb891d6211b5e9868038434a57c2d183f6cbfc4d28223bbd811e691a9daea40ac5d7fd481ce85cabed02924efd175b02958509b78ccbdf3e5876e037beeb8636" },
                { "gl", "37cb823738165e100399c0d5b4c2c96a5fe218ca861e09bdd7de802d12a1813fc628e7c3f6d84a7cdd2b9712054da1c1c774d65955403c56e55cbdd500fcfa59" },
                { "gn", "2899a8c357b797a4435cf3e065b11e8933dd1d4b0c7fac3e36eae98ce2a9e09e2bbdf8d8c1288dfb5b5f22ccae6c7a494aca8e64bfa560757b49c2aefb36b444" },
                { "gu-IN", "aad4d2de9c34aac5a7bf968037acbe9262b449bcc5f2c06a3cbbc58311974002e48379cb1041ffcaa94658e9a8b54f6871e6af40448f88c3c88cea189b5bffc5" },
                { "he", "51633a995c8aaba9ffe443ff16d76d138de52b3e8c2681f99b8b1551da0b2d6c4362156682bef5e9f18b71864ddf079e2837050c1493ec5d9b82741a3f1657a5" },
                { "hi-IN", "b058f9590e380647b4b1fda00443939abf018ddba61902b8b271b08f3bd0fe4d58d464c282b6c8be1b910cbf0a284b653120dae20f1a08486a095133f75d174b" },
                { "hr", "9e2bb4e9c34d83420e3cc9d38d29e2654ca3f05be24b7e8d8c2e1a0a091a3daaafc0931bfb4a1c280c7d556b30ff3c43f288f267ea4b01056f5bad59879825f8" },
                { "hsb", "4b149cc46a4ecaaad3dd06b08b67a4bb7c71aab908bc1e160050af0d56fa6805c8818e7ca13b9c4f721417f06d80e151eb2795f5b605acfd26c5f87f12c8d364" },
                { "hu", "63ac21df917a9145aad4752ed24362a83aa1589be37c485cd68851bbf0bed39ba0c776032decd214944f0456cdded73517b96e6f31673b7c723c60e58ff323ce" },
                { "hy-AM", "68a18e901ef38c28ab07c68081e2712240687612062453e129b3cd7badb7c03c1392100ba4b9beecd8ee0a80521807210a03f0ed9759b5e01232c58568ddf618" },
                { "ia", "dbd46d0314f7a51e00725c6db693dece0cdce8fcc3e2952884bc0d0ef1b9bdf620fc50f99606aaed882edae08d91555f809e1244e1be1be1c98e59898d66bcd6" },
                { "id", "725ed00e8caaec685894dec0adfad60f08ff3909143437bf554248ebbc51155b1a31b2c350103d3035c5dc9fbc021b6b31c104e7e999f0ad6a96b466f10d1ba2" },
                { "is", "5d65ff20acbcb631f303c25876df2c1efff13f0b35e0796d094a7586d81d3a59f54cc7946012510a8b11f2a983a3b1dc092ee94629b437714742214729c2bc2e" },
                { "it", "e5fc525c6af4e24786520028886925bf62b1301357230b143de5c29954f64e025381072954bf673b526f82578b8965d66e5622a988193c9c4e01b3ba33b5408b" },
                { "ja", "c5e529e79726481f793bb62962793ae0b6bfce67e21175ef0c36e10694f5b92c36e32382e77eb7301184247eb115cb080759181cd5a3501324b8049eb01800b7" },
                { "ka", "def9376f6b8d8c035dfc1a3456100bd843d2d66983b712b8bd550bd0cf75cf2008a4d133dc0c00b35c96b7f8ce44d4e15f821e6e33af4aa5e534281eabff1ea3" },
                { "kab", "f8e207dcc15db3261354ac24f5aebeffeeb85ec04a875b7fd97f95ad99b60bd291651ea2ab96a1fac8b4524bfb02512867772081e98614f5b438651d089d0e5e" },
                { "kk", "ef1bfaaf6f0cd3cf93f118a05726022b5050e5084589252a63acbd2658211c554bd336681f33bfa2a7de0c1c2ad9638c8b2fa8132c81f5ad0deb0fece1f229c8" },
                { "km", "72cc4b5363a6c16c7416f0b473f90ecff802a8350d69b363f8557718a3b93ba12efc8ec4b2e9528ea9845fdde5a93ff0d6b6a8a878a00fedc1df6c51db5f06da" },
                { "kn", "45869c094a3b6a3af913837dab20b7c96abacbf0e3334601f0783b40fd38cf522088fd8342d6b9e565698eb1a2dc55b143c4e6cb0ca2085ed7b1b035c4a534e3" },
                { "ko", "f340f3d4d19c197e9116d732637dd4f9886877f4d01ba4f8de27723bf25e687d5788d730227952c0d141df09003126940b24c4adfce96c58f54db9f0d0ebbb7c" },
                { "lij", "a0f16dc9eba4e9bd2655297bf531bef0cd7eab79e44c80aab8de5bf493fa304fbb6907911612657a55dbdcedca47ad59dba0a09417f57a479d5f8fa9142325ce" },
                { "lt", "84ba57c791a8409b0a837d45f386e3c8580b5aec82ae6bb05f50b4e148a0a041722a1d79be2420390e3413871544e88491727602e4917480d6932b3b40d652fe" },
                { "lv", "83fdc4999e9d3cca4b0194396594a2968ece3738bdaef3d03c53487043508bceed42992b6f7e8345a6cc6dcfc6002d026ff92052a819135c166b941aa76de957" },
                { "mk", "ee10357ce4f1a25b6e57f63cb1f76f5a1e9056779db63e7e486f9820e7781d7cb1a007208179548d0f4c354aeda7a4d576374e83666efab1575b2d9c2d587f01" },
                { "mr", "7a5c47bfd41a70237a8aa95a2f23948f3efd52038e4615a01c0e2b1361538bf9aa390c99b649107aada63fe4770f72d1da57399edc797dc46dbe9f3cd0c6e57f" },
                { "ms", "f2805b0eeac03b4799241050dcad8b5b678393c458dcf9bdfb87f79cedae0a72849ec93125448992fcda4e981f719418430f51e15abcadad1e52f4bffe91856d" },
                { "my", "2b0e67d06c101dba201707d51977d3ffe6ef9a0523d64fe90b015d190f531682e5e05554d1eac78728335658fc935a2302a0b63a6b9f0b5aed53ad035c99bb3f" },
                { "nb-NO", "b2366ae579b5e02cdf4010fdc91e4c2c1ab2cb382ee23139884279b5cc614da5b02617a349c642ca77d0f67a9940d7799625408bcc4300e87448f8c2fecde769" },
                { "ne-NP", "36f0f0f13c5fe6476df0e70e69eabbcc4f66685fe230b3333802488c5b895a0c47bba4ab2192a489805edd847258e029ffbf6dcbbefa214dde867c7ef502ddb3" },
                { "nl", "ea1b92cbb37c446b982721f1a84fc07ba79d561daad56abeda705cb9c281adb9618d612a518e5851b84fe6af829d1ad2761e800b2912a6b589d6161afe5e9272" },
                { "nn-NO", "929ad0d5b44569e546e9ea24401d405901f5f2b82cbb3a5686deb1c4187de9e0ed2c20585a5b61f0ed25f3c35188043b187c33b42b2864764c31268eb13c86f7" },
                { "oc", "69dba67348ffb7f43c4ba84718e3b42d86098efc3aea5c41ef2139a178ecaba012b65470f33516e44db2a77e53fb3fdaae3de392f359523777df8a259359dbb9" },
                { "pa-IN", "41ca602e1d4f04692e8338ede233a6578c6da1e6f9eb8dcbd4de1321773694b595b5cb41240794dd2bbd92adc1ab191c3580b0635cc8630a3bbfe4e9adf5b8d2" },
                { "pl", "9ab7692b72e4970c9279bd2aeac06c2154a9fea89a62fdea927c7d79562c79a5b7987836ad3f6ebd631f779320c78e6113ef3cbbfd15f9a8014cfc71c191ce00" },
                { "pt-BR", "b54df38d58e2198a771217a5c135c7b8e045c0920ed64f64be35dbc1239731a920a737a2f49565a5dbf6d84548cc5ae3f1b7b4a42580021fb12f32beab7cc934" },
                { "pt-PT", "4542b3b973c1e67c33ddba4fe6d705be83083789ea559b836e0ca5fd55edca89e7cbf197bd7bb1982a4fffd4d9e988a7a095b2cc32c6ee91a1c7b4d061b2306c" },
                { "rm", "0a1a5627f47b8c4fae9cf7c4f041371a907860e77c3ef487792bafc8aca380427059dc6da147ddb024222bd6e8af594eefb60fff80cfaf4f4b865829e17dcf1c" },
                { "ro", "4725f5f8de8d3d83661c3cf1e860960439ec675a5e4298248d6bdb64b067d109f1d8ca11ab523e957c523194847cf76ebb48ac6557357f1e64d4dcbd8274d1a0" },
                { "ru", "90cb4781d7e505f4a8fddd1d31418fb8587e1781eb45f66c3675b7be4adc25c3933810320a99147a3c5ed22d2a526e3f633e4ac163451c34154781ab2f94733b" },
                { "sat", "93194681a0ef9ccb2b2b21e3e2e1aee01376549c32ba3180c28657f40897af85e73a11407cfbc6d748d86f1555c8adec8b2bce4fa4fbdaee6cf259e2154c0057" },
                { "sc", "b679098abc4e5ffab3b17f35835ba3c4abd82135d6906d593388c3a65e8f3e48d536e501cce5091538b4526d34e48619dbb85a131c10bf1ef8a88b39a7822c70" },
                { "sco", "ae188011688a357eb1bc3646118ded14f9ed3b11784fe988a09d463db1a66edb0160cfe7762b07830526ae46512f01d130d202a3085716199946783534aa61a2" },
                { "si", "20c44ecfd8b99e1aa2a1941eaee7321f1514c3a070eb0b5f8edc6f07de14a743b6e57a313e814de7a8f4ddbf63defe9778f0fc9aa61433c715c3e04e69167d29" },
                { "sk", "35e75e4b8b3f9562d279ccadbe029b14aa6ea6dc0eb41f3573497e3c75d2f1ff15abc9e77fcc0cabfc0726e9915d0a0884d5c8101a6fbf5612e65558a36429b8" },
                { "skr", "fd950912c4b073ceb1ef53444c4daaa90ad27a79710a55b250a56aaaa57470c1583ea0aa626a68a5f1e41bbb2aad01c323c1f1ba1295c309fee39eda6ac2596f" },
                { "sl", "a47134ca71cb2f4da5bcf0a892f4f203d889ff42d2b54012048f243d541334063b6127d1d965c2c55e0adbcc523af75b5d6164433d922003f71eaa0a6f88a972" },
                { "son", "65cc917f799f20016995929b2a2ab34802296ff6998653d5fe67a60eeaeb41a7e25005ba1211f1047c6f4e8957d2f258acd0e4172e48027f03bdb02385540e36" },
                { "sq", "a8022f9d891b768a2249e220e0088128368aaa9ce3ec404a92c4b5f40ee534bf85e3ae9d10ad88462ac7653019cf2785579bc381c81b034169da458be480dbf8" },
                { "sr", "cbbadc65a386517da6943cde0c48ea3355a8e1a232ec15ad3ad39539b12453acb188463be5bd04c6239fca7addaa126c464fbc15eb3eb6f51a8d62fe4d055268" },
                { "sv-SE", "b042e9c62a94803d2ca5e08e19318a80dbae68e70702c12e21d2e6090049275b5714d2bfdc5e77cc0fe7a4cabe86ed07e07fb804e4368f4629730e80d562fb8c" },
                { "szl", "d55566e3676d283a1b587cf049bffcbf7739f66e879779b4a0923ccfb47da5f59b4bf9098fb0772b67bcd0aedccc9a03b11be45d21f59a4d6a8a8f7238c0a8f4" },
                { "ta", "397b9d19e702d4ca3d2a8c2d5acfb2083caf86d4d674a4b7cb6a6fedde0d01112b144b93e2401e6913f052e53f5528dfc14c14858c0bba9b273c7e75310dcf17" },
                { "te", "de9ca69253c6fc1d6c4ba594bdbdbdfd359c9a2d490be557a57ac88bce75eadf8623bf7c73d0b864b9217a25c3a1a3e074bae470ed327e0ce86cec303d7f5b2e" },
                { "tg", "f4d388f52299419fb77261884a2635cc633934769bf5bbb509c5206d4039ca2084d5903e0a7e716cfc26b5197911b75a581f0779ad3ff279d540726b31bcf8ea" },
                { "th", "a168cfe5b13b85b315e75bbcf3c0e732a3f65ba1bee9a4f7ef76fe3cb31c76edfbeb31275e0eb3ef106d0f42ead4cbb9bd1a05e2df956ec6657f08eef2fc11e1" },
                { "tl", "0e779f4e1a6b869ac743b10994243d17d0aa95689cb78986569614e3517793801064b6abeebccc9910b85619d927294e6f5a2c7f41c48a143eb516773c7697e4" },
                { "tr", "f808dd110885916e2b19c3602a8dfc9779c242dc9001daa25d5bb23a33947f160ffd02e50596f5ece452aa8e3b2bcf1a11f122c1bf66a37b1dfa10c1082aa08a" },
                { "trs", "1c73eeeab51a7a3c24747cbf7330b124119046e4abd6b3ff180a9b0c089dc5f2d5224b4d2a8758e5abb5a48d9aefa8532296308ee52bfe9b8295cf772ef53167" },
                { "uk", "7ea0665d9c6e1b9ef25f7e0d345883a784a16890566cc51764b8d10353ddb148ffd10c74e9585132a07f26663fff8e2b60eb46fc7f896eabba0e824950dd52c2" },
                { "ur", "58c983e1df0a29dbebeabefeb1502147deed3cfeaf86c0f90077bbadcddfdcfbcb7b26037e8c5a3d31cb27813b2bf304417955bf508970533d2054d68c41c184" },
                { "uz", "070fe0b5d01ba7a36284cd66792d5d40524b42313cb20662f8174927eee9046c212cd0ab541803663c0d6cd756a18af31674880dd741d8dcb56b00b089aec976" },
                { "vi", "d98eb3915a2626f5e1649b24e54747b432fca57e335bdbc7c1005369d401fcd5c7896e929bfc9c2167d0fd7f7e6855e3f1e45daa2d1bb3887ff690c40055a343" },
                { "xh", "e01703c49ebc212292c0dcf8afcbddd8abde905752d9c3c85a7f4edacab0a897bfc9b0ff7e9069ec369167f50232c28d5bc52d68f56690636665e69155f002d3" },
                { "zh-CN", "5bf9cd3b79d04a55546cca1fb2113448b2d59cca4cf3c7610999f924e112813cc67a8a0dc3fed13a2631616d983b964272fb0314d96bb86e44aeffc8c688ec41" },
                { "zh-TW", "dd0a44e53f91ef69e8109d980a9fe4f7dd3c6796f9a15b6e9dc27710c503e0d6fe33c7e8847b0b0d1b1d2277f2a7563b42e34202ed06f6642d917869db41f1ac" }
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
            const string knownVersion = "150.0";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
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
            return ["firefox", "firefox-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
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
                response = null;
                client = null;
                var reVersion = new Regex("[0-9]{2,3}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox version: " + ex.Message);
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
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            logger.Info("Searching for newer version of Firefox...");
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
                // failure occurred
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
