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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 20, 0, 0, 0, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
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
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.8.1/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "c5cc30cf14757a7bd07f66397ce66f1952c2b1a695fd037cf8ec72f7af3a22ca1a05384fba71dd2ca75c02c68bcf2cfb07879a65dab39b86336d941a3169ae5b" },
                { "ar", "7047fb6db44a055286ec6d2dd3185c1ed840879e9dc08b126507dc36819618442c3ce08507eaaddaf16151a8419b20b55138275069957b24eae8f1818155a4ec" },
                { "ast", "397f8008771d822b0af26b4e143171210274e99e8e9b7d1d0023ab74191d80c1fdca35edf131b5d89e54b2f1790caa4d2b38de51aa5cd9b3f0349cb3b4b5ce1b" },
                { "be", "c6ee40ea9a33304a2624bfa65452bb4b0973a5eaa27dbede7fe57c8704808bc64e07091d55218dbde9e821c4c8c694e49b5afe069b565777ca132446de175918" },
                { "bg", "53961cae5757f7857c1411e5b80675df4141c9236ab76882f7964ef5211900992370fb158455aa260c851d671f261abdf18c7b433145f910d8e50419fbe89042" },
                { "br", "56e173fcdb542017df85fd800a58d244e769b8205ea89167c0829c62f368a1cbfd3829de12b22cc1f6d85d07c7242936381b11883f5cf67fdd541085a8fe91c2" },
                { "ca", "8d3704e240437cbc9029ed2e6f559416a719d3f5c418301b7130426eacfa74b6a0c2d7832bb3ee54bb4b8bf47ddc33f8d584b5871c964d1ef80b86600dea440c" },
                { "cak", "cbd470d8c9ad0ce7756b251b964d4cde73a34ef0f18b22bf2858653383a324e6fc98c813569ac29964264448b4b4949270c6fc97b7220bf51bc39020cf8e54e2" },
                { "cs", "606f708e7438e6e38ea7417b7a51fc796169f76a2fc8c3abbeefcefd74c3834898b3c274c49e7640218bbb5ae674b3e2748de1c95f78c66d013f23023dd5accf" },
                { "cy", "314c122fc8715762c7f6bef01864b4a0ba64bd09dcabfb8613422940d61b7467a4d06cb35a434aad1cb766a3689948f5b3e18e0393274157b3b612d6d5de8283" },
                { "da", "897f8e444a84d97845a6964e0bf8fa4635e86ae5d3f5e8e4df4a413a8588e9c992e8cd5140bd25a7e1f82627a82eff73e7496346127a77c4e9c4fdefbd6f154d" },
                { "de", "659faae3803da71df4d2e7ada8469eea4c6575cce84517ecc8b736bf8817cffadfde7a2b13e44d4699c1364b63970a4a03c4b5b154614ce38fbe830f177a302c" },
                { "dsb", "d4e47a45cf9167d8b3477d11209373f4aaa0bac20d92dbd7b6bb14108e70919d98c237d7d24a4eba443bb7954da94498d22e6685dd8aaa731763f0f1802faa94" },
                { "el", "e5914675b4aa2e5de5e0672a0137a82c601b1777cad043014580d8436927237b95d3d4efaba914fae0ac1499e5a5c435712a0bf399a64611c0e02683ad3e2d3b" },
                { "en-CA", "2d8888dd6c0d9bebc688196bd2b6344d68fbcf0e7c17cf4703b69473de9651f18e3b7e8a4a86811847cf0dbd34f87d64459efbd282268a1e51138c150d2f9df1" },
                { "en-GB", "f1e85fbf46c359b9e084fa4882b081ef1ac6276eb85cc9bb65cfbfd3e28dd0b3879096f159dab2c64e2755c0e34d4d154db2dbeb770be30488f4fa5e082e9766" },
                { "en-US", "27dd8d7fc47a829d9f9ee0b076f6e238e780737e3a53157393cf7cd46de27a4debdb3aa126a8193108c1fbf6e95db41db71f4011238ac0366bea5f8dd6bb36ef" },
                { "es-AR", "a5fcd3d2cc7eafd35906baad934dcf22640acc33a283b6bf0e8d2a55dcab060535ea4fc078d6499eb674cf08d8cffb77682dfff53c62903f24aa531a15444a3e" },
                { "es-ES", "b49175d99ac0d47226e15e72edec549c76c5c17a1105c0d80af5f0c09930bc6794b71b3fa856b050bb38a29ef94f4cbbd0404999c49701fa4a2e62d6ecfbb31f" },
                { "es-MX", "e08b25605f7b692f3d862845c7e2458e9db95ee1433e99fbbd23683f60d18f9883befce30a59eee6a2355f605d5681c9c2cbdbfaff6c556989c63fbb19be57f3" },
                { "et", "a242699fad852ba01743812820021fdfa1697a62e9fc53e57b3e1b45fa2598c4439eefb7e66903abf90c41afb14c3f42274c74408d4c70cf921bb2beac05af75" },
                { "eu", "8634468f00f62ea5b4cabec1e49ef0598b41d512e1ad836e3c0baa8c6995b8fe9ff538d4be65f5a273576a3076b0a37a32d8a57e6d9730499bfcbb0fcf0ce9fe" },
                { "fi", "c4b04999cbbf61a6bb8f8c6676f77f146cfa91dc8c5ebe73f5d4b0fb73095ffab447fe3f46a2ae6989ed9b412648cdbe213b9d1966572bd9b7a729a9b05a3038" },
                { "fr", "783fa54b7c9330b7b8683c8684c4aff9cd2d95ef9b9178f179295d526df99d45075c695395dc5e810f81b1b31d6dc4da5464ea1530f5f114ec5ee46b70ceb0e1" },
                { "fy-NL", "1887494a621e2c1900c89593fa138f7d1b0ba37f824449385b6ce5440172d921533e058ec585f2f85a6de9e580e52eb4230983e6b0d9f1e3a4fac9e45c8d3030" },
                { "ga-IE", "8bd39692d2827ef63a80a2f772860c70dfec160b4a64a0b48f606283ed17567b707d9e4d77909932b1018421730851c09a99e76eb6fb5f6ef9badabaf312dbb5" },
                { "gd", "5d9515c72b9209bd94913fda2e3120cbdfdb9e946633dc2878e9718f83c37fe427fccb9fa982cdb0912c7fe66328cdcc69cc4e4d9e122b55963c82f32dbd0d6c" },
                { "gl", "8c01e9ac785aaee2c05a3186774e835fcb225ad29f25f118326f6e597f6dc7e87d6937ad9fe19f145151fcfcfee42c8e449479d9a1e8ec436afa42885ebc5fee" },
                { "he", "8efde4a8a78e93b45789ad4af3c239fe5d2c5f17a6a9dfb8e9ada823eb19d8629aa2de7f68a72e5117ff50aeccc7249675ffd389f4bc68bd7a8f66cee999737b" },
                { "hr", "35abc05104d702d4f635108e0fd4b23999f68a31c406c3a5c61ac17730dfd3593acef4fdf03f749e222fe8276ae0e99a92a82f92643602b7d621c94f2d636000" },
                { "hsb", "f7ae63de3238ef41e9f4242b5d98c145f4a872695103d960e98f9a22bef9963aaf367512e7df2ac69a184a46fe03060bab692c3a6d0512de40fca5a549df1c9c" },
                { "hu", "3e5eb02a18ed4cd82e831c7e6150169c3b68830cf7f80a851774a4272f023d61c8976fa3406797924d862a66038106eb42e00133fd4a7382aebf84c0c8246b03" },
                { "hy-AM", "20a8e00b4394cd7e852d0eb836eea43f093b78016ecf3465c47c96393ea12daf800fa26dd5caf80ad582136795df444db488069e1b6a4e7ad0a9d8568322cdfc" },
                { "id", "edc5204a932336b319eaec4fc92f0066ba9b7db54758542aaec5017cab487852db2620bff64e2e617a2cd9e25fcd57b7716330a4261ada75e20762fa6229b796" },
                { "is", "66f7bdabb06ecdef8b95c5601ccce364ff6e770c5d438e6ed2a3631dd9741017363c315bc5cc59516292e5c86f145f0cf7a75a9384303f3c295b0187d677951e" },
                { "it", "e4d681d5661522f9e9c5fc47635a8958a5c4842224e5b8fa7679ba397525c01615b10075bf8be2fdcead02f4538cf02679ada0e278795a5425ee209c23c08445" },
                { "ja", "cf411535c56e0a03e7cd21efe88a385772ebbe32409e030ca9b96a6fdd748adc8a4642f8948ffd679101992249de9c2a81c2c36ee2b00cd2e89ecfcbb6878df4" },
                { "ka", "33872b22c116fda3f3c519915cc58a74593f15c6006227f3e776af9ac7f91d3bc99dfa97a8f86828236846bf31ff8187b59aa21f8b4ed72e27dceebe1bbad3cd" },
                { "kab", "f09a5e79059b5a6d2fb868b104413bbc4126289b091f0983ab6eaedb32bd65a62619fda5a6c06c0e5fa4b0893a4c7c3c8975911081017accf7a0d9cbfd05fbf2" },
                { "kk", "3e7b2194b84d99df7eff09cb345e564a97d5c047c370047516054fadd8f83f31dc82895c03c15dae12e8f82412b28c47f695f9aea09525bbada07c12ff662080" },
                { "ko", "bd93d21ba6bcbcb96e928431f140cce283c26a56ce4b71d2f132a868b17c1a8cde81fb77a99598a914c2fef71ce68b3560c14d0b47187733f8cdd85e1485cc33" },
                { "lt", "281b8d6bbb5ffb260775188bb9cbd505a9edbef03599c06eac05019b61e64db949302e41c1e2566f26d52b02eb613db80321d095eb24b4ce415ea730bc24982d" },
                { "lv", "0e140be45ac7bf85c637e585570b5957852057a94abce755e6f3fb806bab9e952e57c1af41815d6b6e75f944c54bf4752eedd98ac316d9fff7f028fa11ea01bc" },
                { "ms", "ef20d09e5d6d715bf00e8851d35dbce9e43ec13954d912dcf670f4d1f523b652eec10c4d71342ae49ea3113304350d4e63d706fdb23fe0c4603f6fb4ba2e491d" },
                { "nb-NO", "8d704307413bd341cd3ae3d7151eaddc9429a1e2a736405709fd280e0d278d2ac4186b0946bd6a9d87eb67c66de563af96e7776918094e47d15ee7afa213a5f7" },
                { "nl", "6c8820859d7d8501ff063fd0483b64acf63a061002b4e807f2553a8c7cc1b4cb84abaeea352f8d5a2c0fa212f2ed6a7c73efe42675d9763dac797f984939b3cf" },
                { "nn-NO", "ae37bfbf3e4a705f3ca22319b9085548c0de2238111fb84817a62ff69faac406bc2158496b30c70574e975faf51cb8064e457397e2090e2570b6176f6fcc99b4" },
                { "pa-IN", "6346050ff4ce5dc2c08d766ecaf20a18b0d13bcaf10b99e2793be7c97aa207fa801472b6dfdd6b7101a71193d392a609709ba16a1b616bff7103c16b91c8243f" },
                { "pl", "4275aaffa871f1d1ae420607e33152fb1d2712d1a1f6e5cd13373ad572a598c1d719370b147626afb4af6e77f136f796cf1e177c01dd1f478b1b2bca071ce5b3" },
                { "pt-BR", "2b701e1b4000c7de6696bf56cccd08b2b5ce9432654ce8ccccb4c3a36c6eb4daa7c97a5848430002a969948bf6b6c9852c4effe2fe9616aeee82e55baccb1bf4" },
                { "pt-PT", "b3cba424798e96393c59bc69360726e9b4ad1105930633fa12f3028ecdc8163befdd50ee8d143fc4053899041490f58c8cfee11386d3331f0693f8bdcf3ca917" },
                { "rm", "aab5e42fcc85d19411ced14b39bfab9d1ad67b11ca68f0bfb45423a8add320fd258f224112291ae54923b9c0efbb54721e975ef79149d921ecf5cb660a3fb80e" },
                { "ro", "5a7517b33a7dd7a937a4bd1fc67d128220fc190a8666c5ddbb4154fb5100f6216299e97cfbd57262069fc59f8f73a0715cfbfea0dd0d43f00f7b87f00ebe2434" },
                { "ru", "6c44d0399283dd04db6bd7b847c18924e8c446edb1b25b7d4fe7291889843df45298d942449a61acc89767fa71564ae1ef3f0cec98c15a92e9408acaff3d3cb2" },
                { "sk", "a6315259000d2ff4f06d2f6e728f3c764ad3e39d33f5fd480727ba9cb491b77ecec9770c887923b95ea57839c7c4896f59ca488e91e48a79524f22fe880246c9" },
                { "sl", "4dbe01a292ea52332c9dab414f43b32fcdd533cddb1467193d1962c384f36eb49e2e283ae2855425b21dd30e675072d5bc5db66176007c59164a936ca23f3428" },
                { "sq", "61ffdb669a176637ae0d789357ce518a249c95595249a16b5f7e1a2230312b41a2e579de0d892fde50ca81fbc15a8044a50d2797f967415dbc6c91d915775c63" },
                { "sr", "9be1b87a7e8f75cdb31316a3be126c94e9510ba2ae647b58a22c7ee268dd8e3f1100e538a69befe1059a09926ce0c3f1de13bc9653bcdbf31762062075bf075a" },
                { "sv-SE", "e5dd259a36a64b87e2c32f719c40c6979a9f1c566fc607171353e5c02d575ddd1fb65de8957d85a2d3ac4dba070c5171b281e30812faae1764a92a0ed6d718d8" },
                { "th", "91c9b8e6edbe53e3d2f7fa8295f7922d5204c8944fd55d2a7ac221d8e70d9ae36470666e7600e2440735bb31b64c868339831b8da69e9f75f82157af32f5a2f3" },
                { "tr", "3b725b47bcb08d78ed0808d699c5601aaaf411388aa7e0d759aff2f870da92122521937d3cd857259a6c56c895698327f1320c909a7b11ab68ef8bced78b2b3f" },
                { "uk", "5a4da1a70a58dfc17220aa477daf45d4bb29bb3f0870baf8926cb08a098cf21c441f2ed6ac007fdc1fe1d63b091dbcaa518ca9d7e880a928d698849c7ec63b0b" },
                { "uz", "f6f6c47f4085e09bb42ddb9eb40a3c04e1bd38e32f39d6a55480d48c08b5a2e76366e2f2b9449cf0d1353117cf8d71d3b1365c0ac737a36b5e1288f8a86ec506" },
                { "vi", "0649476c787a1b76ea6283aba2e8da82cac1afce4d7d4193de281a3fc04533369b7e56e0012b1cec57582ee3ae3f2f82f13b4a77d47a3ff318fe08d176ff065d" },
                { "zh-CN", "d4d2efcffa933c5227c154992d79f99e24ccf5ee20b2a75f14fcd905ce61e016fb0f5a1aaff6f36e15e2fc8fef06d6c50e4d9a06b61dd0645f59a20a74689180" },
                { "zh-TW", "375d8155377ed38fcd67a964491e8c3000574e876f25936048be08a9eae36e4c45f2afb37e8c423caed13f81f7e5fcdf961a8f9b084b5f70357b74328292df88" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.8.1/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "6cd08631f7155feca45260d8ff9ed1144e4ef9a1a513ae902dd0397674bede9e7733ea01fa1c912954b6daba6a63a315daf2e36f13fb76eef86902aa6c7e4deb" },
                { "ar", "4fcf2fcf73fceb2cc2ddadc60a71f040d5ec2d3d2982fecb365533a2a0f99dff19e1d6aaa3fc2096a9bc511310f71f8fbc79862bff2a018725492ce1017bc68d" },
                { "ast", "1692e2d6328f71b75d156df13844767aaf7387207c425101f101910252bd20b22aaea204cbfbfec567059caaa29809919381fe8aa50d1ac168baad567f9c370c" },
                { "be", "ed9770b0d478dcbb010008893509c5bfd4bfa363e8fd61e4b2ecfe5fc647f32cb3663d70964417095d03581bffe31be894c827f587c089d69359a766f6ddf0a0" },
                { "bg", "0872d72ee17db7b54702c19b4734401fdd0683611f5d75ae09f1737584fa25978d347d48b661bc51c984a22e4d94f2b73ab493af4f9c037afde84060f459aa3a" },
                { "br", "81d70c4549eac6fc2e4a967a99dc5ecda5391b0cc0cfd40e22c753f27c74f03d1278ef7dda73325b15bcb5d649512c38333eab7351382a508c7e6dbffd117bcb" },
                { "ca", "2186266a63fde10629c45da2f94b6e806e973df7cbc59c26c3f2150e47e67e60793a61657ab130ddf1832ff56d52dc1cf8ae0295c9e07335750895ceb613e405" },
                { "cak", "f069cc799a7274c7f368ac5a422ba2d042d2c8f7ca85f816f3abf8385263a5400049683f34ecdea35217c1a6565c0fab18cee4229e86a9d52b06ae0068f37336" },
                { "cs", "3885b0daabede4e85666fa3f6a66531516a3322929ffdd63e6a3e4f02b6b2bd84ca03d33edac524a4c7db072e7950cada3253236e060abcc82252f30078f98eb" },
                { "cy", "ace2c83a89c464de8a6818475681196f08c8bcf03409dac322bfcf83d90a42345de3d7d6082261cff0228d6aa09ec16e50cbfd701ed9896087deb78ee9a36fc6" },
                { "da", "0bf91bcbec9cef79b12cebfc7fe8ea952d49a5fcf9a932be41d2e20098e56aac974756ab087cdc31afd259659d58c9b9b70d91f827599d640946e672674ea475" },
                { "de", "34bdae32a86aa50d54da6f6115391120fcbc9bd9ec9c9e88636f335f6b1885864bf8afad0a897670794ff588edf00c7eaf6291bbf6a0568dd5faf2a5b859b93f" },
                { "dsb", "f745fc1d58ac89753b7866e7f352b6062c0884d7a96a4765ca781908fea2c705211aa1d6f5b7e59f2cc44d8445107ccee0c8d0e25089bb8b2f198ba10770a5c3" },
                { "el", "3f02aadfa495293625df564ecf68eeeb55cf93228e470dbbcebec4e63edc57d85bd846e8c7c7cdd912ae563dca9f6064474867cc7a5092392765a54bb35a327f" },
                { "en-CA", "2bfdb23037bb6b2ef94ebca3a47dcf64cc2c9bbc622961afd2f223d6c654e97a98e3818b88a329c8815fcdd51c486c67ae3f868e831359a1ea614af1b4a26ef2" },
                { "en-GB", "a8763f26ce4a5eb8bcd1b8449504959236de1925ff3afed4d7b91c0124179e3eec5523bee83ab016d58a0b23e7cba8e4f96c3f77b1ba7a0e26fbc18d88195754" },
                { "en-US", "9cf0c8fef684fb2981f1b476d6fb6c5a8af77b60104c9583c7a24fe6c2e294704bc44f3fee279c6a8898507c54b444b44fe4728a4fb331fa6093e321a05afd63" },
                { "es-AR", "cb01831e53044a5ee27eb4579b48224fd413dcffd4c3955ccadf9d0c76ed27042c8485c009e1cb675961b4c52b0002a86eb58e278ab378762c54e84f573aca86" },
                { "es-ES", "3384d0074ffd83c2c3a32a98baace14a094c986c101ca30e00fd2101a3d304af9dc8212ebca9fe1d1f7315f9fb5b9fb5b79174e43be6c861f5c7249ab2f47f93" },
                { "es-MX", "4eadbe2c04a99f2755240e7c30e2eb096e107eb0307b8f9a36ecb53ebabd0fa326e72fc5d93cfa93cfbc34aa7aba83c5682771cac8e0c8a5ffb63332fc347c91" },
                { "et", "c936c4b1b13a82e4b8560fa34c215189591e3da102fc7b6d90be37eddad3e9e4a87ad377c0f6c9e597c42a52c8e231b8db20297cd25e0bb8c003eee61904e15e" },
                { "eu", "fbb9059cebcc20eead24d6a26d4df5ebfd43af00c26fa6ea1c3b463617881792b82cb13e8d46df56eb68aab15638aa8ac3f6a65d96adb5b928bd714b6f615b8e" },
                { "fi", "5452c63564674b807da249505bb75e447b46e6d4ff8939595247813edd8545ae50b206f60b6756039c7bcf873aa0256e9f9b9bf77c12121c674a2ea4f1ff6f6e" },
                { "fr", "2222a74d1e28c281b0364008873b0158ee5eeb8c3abbf9e3d7081e4f8a8b363d6a68c4e98896f0be62863333b3b03f9d355e2334a95739977f899f009a809c7b" },
                { "fy-NL", "a1f8f38448478de0526fe8e90ab399a6a9b9e4330381602c4351f961fe6a103b72440cd47bbd4de453b61c93cb72cbc5fd2912f5c7fa12b00c470950b538dfeb" },
                { "ga-IE", "b925141b899392719ccfc11bac23a7ecb993e19296cff2b2b2b229bf5079e93bc3227fb0585a878010ecc9527fb805241664bf85564c92e0d3c9d72688c33452" },
                { "gd", "b2462cc2dad5709b54be1b155aa45ad3a9c52b6222b1d50f5eb39364ee75e733c8ba2a397b72f5c64970f2b4d3ac7eefe38c2b6492cc73d97e6b0c7e098bceaf" },
                { "gl", "a02edb57fe9745058dadf92d86a3904ee9ab338cb012b5c1c1b5a4323c14d2296c1aaaa395eee0d370484a48a411be42cc2f7bfe4c0a6086ab1b0cf537d3ebff" },
                { "he", "294311b6a70d42484a4e7b1a14732ab4274d491ed4231cc8c83b22156d32a47b23f3a5455e1c6f8c2858d49c505d8746504c3c006c7b251ed965a0e5424313b3" },
                { "hr", "f082bc4a58f95aa456c78141200fe0cde3e40502e9c5d7080aa1d1f6bb48ba842fb26b857cca84f3f1117d736bb934fa764c78269426a8103d31b14c36d47c2d" },
                { "hsb", "1a52749cc9f6e0fe450d64bf0d2a84f98f654656dc04d323bdea2b06638e4bd7faf5ead446b66306c7f9690cc6d9cdecf78904f95fcd68924bf22f8b873d017c" },
                { "hu", "1af8d02a7e8a4dc1156eca3ddc354fbeb384f2dfd74b5c9dbe096548023b17757ac328923659e2179da5252a6ef2f91dfd17cbddb73ed097e64c5d83b66bbe80" },
                { "hy-AM", "bab8d81a05072d8cac25bafb22066403d6860fac3a3512f867dd7d98a8a8ca53157604560a90892179c5bb0154e9cd01a06fbce0fa652b9448fe5d3dcf08da7f" },
                { "id", "9fbd799acc8c9b78d3e9917d22ddee6101077185631dc3ed593c77517e4ff7a9ae5535b2d24578ef346516831891d55bc1ced8d028789a57b02cb1efadced76d" },
                { "is", "6bc6a7614e4e2dbe4020d027bb0d17beceac7daee0f46c407636e64d243b6efe0175b2346b20ab44195b6c98572fc20068a2ec1783d9eeda3fa2f35faa376cb0" },
                { "it", "c0254964b6e46dd00b88533a81b2c030b8f23b798a55a205a273f5ff1dbc3d66ccea8d981611bf1de42d09dfed162131e71bfcac9fcad62028c2b5c4cccc5f1b" },
                { "ja", "cf1dcad8ad1b2e1b1ca626ff516025ba10a2a3859c7d83bdf5650a7d5e0946d9f581e6b41d63316efbd0beb5f1f1be845dedb9a6b39754ffd66d1f6ce242f4d0" },
                { "ka", "29acca58e2c36cf3b660d312deb586e9ff6bde8f202e655c58277bfbe74c73773649b20056598f1d862ae986ea28c6e01ab788386ce27c7122307be26aa3aafe" },
                { "kab", "9fc47596ef2bd85bcd5285189429142f2e2624867db3489e04ac7fc01abfe9f5e9284d320801549556447a42c9901584efd50c9276ca3117cfe7965b94dcbfac" },
                { "kk", "0a10c0f33da5a25287949002013786b3858150e9e971359ca7987403f5fc4669b8b69b5dc4de09311c388dd2f8031bfde1eedbb1d2f04cfd9a688200b10e9cc5" },
                { "ko", "753a6dac8c79c919c297c00298d64922434434605013004349081c4532e0155f9d57b3e41aa03865473a85d0db5798d9723b0212d67244b4fe2718814b0e784f" },
                { "lt", "118cec3642082a18bdfd62654dbc1c4edd6a9be579e9d22481077bd062c3a832d8eb04a6f505d259fc425b50b905aed35cfdfa533393ab912a3679a50e061410" },
                { "lv", "0ded042f5b1c4a40ac11b0600e4e71d281bec96d6dd7f604ffbebe892641f4a9ee310f0668e4e492ac3f985e5569be772eeaee1bcce492668e352b122e2e5b09" },
                { "ms", "70309d5dfb54e91a7ad2b40996f21402848e2806a852947e9f25c515c95fa9685c5e83b4c4179e27ff1c0227c860e08aee67b3cc59d8ec912b0bb89287332b70" },
                { "nb-NO", "706551967705a317d28cf1a8cfa1c46d88be1a1cb35b9452ec43da47153eb52738673bc5b5371330a7a6183ec10acd0756ed1f28357e9fcb22dcf9135e10d138" },
                { "nl", "23ba47086018a6015f9e4c53c867ab24248a566c4e8088cd408408878255b494b3f816d8d050e59d80ca2f914ac8a72c566677fbba63840e252342c36d1de070" },
                { "nn-NO", "b70fdcc6cbb7d980390f22309e214e0b8718132b8bdb0e8e3fbe1a31731d6944add9762a486565ef15662b58ce7a9e5467135a77c64dc9578c38236666655dfe" },
                { "pa-IN", "987d676dce8903d61f6f427d358fe4df321e357080a12ea73bc0af40c39985e1e0a65a5fd33d26047375121426534bdc64ff89f228fd61c158f789f93eccf862" },
                { "pl", "a7edfcf8b5cbc560d4630673bcbcac1389e3f45b5f5469efb48ea1331e1a4812ed1db2d171258c7ef90bd7d13fcc020c39b112377c1b3f9e0052c3857bd9f48f" },
                { "pt-BR", "e21f7b72af4155544b1259d95495e9c88b641403c853a0df365814278c42e1d08f74c9cfe70e1285a3e752cf0918aa737b6101d2e7741162a29c8e216d9db4a0" },
                { "pt-PT", "bc935a865ed53f4edbe2ffe12ebf3a882747ae22c1b96d743933ec41a4ad82247a92843591cfd280f488ca40a5aad76de93dcd9c22af70e2939b884c1aadd31e" },
                { "rm", "f036e26d47f2cf0ef8dfefecdf77f26f83646d1902363a22511d6dcdd26192c42763359aef862d5e3f57894512f7b733b82b6e79d54c2965edeec775dd1f5d0d" },
                { "ro", "9adae8a2cc40d85e9c4ba3afdba959384c6eff974ac8b0b0b1649088bf8f42d7ec79d4f86e82f801f41036a7aa63fc9481d56bf049b495250bc74768b90a8b99" },
                { "ru", "5724f1b687cf1160486649c32d486c08e36c383e69a6bc2ba3650f864807bf6a9beb376bbc49c03acb343fad896d406fe8003900992844c9044e3c5db5425467" },
                { "sk", "eab021b4b67b52520371adb9da6eabaecda08ffb18a48aeb7514585bcc9d3e83c3be1f2beeb18741d514b5437f651f48a4b0dd814f9de947362cde0b50315d57" },
                { "sl", "45a2db3767bee2ba216145a15980a34cac4366d1eb6ff120e6bc037051f99a53ad4a697c39603b56b2ba0eb937e2adeabdf777404adf8a714db77bbfafcd2802" },
                { "sq", "e1b72b51fc9700628ccd720ca865df8f08387cd7f5c0d26a28490bfddf006d76befd88e95d05e0882ab5fcef6efe88f26e63b281a65d495a79d5768fd0b38828" },
                { "sr", "f30999abd3e1baea741eb9c178c30eb2d06924dea98ccd7cd67cda44ca31300ced576779338a5d3f547a51004d23d9be079ce6657c1903609c4616588251aaa8" },
                { "sv-SE", "ae8a15f3c4dcbe69dc9134da223e44c5fb10953e07387a27e00e2f937889414c03029549708c18e7cc4ac5ab77d9f79e31b63528efa7ac6003bcead50235122d" },
                { "th", "c912c0d5c61922e6eb51c34b274f27e11dfd7caeb17dd22cf125986101251c852f03bede0d936f036abdce434a522d8263179bd85b1a867cc4ff6f2ae9b9bd06" },
                { "tr", "ab9e514cf5e486ea2bb73ecb5956ad413a0532a499fd810547c258d11e7a3bf373026bb93a62d64e302c03d1c8dc2ba82604b65d6a3115ffa567a5b61744d25b" },
                { "uk", "9ef46fbc3372d71e984b5f2adafab696872146211c1be428e38fff275f0ef1b131b75c407e706968d9dfcdd958cb0a1a065d5af6eede6695f798b9753b6ea1c5" },
                { "uz", "6131a1cca6e22491cb0f1def56348657a4eec3160528301ceea5366f33a0c79b7e802022ffe3a5c5d729e3d1f1450b75ce51295bf69fef16c7720b3cfa6e08d3" },
                { "vi", "944ede850d4b6209e5a99943741e06a013bce574c0a6aa5c5368b12f9496a6bfc2e1a7d814aadd9a53c779d3d3750af4072755563b39c5b028f0d0ac24101a5e" },
                { "zh-CN", "a3285789749f5608496ad4f8d077d22c681022fb960b41d65e6975820677bb4eb05d7c10509f41a976a0c362af61fa96ca535d684c508d5ab4085149d0963c68" },
                { "zh-TW", "5499f203cb8a82373e656fe67c2ecb1678a8b9561f561a2c8dbfe5aba5d57bc50224e6b5297184e52e889c09c744752d601c0652727f0a02fd09b42e25bab242" }
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
            const string version = "115.8.1";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win64/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
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
            return new string[] { "thunderbird-" + languageCode.ToLower(), "thunderbird" };
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-latest&os=win&lang=" + languageCode;
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
                task = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                
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
             * https://ftp.mozilla.org/pub/thunderbird/releases/78.7.1/SHA512SUMS
             * Common lines look like
             * "69d11924...7eff  win32/en-GB/Thunderbird Setup 45.7.1.exe"
             * for the 32 bit installer, and like
             * "1428e70c...fb3c  win64/en-GB/Thunderbird Setup 78.7.1.exe"
             * for the 64 bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "/SHA512SUMS";
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
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return new string[2] {
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            };
        }


        /// <summary>
        /// Indicates whether or not the method searchForNewer() is implemented.
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
            return new List<string>(1)
            {
                "thunderbird"
            };
        }


        /// <summary>
        /// Determines whether or not a separate process must be run before the update.
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
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
