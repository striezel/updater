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
            // https://ftp.mozilla.org/pub/thunderbird/releases/102.12.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "0ccf63795c04593688d19829adcf6584ead6fb44e424ebc7848dc82d6114fc135f590a341bfa4967df864c1964940ec6e11a4afa96026a9f40ddedb469b38297" },
                { "ar", "765aeb437d3854191c44a2a79039f226d917f7cf14cc15617f1480941c0825ec1471de8f735fb8e394b86f7c246493843079edd2b7442234b079b1c9ff3d943f" },
                { "ast", "c4ce942a1a65c8b6fe089c087f9a057d55c81c85110668c00e7e999ac7f9575908e73d867149c2fbcac91d0eb056ef8d45265d69a10d506f4c0abd85dc76d4d6" },
                { "be", "2a7b2bf143df5b55df7c0dbc6cd4770d9af23c2b83bb1962da03ff4b4b724ed42f66b5c169a582b8bb009d4f0782a5d11b5ad1f32c7657f713aba03bf6d3678e" },
                { "bg", "5874f7dc4fb17b51439df5b1fb28dcc2ebfc64ed1d3e9d0e9f49a94fa1ef8f7755ed58492b9d088b5ead840efcf0450c11ef6437c89e6539faf27595f5703757" },
                { "br", "59fceede87d378230caa3a22c3d8091b74aa8f5c2ee966f45647de545ef1c030f4f8a5610400b87ce0aca073e91eae371f8b55c430edeb5749e943bc39c1243d" },
                { "ca", "2f9a2af989ebb77b008063406c752b3f32dae763e8552ba3915322a16e27260f5c2cc48528e76cf342b396945dd3ddb23fecdde50927217ab4fd60b7f2a588f2" },
                { "cak", "b54190349396e2a675de72754c4728f5bdfd26d5d3ccf1f1e9d91eeba957310ae0dc6c1e79c1673f8e4438b431efb1756c37383d112ab47c5d2ef2b147e16974" },
                { "cs", "deaabf61079812ad2b87d662e86de96ee74131d4e29d95d3cb5de29a8cb70367353744fca678e8d284c80c0a539a65711cec6c5a5db33d6ad659ac10d500547c" },
                { "cy", "c382e20f831c8eca43aa7d9adfcf013f74642083fb21865ba6c9fa9e23b678fef8d84b8454c84d4f965e39197550df3332ba4dc541b7bb5cadbef9b50e373f52" },
                { "da", "285c4bd2ff3ab52bd7c65c2a9ca36f04cdeb59d0943e1c9f49901d435336ad79d82c2df48b5538570f12a16fe92cb547f94e75f4680024fd1b5e6ce1956e904a" },
                { "de", "77a9e1ea0c158dcebcdbac4f89adaab55841c7528d5d698fa24c076cd1f55ed6b3491ee3a2848832add85688aabc7bfc29dce5b20b4dc03aa42d68b135ca98c2" },
                { "dsb", "6255bc34c7db4c3a80480f1823e788b5fd70e7ee13a116e2413c874fa3f1174153e5e732e79cb639552ca64653f96a01a3a3dc4b83a700567bd7e1e04cd51dcc" },
                { "el", "f787fb4f003cea08ab36cf59e2618a621155822183daed61841b540333288c1f16a5aeccc4da470e2d31f34adee9be4da5d757398c9f0b7427f5ef6e50485893" },
                { "en-CA", "a34e685072a290d4bddb367ad1d844cf890d0a2b5094dfd80af710f03b6d78daa73eaa5d95314df77cdc9af2b1a95962ad935874a8d82a2f8e1bcc40c6b16dd0" },
                { "en-GB", "8c2c9e6aedcb1127664b8fa62d8a46e9275bca0cbb23c0f80bef8a2b2023aec39f6c1b090497032cf90d4a203f7c2fd85be6538d9fcd7666189a371d30567751" },
                { "en-US", "0a1ee9c25295aebf50ae0af614307da0ef6e1a27c8e9bec2fcf03587f018103a41cc0a29c62e1b61c7f5756f27aba4d82915b80d9a113e2388a3348486f77007" },
                { "es-AR", "86e8a6727ab1aff12e7c0bfd97da93eca6278d6df749f7daafd074cfba8f7cb6b62a1d1cc6a6ae8895f2e5945a698996b617930bc7eb3680c3f4d7f397bb8142" },
                { "es-ES", "5b6192a4a4ff797364563c36564de01e061d875ada72c84eee8f0ae3aebf677b5f0a9bd7847dd47a9811a5e466b9bd0a47d8b61b4b23324d5534e0aa9e6e8455" },
                { "es-MX", "345bc48abc7610a24bdb63bc1698402d85b9e8c99859e6ba61c812673c98678a5b625721d6d3fd7c719adf922bd94ab18973913c0502b34ce98ecbe024b14d4a" },
                { "et", "4d3d37164e6e53639f2d6b9f18729ff1a8209c6179519a5ae75400864bc1159107be39129bec38c7f7b51effe8edeec70e17070c0c28559bb687bd6ecdeb1847" },
                { "eu", "0a9afe213094d9ed4e92fcd7001d8a546ffdc21cada2475437c2eb43d0bbfa1c5d1b7dbd709086879766611ab798cda99cea03293054a7a7eb0782ff48a98f57" },
                { "fi", "51407eabc07a2841f7272a4be6dd017122cfe35621e305ced5daf600d84f9ce02f3538108ab25ba65c44a01509e0e20aaca73e7477b6b30abafedd20fc08ea1c" },
                { "fr", "884fd555f1d684576a335bd0d0724f67104e66a85f6b763f42a7693c06646128ca3afa6b555d9a7aaa65e83bf32b4b7c3bdc0715f66d183b89a156cf4fb35128" },
                { "fy-NL", "30f74c3a8396bfec0cc91508ccb6d454e62d7896aa9fe202c1f7c940c0b64a709dc6be226522926035794e5b3613389e9aa0b3d6fa4952b72ffc0afad7264663" },
                { "ga-IE", "75373f98967fc019e156a4a0f648a42933a10e2c0a072632157774d529b5dc9360d857ca3fa041ba9697f452442b65ccb646823cbb25b7587ceb3ed8187b18b0" },
                { "gd", "df762b057b6a3ea969d9b93285866264b7eaf118bc891eb8fa0d81b5fd84ff37f1966b25638721cce564358c6c0f2c5f0e35fb9772392cf904958f7bed738964" },
                { "gl", "166fcf8a87bbc38045f39cbfab832d3dc92f9f9439e9da5edd4c05128247dc038a5c6cf77e3ae65bc6dbb950a165c6d77987c56732539cec4103b7838ae4bd56" },
                { "he", "239a6869218ba22d620a6d1c6a1018ada9ce036e2c9a567d73a7d6139a994e72e08dc9f6952881523a6025c415d0a6e67af4ddc00968c0429918275984be508d" },
                { "hr", "cf6256bee672600846cfbc08ca79bbc36161e8545a0d309f7ec5e8d0e54769b154097481a466ed6f206b8ecf28db7dc3a7e313a726796e3aecc5fbaae751f941" },
                { "hsb", "20bf164d5849426252c786dd9f960d01bdc2d52efdcecc7f719961d082fe3e7e5c7794a462b4ccd23d71e61750d0500f07b60b9f10c3c1afdc08f253c16f47b3" },
                { "hu", "4fc1429ef0f028327dbedab3e5bef74665680be2c46666c6988b57709a3166a7d1c4f19d994260a959e484059aade736fe8b31ccd7c9319af330cf790a93070d" },
                { "hy-AM", "9f34c9a524a095d37f10834fe36be7c44446bf08b7e6c8518598f3c92313519d643780d95a0feb7554a7d9969028968d46e2c680899fceea9ed52a10cbad8419" },
                { "id", "2c075012289f39b485101bc9936133c02889303bda660ed6332f7da423ecc08ebaf66501e685cd88ac79080c2eae11d8b1c5b1560b4b80fece60b88477cda7c6" },
                { "is", "afae444beb0e9311da3d9c15e6e2177f51c4c321d6b86a692f51d1c992d24d3e493712bad27010d6ef76eeeb07acee40fd3fc92372d0cbe1dea7b044019de701" },
                { "it", "7e5686c9e1f8984e1fae5d3c2640e6b55c2fd5b82f06cff6e1e25d6941e8cb390eb7731024d167902b9213eeae1c5d48fe5f4f92d20b93a4c18061d98c5f5e46" },
                { "ja", "06159939ea9d3508b093d177c65949f91b227e28703d1e1dc82d347639ad95af3da6d493864cbfad2719c401e7c090ef870713a3615870dc07530fe4f16c4252" },
                { "ka", "ab208acfc8834d02995878b3684b30bf3e50024fd8502f225f9ded865262a9cdfa68fe9e81cadbb117259c7d5d3761af2d1f3c443d77608a09b47afb21e3328b" },
                { "kab", "f0756fdca4083e0c2fad20156987a361750261df5df7428b9692bfadcc41e7d3c438bb57a55a1093a5398dfc13a0dfe55f52af5d752ee2da4a3cf6890d7f85f5" },
                { "kk", "3ae87e0f5e82075fd66b2dff0fab272df918be9cf06fce14fa770b385cc659b76e0afdb8508929ae7f83ae813d0277aa95b903ecfeffb13a6fe321f501329468" },
                { "ko", "99df15fe1f2d3be328f2f8dae93313748aa74ad0b97f8eed7187823a93ad798360381904d5cfd4ea29d1cfa850ecadd0f22bd2912bf1e7ff39223f81dc1e9c3f" },
                { "lt", "5815df70e14c8fbbd17e923d37d0d6b0fcbe3536f85409df6b6e54728870a2ec34efdba614fe369470f0269cde15c39bffd605c95d31cee5d92ea79d23f931d2" },
                { "lv", "074bb97dbab9a010c908d6d920cdc1ea87e083263714744f2f8738ce65d44cc2b83f5685bc2cac9e360bb51f5513576c9f02d4b889c9f77c7c4662c3a334c8de" },
                { "ms", "3d2982bd908d829df781729878d31f05989378bf02a8fea8b573507a8204ba1dcab78862d68aca7f5a3d7c5d16c1bd6fa4a554c6d10105147d978b1d4f5f60d8" },
                { "nb-NO", "49a8c15e35b142e9559dbb45544772483330111af40c453934ab2c58f7733bec43da9ebd5dc93f119e19ec9b826caecb35349c13c7496d9826a99c9593b45abc" },
                { "nl", "93d8a825ae8c42fdba812c33b59b29cd7c21405ba16c5cc1f09867e2d81c9c52626373b83e78ad4f889327309850d61875aebeebe4566b2f414c95d94e83faf9" },
                { "nn-NO", "10db87e7d3687422c4b64c4a4a8fb0bdc8a5994b67aa70822f1cb14f3d3c379be58578def44f07f5d80136b52ec8cfe27db57af157af3605f3c78b68e0e20513" },
                { "pa-IN", "9cfa6d7fa54ff81fda8ca3169c4ad9ecf34d280eccfb0e0d5ea941b289384be18bca25367ea50b8a08267d41a8e8e03463a2eb3423b0c572c706421bcb66bc0f" },
                { "pl", "2ce8039ea84cbd7fdb49f9bcca32d560ed993e999f37a08fdbc26bbcfa02d503765a888652c0d839626d310c378c2e78e7e283d69eb3d697523aad9d1d41f664" },
                { "pt-BR", "9d6fc31682f17c12d05f917867ffadaa281cac49b8d9b6c853555acef1d4fa88f5c6bb07f84881a0f219e980b0905d2e0a3ef92275d85bd5dfa27ea59ccb0e28" },
                { "pt-PT", "4b726c4a2727fde066ab5799d131fc1dba7057287a2af0b22a61aa0dad4da5c1fc07c548808d906969f1dc9113035e109db31121daf9997e8d0937ea0eda5330" },
                { "rm", "663918201cf89b003b67a0e4a7793cf0b80892b64f901fd85ee4f4eb2a2676d408f7640c62002e576072315f6fe7d84ae60469832c1ef28f13cbb08299195e8e" },
                { "ro", "45d1d0510da6494956e61a62ccf034b0bc894430b5dec36b588be0d2e7852b59fea73bba439bb9afa7d0ef722737933fb7f173ac7e76b91ec63e61c5ef43b84a" },
                { "ru", "2f6d3d8bd2f6f35f0f9ec6d0ae7deeacabba26c73825ac1a4653a6f9f88e55109ac83af4ec88f257ce5a8c2ca99c178a7437853b7539714bcf7ae4e5013b3766" },
                { "sk", "6926435e06df4ab1be8371de54a70a4e99dfb560124832524a093b4c9f82781f0a3e7fa0d1bd0d4872f9d8efc40cf007bbe8e9252e0c55db1332b6ecf7f846cf" },
                { "sl", "bf273ed51c3e676018c54683ee0e0df90ad7f96942ec191f9a9838d26060a03a6436ad6cdfc3c8db34f716b4e4c41b9bb5879c038bdd9f2d050e518fcc5fc877" },
                { "sq", "66a4219814cce98734d4ec46fda594198d6a65f37a7df7051cbd08785cbb1e44f0c96a1c641a11a24c43ff6d4f8aaecb1be1ae466402f8ed827c735b7a37cc3f" },
                { "sr", "070c61e158906a1c4d13fe76ad533483956c25de914d49c694b5d606ca9634c3765ba125ec2ea6b9bf9c8fe77ef465c73b2211980574382b5e71ed6e8ebc0f8f" },
                { "sv-SE", "4a7eca1828b1f5ed6168cd853e9020f0f536e590d49100637920208bd390de6ee3da4b7882b68bd93acd36d8567c80cb8f32ca07f80c7f774e6ffff3c5b3c226" },
                { "th", "cae67e28360fd3eccfbc96e03e999064feccf10ce998a983f35c738c61c15d4f4a185373e5fbdeac3d287a509ecac1ff0a865561a4249e3cd0829d3012fc272d" },
                { "tr", "488ea5f31b3019cf2fbe5becd1859b2e7fe9dcd85fc7d8dc66519aaea9c73e984372e2ff6f1467c76fe7af7d7271116b9a7c4caffe1b77beaf0eea8bd008391c" },
                { "uk", "16e82f113335288a69a1b0f71133630162d78a9b3fabc34838c427af134eec50c09bd84979b99a5b0fa8c59bb30b728559d800ee38b90151683f9578159df1fd" },
                { "uz", "729796d49a5b70b7958670eceda18555d8ebaa8c040c5b1015215d4dc8b819b8ce4b50986a426d04493119620e901255504f56fec1bb0276713eea98c5a22b67" },
                { "vi", "632613e861ee1d15d7027b50d62eae028119b027b2b249de488015fb8c9c1290d026d678c0e7d7d55afcb208d1f642fc47bee90ed2e48f3b9c96be85bcd99404" },
                { "zh-CN", "c8282df043d0c9965fb7be66de4ab9604a6f95eb497227cbe99f70dc67365db732b89dac7991f53d1824861b9758130deedf9880ec522305e57b70faaf131b5b" },
                { "zh-TW", "3288a8b5ae526886ec2107d5bb8b1ef945301f58eb19b204da1160cb8cc5d1a3274e0102f99f39182ab3dcef0c790e3509dc19d033034a8f2495e68d4886cae8" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/102.12.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "cc59d3c2c79bc9b041fdc695ee823745c7c4e73cb56923aba1b3ef829dc09dd2423e561b21d63e26bd760aeaef8d592203c682e21c776402fa25e57e60917d41" },
                { "ar", "4ddf7014c0f335b22910e89082be15cd1d8731dae9cfb694713dae7380f0f49aba37e04d3c65cdd28bc4c26c4336100c6159a174de7770f20258e9c2748fe305" },
                { "ast", "7120cbabab045f7df34a85c72fccd68930a67ce6c0c4a261c04f461abb3ca9ccf7beb736fb615a1c498ce5e79bbb2ac25598ef64b79ff974b77bdf84c4c4c93b" },
                { "be", "cd454c82868fdf4b70d5055dc151737ebdce68dd7944692d09388d7d698a01d8bca3a9301ac813b7a8275eaa7966750c9c73b1955af09746cfaaf1096ff080cf" },
                { "bg", "5d686e8e9f829c9b7edc688267a9960812771ac6c48e6e43fb7f9e693b66ca07c836b984f32f2f90757a220c28f2b1e99b28fc4dfe7eae03c718b6c4cbcb08cc" },
                { "br", "d71c4fa2c47e33442ec686ce8a404d419a746ffd9cfa123ceb9e2384da6c790e3c005749ddf1ccbb9307e47a0f4ea6008f0e15f9ec6582ec0fce97e7df5afa60" },
                { "ca", "40476668175cb85b92cb522fa53d4da1ddcb035a82afae81afd0a8a8c53bb78aa27232b1ec1e2f9d205bc9f952f1904d10a24f461cb0cc0c9b24636f0a3510de" },
                { "cak", "3bf96f1bcdea7c50c3b504eb6acd4a3ac8d04b45c2752daa77974d64f9d1174ca1ce0aacb9840e19a5f1d2143e832a98a4c2e6f2d1b33435ce8f01e4b7d68a51" },
                { "cs", "4a6c2f4e7acc64508ed4ca1c5a64b2c322df5d5f981e5994d9f605a314aff6d96cf290393af6d48d5a0c3539734e3a9d01ca73a0d62f650c6ac1b26bffd889a4" },
                { "cy", "aeef6090b24e9e68072561d8669fb54620fa9b3c73436e9f158816ef4b9de186d8641bda529f19266ab3e33bfa937a97061b04c216fd6046f32106e5950e9e80" },
                { "da", "6c8c7b4b7d68682b03bf46b4c552c7c62349eb2fdf70e6d33bbe431acb2676b6ac57356a43a307746c7ef52db0056791c501dbd7ca0818f5acbcab0fd251874b" },
                { "de", "cf125b0a9fc391177658e391567a2422583ce9948ac881e1a6746b353b19f67a8b2aa6a258b29e59699ec79bb5f9f452b2a067464df294b08843e59e5081f9d5" },
                { "dsb", "b3e8fb4e88952b9714312eed367597c7d19acb8e65e2f283ff8efebed4fcaae3e803198855c68cd4c59b70f3ae2ede4375587e92e5235e35d91833f2873248cf" },
                { "el", "55de83154b6c8b40a8aa064e08e6e6448ce4ec38c0cc16a55f60a00de2d8958f546d1a2ce0dcf67d388cff6556fddf1f2f8178ae2669ef7eb370aad92bd6ff54" },
                { "en-CA", "f1450255f98c004448086ee5600b3cebb0502f2ef2190d384df81018310d24e7f1f0e4b7d1ea1a779fc9fb2aba5ddd2d27856f417ea0e451e1a24d7cc50a172c" },
                { "en-GB", "699cbab2445f47409e972647b3323e526b678ce3eff336dfe814eb90a7b9b0b940184bc4ebcc45d060b09fa7157fb39a6070d8f3e477956a7dea66830bd5fad3" },
                { "en-US", "49e9569fbcda6ad83ee96b09780be3df4f2019930a18f7964519f421556bae52cd5c85c7e8032789c0b9c0c6157badc1968f88250d52df4467e71cad2d07af36" },
                { "es-AR", "b8461c33291fc91fd61e8f51fbf42ee5a2ff61c0be0b3bb083d4a60371efc61e34b2f7e39e1efb6fb032a505d64af8156c642eafac2f310b420b905925638988" },
                { "es-ES", "bf8b3c738e4d5092c7e944d15fb617e185d0765eac07f5884451ac16ac44377462ee3325c3038b6cb44697cf373bf8ce5e74d3b1eeae09581bfc44de0cded0f0" },
                { "es-MX", "e9c61ffd8d87b5a71848fa53cad562abe2334e3486dec78225fe61f5dcd4fe0fd957dce9be99ea66ddc80212f96d326d1a59ccce1415455bbd113eb9b262e2e7" },
                { "et", "130c66d916f53903ebde50b9e0bc3f62decbec07ba6129d7eddbc595d0860e59f9a4d88cb53716c6535f40d22aa91648f7992e3e3dbfc0631da22f8e6090874b" },
                { "eu", "471497490c9ee978e24841f3c20a2407b874c098220e4858a6133a6be27057e8ddd88bc59787d2d7f4d74ca41b8d03fcd060f0919b07f32ed30df10508f3bed4" },
                { "fi", "1572e279be130c254c3b8a029847c85e4e6f1129e920b94887ea4e9f970f4e6091416b793ea2d17b0d7275416b9524f2ea8ab625414fd0bc6840a278a8ae0227" },
                { "fr", "030b3a3bf509d9eb2c65172a04d642389dbf9988b7ce85f7df7de77f6c9ebcbd3180f49281ca66b78cbcf895d04f1d30e02fa207bf42e44b5d869df645ff14e4" },
                { "fy-NL", "91817e93aae2c4b1bc0cf827976971d1eb9ceb8e4f84e51cae72d9c922e2013e54f14b6fc9d0363e3ec0dde863301728d9e1596a93548bfd514bcf06d78d39b0" },
                { "ga-IE", "0b06c9be5801c5652b65bdfdd62e84de7b627f844b6047f2217471d28633683a64f40ca2d196d34ca08a133e1a503dd175e535751b364f2e28916a127019ab0d" },
                { "gd", "a338d19cf0980d8c447387fd03b2b017ea9e3085a8f373ae12e40737f734ddc98e6135da31b2d49087d57c41759bd39a11566bff25e883f2ae0a6210ad81a0dc" },
                { "gl", "77d79f3c61ae1412eeb4c3e23727e953841b5e8e81274246417931b50e53aec21b2865c835d36f06f514f4bb904f4ce622540e917ee35d6193e45b5807dd7960" },
                { "he", "03a820f8bd3135205c7434cab35aa22bc31c16d49b32099220a9f69ab1954c2554f8308ec45bab69a0b83bc23c0de5d88c7a2639c5e0e67bbcd465366e98a7aa" },
                { "hr", "b1cf083635d71cc73332e79c146c9aee2d17d28f39b6c3afc70999e2b3f392ec68330e276df2450ad625ecc7191cd376554210b6e93c39cdef1be1e38ba9e120" },
                { "hsb", "770d3c1fb1b8cb6f46bb455c5e9cdd46fa355dba87120e5c577e519162cfc973afe1886d4c25e2ba81462607437c5d1890db37709ca07a134b75485c6d6fcea8" },
                { "hu", "6700f9bf4785f9b26ddcb927e0b1b4e23b9db6ca7f8e690ce43e35db9824db3978ea6412171f93c1209c744546d41b4a198d068095e3949186c0c418a594c3b8" },
                { "hy-AM", "92b40a3b441f1bac11ed4d1eaa301b2185fa0368e502a8131c4619d0dcc521a8ddb504af79eae070eacb7baa1b56429aa8561dd3f35360462ec577a3ba102d4b" },
                { "id", "c5a9fb7b267889c3a7fc7f5ac815e6b4584d7d8009829f55fc43d63f3d0e5828a4e6fffcb7078760d799c678c735ed1c2742621b8e35c9e765ed864982713e09" },
                { "is", "4af53915c6e631ef74baf3e21a8612b1f39ead441af7e5c7cb1b4b7aa92512f4860861739550218b0a687fb16659bd08e84d9ec743d02472008afd16e482bfd1" },
                { "it", "7099067d3da95e4dde621f3ef732e21b95fee1233983d75f905828bf44dcc375b0f02388a0e3733401861398fbf83f64813bcfdb3e48912b9132095c5d086b45" },
                { "ja", "6b9fed273fe57169a09448d25c823f4e8f84b3c37f7e7a9d9118dfdb414fe5eef1f609d47acc7746226a6505d700f398df507e4f08f919915d863e6133a7d56c" },
                { "ka", "c6388ed4b4e5702e80730867a9c1ec908b0f07c154aebfb7da2b6e427600b5ea71ee4ecaa6446f924f01fbb38bddc885cb9ee96dbc1649079bdb996da9ae2776" },
                { "kab", "e909a91e3a64addfa4df980a977699a53097ca7462b45f27866e34bf9e5049fe4299700371488e4888864ca10d3d0d3c39bed3f54ce9cd548db9440f83a1d2ac" },
                { "kk", "c3e2697876670fe5d170302437612933c27b1804bf280eb47eaeeeec62b5f4290400a32af8b29cfc055dccee32ac78a411dc4a6306b8d70c7adaca6c88085d31" },
                { "ko", "a7e5b4b3344cfdf19c4462c995eace2f6eb5cc207c01530f77d9ea83fec1f001d168d88be805bcacced64a4936f8e263959c31b349c2eef07ed18fcb20f7d284" },
                { "lt", "3b4baa95f7b0d9e91e531699162621a03dc604ecad71efb68b8d20830268a37c399a294595d7ab9a414d4eb3c5172870b494383f2d8b60f74edd32832b13b1d6" },
                { "lv", "77f2c21ec06b06dc2ce1293bdd34cf42a5f9dc89dba8ee2f60205be9ac68cc935e6b857eac6c209f27ca59b31804c1b8b8103902769e9fb743bf8954c30f91bf" },
                { "ms", "b2c213faabcab690ea3f94fede6b2b02b34196f26ad8c1d99e162e4abd4498561c2f18278e91e8260f1bf186d1b65f0a5e093af78d37c6ebea9d3e6282694c5b" },
                { "nb-NO", "fe8d44de28ff423b6d09e0705e693d03e9c4fbfec9a9057fe51e9396a9e6bc23465c690c610fd62020954156fb4a86f178e19ec6b2c62da31e96eae9f17707fd" },
                { "nl", "19e8256b0fae95929ece459fbff4459c90d4ad240021610550acda5bc5a8c537c794543621922df2b945596ce340562b9fd9156d4290891d4addde5ae1af5b1d" },
                { "nn-NO", "5fb5aadb16bbed680137e982e4d6418ad49c4d8a649195c822e8d5dce0c1196e42399b96ffba9722c473a2da5908c08541fd1d67d9e12b273c78adb16e3f4253" },
                { "pa-IN", "f3c9e804915bea310f4f363e5929036be5d59635f6b356af1f383dbf47040b756f349c9dfe2966690a0ad4a5923b6ae7bfdad14f6e96343322d5141372ab4787" },
                { "pl", "8f65ed0bc3e15768094f19cefd048db91c2da0f2824a36aff24be6c2dbc5e56b8d1ae4103c7f7a9fd5ea16663af1928c7db2e236bafa3caa903d751b5b350005" },
                { "pt-BR", "4794f42f1d29208d11ff087af981645b30ab0c964c8e3793e0ecdb470f65c0e7e745fabc42606db5db3a444f9187e79787f3bd90168db35bb227bd4b132e786f" },
                { "pt-PT", "372b3d76ff23a2c3773225441dca47bb2f16152944b35e38d38d5781b18b03cb8da1b2bb8c51c356d1bb8689756ee1fdc4472a45265fc25edefc5749311c14ec" },
                { "rm", "83db6401ed40e209abf87c3b848e6a31c559210bbc3dc86cad1cfad00fe7baf87d25c1a23dbfbbb2a45449940e74a96028677647b482313d3e150e39174f7427" },
                { "ro", "9866dfe2e79d51aa31e2651e546eeb8914894741663f6a3cad582f38113c8300de9f638c25725eb8dceab17ea95ecd6155c21dda1ec6c25dbb5bda3c0dc0d8ca" },
                { "ru", "a8706ae0919f3f5a552407ca09e61681e2b655f8845136e43a99b5809070e5749ff4b8f2213f4bcad72973c801d8d1b8586024ef930a383ca5259b19a29aef16" },
                { "sk", "d667da0d2be36365c51391c27297a5695a983a890c529b5e5104862c88fd8c57a8d80a6549d820cdaee40d500616d968d6cbaaf015181b170ff8f7ecb2d94f01" },
                { "sl", "af35e676a55eefd8d3e4edd9847e4a927223d80c2fc7183230fbc0c6a38659dc7e6f0b74f68ea7cbd9ac3311d0fd9202fca4c2ec294cbfff53691e7ef596ba58" },
                { "sq", "c3e45033e90a788248b5e06768e4f21f22a2825d9a4493c695817ae3e7768e6e8e83019569ab432de5a3d790d683fa4de7a3be669afe22fd6d827914780a88f7" },
                { "sr", "c1754f686f88e7f8b3b4476784992c8d060b340f2d50e1c302ef1adf804838a2d076f22b7a6b5f1630e903f1830527980b7272cf7a81de900ee12b46e6354f08" },
                { "sv-SE", "2fdeec1895904ae50a7bff2f7f69715a8926a08fcf54784635f88452914ddd40124548748293d31af5c4cd8df995a56a355815d01299881f47f5089b6ef16ac0" },
                { "th", "fa8cf1c9229f780df7912571f20def4496b45d24102513c838ff1a5d0914d9993145f71d067d07a529066f0a06457dd78dd32e7ce21e595003e1d4eb5a8ad2f1" },
                { "tr", "a37a67211c0d571189d4736e42f8a801b8462cdec670716fffe46d516050651846094a1a25692081942a4590be5009ee5bb9b69159c630b4e2b2fded011dd038" },
                { "uk", "94f1287fd7b81ed5037a846f23fd2975ca6790d515471ad36150a01d64070fd7d906bfe4716d3b48f4588805f55df07e0e5f55de458757c835677bfe2135612b" },
                { "uz", "dd7584e1f7af5d17bd373540ee7fbc2d44ba08ced4b35dae01925a55d4b02fb954996a481ac6bb4ec6375dbf31bfce4f6e575b066a027894be006e161f3d6dc8" },
                { "vi", "b575e96093f603a306d1ae7cf7bb1699b1a68cd890aa6da5bd0b63a7596b9f09f435f43ef8bd0b681e7bab74b2779998c4d4c632f1c045daaeea8a7b4d67cce2" },
                { "zh-CN", "ee523943f5efe9ab939efc9623c70d592ebb13a63ba38ce8a07f598900242bf8c237e16410092d5a22c87d1135592db021bb07e29ff79a199d4a705b69004839" },
                { "zh-TW", "2d877ea42936f46ff067d27db0ef414e704df172ba6603c5c7f91e5e500d772f6b008c5d80a2c935ac1b1f6185e4f722b84cedd4e58cf0295c3a22360abe8fd1" }
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
            const string version = "102.12.0";
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
