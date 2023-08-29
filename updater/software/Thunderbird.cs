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
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.2.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "396ab67b5d4d684755065fa823d2e1f87e08ae346e3af0d914aebce650d67b69f7bcf343fa65427f0a572c8ce85f83ffbef174e6c6d8e2bfaac7ca81fe8f6ca1" },
                { "ar", "ef58c0f820efa3b2308e766f3cb427209ce7180455417d5f2f8992b63921125b91468cb6f7b2071f36e5cd2b0720cfc8af2325a5fc8adc2c2a9f0bcedf800f88" },
                { "ast", "8da4e38eedcbf010723cc77e36ee156f6fa6256cc0d9bcc7f96ff231cd3e692b549843afa9971b3cdd8d3d466c4b8c8602dee8f222fa0a17e4dd24421f3f7b4b" },
                { "be", "a11722ad3149874d904106e995e9c44f790b2eb5344d5f1eecb50cd98ee7e71fcaa1615111f9c80ba3b0f21914d94c0673854b753d0df777eb92aa612a8ba43c" },
                { "bg", "13468e16a2b612e5676b09a9a0c1b5bc5588e6933f285a13ef6768a793d5fa928ef18cf09aa38f37c2352a3811de42fd8ee82e831f25261805998d5d24ce1659" },
                { "br", "a15adbb15d46cd3b1825470ab3d828af8652f768f7f9d748ec9de8c440eb75f22e795dba01b548476c57c5014650828755416c3a41b5fd25a65d405e6458080b" },
                { "ca", "7aa08a735cc2ff1790a402c29321c6d8f7c9a776729fc855e716c025e629dc65b42b6de9a7595e0d754f82814cd92e46bcb35535ea496818d80f43d6c8aa6219" },
                { "cak", "12a3caf8f0757e8656e089048260cd1db7f7b67aa2aeab4c350be4e34939c9d6f18d85cc6b052747c1d8c7f00fbffb70a6ff5361ff632d5309f2bc576df4b061" },
                { "cs", "e0cca23f678005edefe39846ddf433aa54466e73f10f31e930e3b684ce12796936ac30e6946bc7649948f9cb97a893c17f0a331b28f55e993fb5166091a91726" },
                { "cy", "7bdb6ea22a3caaa9f1b6e09645103532a8b9125f639500854d360928f23983396ace90a1be0ab841e5612103d227b87b4e38f221a57258b8e360ee852dae0b21" },
                { "da", "c4c58038691bb532e7d3f9b162dc8bf7b13d5225751a62e6ad64a0d7321c00d4fa2093fd3eb067fa4359ad5c6d3e0901cdc2f871df7be6fefb47a4fb35a43848" },
                { "de", "96fc2b039e06a39ae8801e134a0a7014eac19a274afc1d8b8acceedc87f279b4b5f0a8ca68fda9a227862696684c132a301eaaa820bb6484602b15ecfd6f60a3" },
                { "dsb", "b72e1395819890d18a980743b7d7bbf75e9fb6a36423d0346167bd3512e0209f4b60222899136fc4c9acb395758956e973b9dd440b279172f36258f0949952fa" },
                { "el", "9759612015b815b39655ff3fe6c9ca6f78bf02cdacefc4e3973f46243b490cade9fe9ce2ed32aab3668fa79ca6e1bcfd3a3e6467f597b25df6bb4ea0d707f9aa" },
                { "en-CA", "18a080ff79de55369706f453da5c5e8cbdf56ccebaf448bf6008316ef5a9cd20d78644e8d4fa91e6981b65cc92d8f38a1b58592c492e587edf54ab8a0fd98484" },
                { "en-GB", "7bcbd4d42f0ed5e24a0270086ec266224e60c72bf40915a49d4f102d50540f0e3c554b3b2fdab32d4552d8df609847b8b74da3239217c943ae996c3aed26a8e1" },
                { "en-US", "a1f020ee39277d2b737070842347768b4b58d60d1cfadcdee73f6509fa3d946e1305788eb00ebb4c964a73abd3a34de916c85844e6bc119e0058531870476ab4" },
                { "es-AR", "91a7dc89392e01b7660d382f34556acc5a7273d09e066ba08ae8acaf378f8496b45c8533f010256066d1d540462f6aa49138806ae1cbf0ada51000c3e1bbfa54" },
                { "es-ES", "34ac7c80863904aa61e6f9b0881f3d4b74660dab7ee52050cd9324c1226b1bc4071d9d73b8f92d472dd05113bad24340e432a4ffae3d6467ae11f3ebb2ad3dd9" },
                { "es-MX", "d69f3e6ff37234dc0eeacf25dd14604c439fb55dae9f91c2a5891d01126b0a168daf9550f55389dc29341ff9a07150223c35d2f4c4c120f9f159a18cd243a7d1" },
                { "et", "b908b3fa0aff949d1cb3b8f944b8e00d4da87bfc7414bbaff2f383921982e45326aaf81e1f0df6c5a9fd81ae9f8b75461408eb7a813ec3808d1ce7127e299690" },
                { "eu", "d48d7856027949a45a7371634e5ce57aeed73b926f4b943bb1611f4147bf7487cc31548b821d60b0e5f2a1af9edf67897da3c157a27fcfdb847b5671d4249170" },
                { "fi", "b4c5477324817a01374d33c84dd26ae75a9a8129aa8257ccaca7d52b01aaf47dd89c43345467dbf7a4e24c3fb4d088368bd1a7d69abf4c3f8d1bd114aa9fd019" },
                { "fr", "348c69d0bb183085d4a9f3b6de46f447d3276887380a9f066713de91baa8138fddfd7442c7892eee3033a4109d91f14522ae47b83a07c18d046856a314f4d5df" },
                { "fy-NL", "a72dd45d35f88b3351bd6c6738cbe088fdb3f62820c74c49c1987ac6cf5d387b0ee6a867feba5e4d31e13a5f6cb9fbbce76eea3d3d0dce3eeb2596502a17e550" },
                { "ga-IE", "94b83852a37286d07bfe149716f91b4af873b9f02d67efaa1bae00b3e3aa6df6fb0dba47b2081c6bea043f3b4f1a8c168f8a50fa281f5740bbd7de51aa61dc6a" },
                { "gd", "12c2837abec1545aee79de4a21b0b25d219e4844159aa544fc0178fe3d98ef74ceea67933d9c91d253d53db9ec26368a5f41e5c2ba7c4a0f6a94ec4cd233aca9" },
                { "gl", "d777ba7a417419ca6a4cb29ec2114cb5da92115b3e3b46f6a30116400b6b7a8924922ff5366fa728961702337ef668229dd624f2755b4e18d0c7d8a69d3543a2" },
                { "he", "de0e93f77d9b1537f0573981c114a9e608a4e0776ac3c9af46d0812c447ccf88d6c56c4ba9998f99c47593a2aea2c690c5a78fcb77b4bd2df946bbc77002e499" },
                { "hr", "ff76ee7ae982fd93cf7d4303d5d8276853b44df5574af5e2ae77e099e0e689dcc573e5649dd45e5d1299c3adf512db2357e0853a886a6545147a6499e50fe38c" },
                { "hsb", "5f99f6fa7cd9e206e72ca62c9396634d5ea9fb9010be5a12ab31ff88eead0dbb48f04eeda08e975858cd66bcf4645c1e004df2442d0140814837e0ee6a8116de" },
                { "hu", "83344fedc3f3ac4615a3f5a30f1da2d0aa0d50385a223a7b95d2dbb7ce343fe1cac93320bfbac373fea6ca3b36cc811f364d35663b6f00a84958effff1d83e11" },
                { "hy-AM", "134463509f1d938b3a2b689158ec8d534b46e646cfab975d517e81fdd7ae814502c49b1246454cbc6bd20d778247fb4f58d60db7ac4c278841dde6bce9bd3cf0" },
                { "id", "a79bf09633c5b249929f8de7b7c9f358170d7a969c43ac09bc13f333d379149860abb8bc2b9d23c3cbc7a844ea444ab45641af5c35977d0d558d228e8ab33101" },
                { "is", "6dc716113f4ce63f61741f2d94a667b477026f12df9e5393ab8cd180c4c334c364380163b4adf34ca345bf707d4c097869184600ebfb50cb04dfe35ffa579c3b" },
                { "it", "0feb665c53336d720d74ebe495dc0d191abeecf2ebdc779e9a3bfb0fcfe8229cb0aebbd5d340a13365253c754cc839cf439ea21dd083a85ef5a510a764827358" },
                { "ja", "0a3ac7830e29bc573ab858b6c3fd4f1d2d430cecccf89f62b597ef4daebf0ff74885f55b078a195da3e79872a0a0209e45b0991e39c17b374012a9583eeca9c9" },
                { "ka", "2016fb58abd3177d6ae84af35a1d413fc8eb52c0f9f75993a47d0d72f223c28ed393393b6d2bb0f075c6605fd63f893262d075d0d14982fdd35caed4be655c94" },
                { "kab", "c0a7cdcc9be29fa5a93090628879253f38c23d8819d0069b8c2d1e70faf31cab80f86dcc3d640dad7cca22c39d86629a51c940745077e36359431fde6eace7b2" },
                { "kk", "8c747f06c9de0c10cbe18dac99486088c51c28f1bc3ba2ecf394e62bc6c162617ba2c50f68770bcd7fc95d65ad2e360e81af7352eaa4fecf07742b9de10ce4c9" },
                { "ko", "680c6b2e01e9140cfcd2debd7ca8d316425c5d2aa0e2f0b0952d854f7a9a6731165bc82c9cfd6e96c94062327b31054aafb9d3589145a7bb2742b09cb2c78e6d" },
                { "lt", "f4be53246654be1334621a8f9cb7b95182c18fa718c9fd91dcb4fc463bb22d12728b3d4216792fd98906317df62f8cad3fbfa402b7aadb25548b0ee4712e2dbd" },
                { "lv", "b854dba294abf26d160538f4d7c7f4165ba43909bf40c006c70c6e5744021ee11d03a2f3cf954b312d79825fb5887e4b72625fd95aaa9a3390c43dab33ea6268" },
                { "ms", "ddfbfc95ad3d4877a4bd7fdb471bf3360f8484cf63eed1b24ae2161f335890a36c69254d4745794b3ad21c723e84777c4ae1708e5984cbab8da91fdf4a9071e3" },
                { "nb-NO", "8564fd5e07e28e388fc0a1b99e74bc5fb45e982d71ad82e7f625db545ed0b1b46cc458803706b59f4720134af08dda3bcdb08c955fd65689910649f7aa350532" },
                { "nl", "df7b1fd14923ed7c083b7cde8ec26e0f9b36254d4f9a3e990335f6e5f150a59a60cb917ef6f20e055f2c525abfabed10486cc4e65d98882aa12e7598d9f5f85f" },
                { "nn-NO", "a16c4ef7a8a4c94b3c95e9327e5716d5044aaf6a8b4158a98df9493896030ac311f7fbf5c69defaf2072d0812d1ff2b9939ba29eff6c33007ed4fd14cf88506d" },
                { "pa-IN", "ce58e434af7eb2461520c54016b24eed2f97e940b958dc17f7e16c4190c7debe99dd4774f7244ccbac515c640d096ff91c550f8c5cdab458d655b91a86c278ae" },
                { "pl", "083f3ecec5ff482d0e0ab40d1ed4df54a0b08254e8427b344acff4a60802e97aae75adc089a400912f455359a21c9d0c669a75a50012b20102442a479f30b320" },
                { "pt-BR", "e40595a68796b1fc22709646260d37d19839a1e37374204e82c14c9542c69c0ab557235e323642173986348f11fc651d1efe635e353365af33e74becb3d86d79" },
                { "pt-PT", "4ddca3a42fbdc117d46fdb2e71645c24bcbb6dceb4ae83789930d55b3daabd0fdfce844589f7117deeb80ba5687d00fc020b8740eb21b096e6ce92e000b72eec" },
                { "rm", "120eb3ecd607aa6c4e6ad17aa3062bc9e068991883aeade22c12d4e6c7e9cc9fb2d47c1d85543d4a08dee38ecc39722c31b07b590a28264d850d3c8eb9c4045d" },
                { "ro", "ad012222503fbca22055f113ae5e069c4cc5b01bdf0946d60e9374e9db58f4544afd601fe146fd46aca47827945d6f99851d751ad148d06677cb79fffa54a1a3" },
                { "ru", "f1797a9d13010f6542eccb7acca218f4ac1d497e500fea300cc353a9a16d6ccd6b33d1c5435128d378bd72d4a56297f2c2871321b897d6c93a9d8cb2c0af56ae" },
                { "sk", "a5b7256ca934c1d50b0f254f690055e4ca89251a14f0afb61152de141950815ee2fa196992d6125db4a831c67830a68eb6c487af1df037160102f537499e4f61" },
                { "sl", "f7eac00849b09ac856bda1162324528aca57007592714cd98a729ce7b237901f7b8698fce012dd8da697db38f5980c9d7269c641c952a5c7bb6b9283469f2cc7" },
                { "sq", "41fa2f0bac9b96dcd013278fd558ab1317f12b920676a8cf94da3fa3b238d2ca2529a0cf98beb5e2ac74dd16a5b5ed4228d24fa1111b25e37a7c03b50fb065aa" },
                { "sr", "d8595359643b3b3d4d04be5e8aed43a48685a87d9b12774237b696236540ffb4f6970291a3d53f72cd166e8764a834173a866d949178fbbc60889e3a623a6f97" },
                { "sv-SE", "24df0af93faa589c923f160e04d05d5063960ae030da2a6aba76e74d0a6128a68a6219950f2ea6ac11141c50ccdfcc40dbc20bd223bff39db3a6b0cec622c605" },
                { "th", "9f51f1e1da5094b57375863c0e5379fbad4cbee8d8ec65bc7f27be99677b11d7aa42c2e95765b2821dc64cf05ca4f171e4eae6a7a77fafa09d1e26dc442b36a4" },
                { "tr", "2ef3f70e6b70ba41546233c4ecd4b67a0e213814bf2c1044567bd6895feaefa9f8fd8290756efb1c760e22ace7d8329a29cfc4edbe1d2f020d006c0301f36419" },
                { "uk", "d252fba0e357942e40461cff8a25ccc47eebeba6651339db42ec9a3e7f7c31d4f3086a68b5826603f9fdb50af5cd05a8eee3d866f05fbd27a4e66da9300c4bd6" },
                { "uz", "d2740a10a8dfde03118682af09a9f3abee23a3c99f76ae2982687748b48ad742a0e7e1db00a8fea8734dd3adada877eb86d10cb560d5c55a5f3cf1b74251750d" },
                { "vi", "d67aea08356a8b6bf0d365822b9f060a6024251c57ddf375783f5c2f695b35d8ab2efdf735e3212c8f75b6368e842cac59eed6c2cd6e942748691bd6744591f8" },
                { "zh-CN", "99c781a5a587072a547f2b94a3d67f191dc23efeccd3ea24346825856643e61ee2f77694476540fa9955028708dc5bab80c339ec97c1b457c7611f4460bd237b" },
                { "zh-TW", "e351fd24501a48bd64e7955b73d49dd485ab609e426d5384dc418948f3c2879feb8fca8dc7bb7afcc5837473451ab58273d84135f3d13912c3927a6d69e0208d" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.2.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "019042bb6351a5629c6432a59d0215e3c9c40fe7e234d5a82b98449a061a7f76910db3d2a9479245b5c1b9e3b417d6fc2a017ab179f3f7b5294b872fb90e9a43" },
                { "ar", "925beede45d393a528b072ed0bb5f51c41b55e9913adbce18b84595ccb45ee786e04a3381e91dda40e55455e59758da9b7ba8576a4eb67dbca7a42a621659107" },
                { "ast", "af615efbc1f3a1fcac7688075ce425624da72dd9fd36fd784ae2b033f9498cbb4fa726cfef452f8c3175f824e16fb592dc448e4284a42f1fe82fd250d3999b40" },
                { "be", "6bcd889eabeab5cadf5c2ba9a037ed4926f73a2c53df2fa40c871b21689cfd1e2a38cc17f4272912985414b3493f8d0d39312035853a1d503d152fbc80f144a8" },
                { "bg", "dc93e53d5737fa6a60f2a9dd92fad660d51b8ab90422dc083bd35d003393fb2b1bfef1b801b178cc79884a25cd13fefa91d5920a5ab09ce79ae578263083f111" },
                { "br", "84af34dd00469e852022cd0fbac3bbef978c57688d4385c56588f99b03a27d49609ccf1144178b1df484843c08e04d4d5211927da4c7141dc950585ef2208053" },
                { "ca", "2d6a068bc18a1f886f950793cfbb14017d8c7efaa22c0298d8b2bf9494d992cbabb0bd283f54c89c177ecce7b24894643cf39f063d7e9163bb355956a113dfc2" },
                { "cak", "d75ac88fa551dfb3caf954ce9643e7f71cc1ae8ddcf8a4284d3cf4d2daa7eeb7c64aca4367c6664a64c09371f1dd740bd46dfe540c5fef09066bad148154f393" },
                { "cs", "c1ebce2e539a98d44db20d3dc7de5e579f63b8a99b52d030211f41319c5d1cd254fd25c30f1f834c74e448c7b5befb8f7201a4d5e61a7319865d03efdd946d94" },
                { "cy", "d2e79206bcf9e02e7c0d67942126cba11a73afde51ddba6eb5228354266dd8eadf73ca5dd01143b646444c2ff2125357b90c01b607e5552b92d1b19939762380" },
                { "da", "74ce10bb368eaec2935104c3a6cc0b27c5024f4e45fa2eb49ae6047a4bf1ac34afc59c3fe3c2fbeea96d2e369567f8147368459bdf47f4ac00b3260138ac64ce" },
                { "de", "420fbaaf5df03b49f698371b5c3a3153592a570c26f3033df941f743bd92b6025bb71d9f34527552cdaa52e9578544026e6d4d22596418928b60ce588e4074a4" },
                { "dsb", "8325e9af211dc826ef3e114a8f70a0f30b71afdb46bccd2241e25245c01a57b11b684f7f3a7f9c04d422b21a540d1a4ffbc2c5b77951ba1dde81bc7a09770f26" },
                { "el", "cb013046e3fdfc6fa6ef8f9a556f7afcd199f00f9b35d921852776d86d71846487aa12b5d01cbc34192b68e290591fe951a7f813f1c267f3b865257662b583e1" },
                { "en-CA", "4d932594b677a5793f6add69631b1c6a0844150412f7236254a272ec313b8c728dc38e66fdda9b31fff6578dd8fc7f72a5fb2414e9d45048ffc6779fcfb91286" },
                { "en-GB", "53a2b8a0a78e5670a55aa22e50088dae14690c061069e28cc2a3363bc75395191848528b33ca2055baca801bb37a2e5817a62ba35104806cef04d27d8b5deb2d" },
                { "en-US", "5f71cc380626916b79f528c07dee381b88b5a9c79bec4802c0775ff45327db2d100aa47a8e17b6494aec9b169b55c4bc032f29eeda7a249ad02535eb5950fe49" },
                { "es-AR", "ecb0b9d72e4f7674b03b8b44112598594c4086de1ea1f18c615595be265f8e8d36ed50115eaf71c386eada7e192658b3ab5bf6a4e8bd0c9dd92381e8c79a753f" },
                { "es-ES", "c225dfac8c64e27ed1b4599850ac69315494a4f0770e9d052f223beae8eb0020adb97dafc50b5b8695d5ad17f2f1c42f528c88924678a929abc284fca32b4cd9" },
                { "es-MX", "701f455d9eb70879be58cb4e7721bdc138569843c4853b5ab7556c3ac27315fbe637166cdda36ca67e3afc0c407b1b9bad0ed94dccd5cc10593273248f183c6c" },
                { "et", "2801e72e1265f01801819bc6f131fe5b139780237801043f66a56657d83c46496a990739aa0e7d2525494abcf3c3c1e66b583079ba1a9293d0bdc2b5cf62d12d" },
                { "eu", "293a33e0d3856cfb397cdc2cf56b860298de5b81ca4764879d60270e549b7d27b12763ee3244386c2aa7a931e815dab717803888aa28ccff60cad4ca62df4dda" },
                { "fi", "3b6ca55afb6f12097f7210beb25030d36c7cb2a77a926b86c6e402ea3e36f069f282090ca8f1879cd33e2674803b9ab992bd157664011458301dba0de67a4c77" },
                { "fr", "bc4c68f0f8fc00f44503563f5e7664fb0139ce36fed701f0dd802e11c40fe120e6f3e6eb7cd3b055ec458fa19afc5d1e8b18813639a60b355eb023b755e34f46" },
                { "fy-NL", "064103a2ee56ae440d0955b20a6e27467479a63dc2636bb15caf9746ee816ce05aedbea59c86c62d7949e110df20a7c4add64558f77a3ada0a2e5ed83480120b" },
                { "ga-IE", "fa738b0719aaabeca5a9c1a0193439f503b81d9f2c4cb954b1b79a125364cfaf0ce3bd0dd9c6cf187383b88f2ae21512ba58592f9d773c857dbcf426e5f0f35f" },
                { "gd", "6d2a91645f6a231df5957e047274a9b10d7161dc09526c5e28154c2142c910c6b3f4198f0fd2ae3c2f6e760441f499be63876e0f2274bb2319c28d80f4c22e28" },
                { "gl", "0595d0e124d98f121d53c0abdf11301c244c742fe844113934ae2991c13a9a96750abd5407fadc0e7c6010f80ad575bd8058913f7303d78894dedbcf8fa9c6e3" },
                { "he", "18355a97152b2883448abba6c2888af8987d8b033dde9cadbdb6616cfeff8d4dd17081b4196ea9eaaada63f6817376daa5b05f7ab0d351c47a1f578a884a9898" },
                { "hr", "8e0487a2f1eb3db5a0c9b183a352f6d91176d37ba334116f9e020db93c0d81fdaf1817d147bcbfb70631ea8898c4398d1cca1cf06caf878e69833684ca2c8d28" },
                { "hsb", "624bef94617a2720f39fc67b2959563957e655a40771f6b94ed08df4813ed93f2bd9b21b6f183e9eb76ea753f12e49575a6ca88699329703a24a5d65e018102e" },
                { "hu", "07b6d05202422b12db9bd30d94ea24b17eb55e9895e8f3ee3078fc1272956d9839bf24208cf76d238432f51a2e887b4966a59c745cba6cd9e99b918f3fe6526c" },
                { "hy-AM", "3568923e177ebc923883796561a2cf09f73c1d23c1b47a5427d5b8d20ae1c0acf6fb85151bdb61852cae4ddfca22a454a85266434067964c70ec80168769f17a" },
                { "id", "1202bf57cbd23b2d08730360b28b3718681435f7d31574d5cabf85843c4df59242dc0901b06987854dae3e33d4cb10ebf73978fc03bd800b214df2f9c885f73e" },
                { "is", "998d94f87149bd1ba818fd217e1c1b82b42affb676f6330d304e5130bc935811b0816cf429d015b0bec48aee26b0c7eda4b6f618f59dcfc49ff681b15281f135" },
                { "it", "75a14c09ed900492e1c43f2d209a355bcb061d00c395d030f427b43e947cf98a46b7279d17f99ff6a099b43e25d3c882b5fbf523779f921dcf1d0b358a85432b" },
                { "ja", "a06cf4dda5ab8ed2b69f4a95b9508692e9f57ab057f170757cbda5f07f86660dafedde705f0fcfad7e8085f4e87bb0206d3f9cbca7de96884f7afc5efe15dbcf" },
                { "ka", "ecb34f541449f3b92e03ceeac78e300169417077737895d8b9f7371eff9d4bb09ca0cb9b561655507dfc78277b583e0a7763e1d1f85a2978f74a378550160953" },
                { "kab", "4a204d25748d26eecf58469dcb417563c6ac9bf04bf0f2e4768f25e7223a1638fdb708f52ab880ce19b6cc9353d1a086e17d7f29fcbf4e119ee31f4ed8c288cd" },
                { "kk", "73a5d5e329769b45ac13b7f888a627f91473762bcdc6d58584a1d3d3bb341a8ac0e0afbda0550657ef622803e659b13b6eda1064ba29a4b195aeb8b8d3b17f7d" },
                { "ko", "75fc2b8f8a0d74a5b4a5be51ef37518ea788381c1882fdabcfd10bc2ff834fde65f255a4ad4f1921702e8ca328e7b402527d21d8ff52905bfd61c0fda0ce2707" },
                { "lt", "a334206ea3e5482248cda203f5be08eeef62cfcc62e67ecf8cdd8b1c9c54c1f597123b472753f4d1af24af98399beede36a4f2f4c8b33d29f56957e3ef935cfa" },
                { "lv", "4846f9f81721fad5f570439415c9ee74eeb1c9c1d276f4585e6c3cd15bd6540459eb304a04cc6e4789d6f8fe2234e0c44d2beed99a3d8ce9e4cb1390d81e150f" },
                { "ms", "7bf1d93b883a4fd9bdb20269746111234c8a31d42a1009c2cee54b9be487566d792ca0e5be043aa3d415a8a9b9d7deedc048eab1875581213052453a8eb4922f" },
                { "nb-NO", "6d72c9965afb83db454204f466671b2cf571756e153f76e8be35e853a11c787df5322049509d261a165c75914c2d812406b205472d6e5123758d385da6904f18" },
                { "nl", "cfa31132d99863e60f087eb7eb6e8b1d2e1c57e3f4b584c950af95f93c4c24916cc51cca3767e847ef597dacce66fe99721f881f6a366666b2dfece56f1de642" },
                { "nn-NO", "72d6090bcf96147c8efd4fb01ad3cf630547f30134bd1eb21e4edb496abb97456a9b3ae84da5870721baec997c626e8d3edbbaebaeea5a62081c0a0316b41518" },
                { "pa-IN", "132d85c7590fbb54898d4cd6666188a2d87be815ed7afe25c46e56d5dd82e5df037922dc671e07b72b5b45a88c00cc8c7ae93a4a679e272ef5259444eade43c3" },
                { "pl", "3e3cd1763559c59080b080f227ef651d7a245e3b5c11f6facc9cef164b060225cb0cb7da710f0e490560b36faea38bb4561582cb7dc6326d9ecf4b36405e7b1b" },
                { "pt-BR", "37a24d3c1b48861f6ef0dbd4932e0a29c7926110581c2230781bbe2afcedb6756d1b6cf2146072d7d3c8386144adfcf2856fb426d5d7f5461446b95be1e6111f" },
                { "pt-PT", "4bbcfefb189803289a64c770eb29df1faa38af2391ae01f121c3b51819a1ac6b2effbe2d40694125391fcf93c854ed8feba35816a520abf47ff87cccc16fa4b3" },
                { "rm", "f7918f418b2a578144e3fadf332b0e268fc29f69fc9dc449aa40f86f5435663897a2b249aa0d95fc402a0f062983ef0d65ca42b2931b296931cf2c4e586ae462" },
                { "ro", "3589246f5f569c3b14cac2e8443768eb25f69b361f979101bd3bd2825d433078956d4fb7fb937a8af9b64b222259a0a49d5f9133c27aac27ecafbe29b7605cc6" },
                { "ru", "6b09f98be952241915a517fdf3a6b454016b9d8a504eab0932f59c5e70414506fc8235a72f3a53b87b1d16ad9301b6726b1ff9c170de473bb602c0226c6ae9a7" },
                { "sk", "9d982d7c62e52d968429d5bc6c6e991652fd4037f147d958b48d66ece403a8f0fddeb650ce2928a0cf3a5e0cf47193d6233837d14dea382a1447004da82728b6" },
                { "sl", "2bf157045b171bc8f51deef0033a4f0d7c90b2bd263b202188a9719a6c24077e2d4e9ab6eb565d4703e4de7ea9bae55a1e93c80a5d54f1eed98d5832b8240667" },
                { "sq", "26cd037a78bb3c98661243ff0e78709fad971806141f003e5b329da27e29a17b532833e0281bd225000f312b8b1681a7dda767919da20632c4031e3f3dc507fb" },
                { "sr", "7810b39b98f4925a37abe288ac2120aced86bde78eca6a33186b77e7b92b1f3149b86772a88f40c41142b00b59ea586a0ce4fcb8c79a3f94f15c911509220a5d" },
                { "sv-SE", "435a338c705fba0aa911d981c8b0b822160fc02bec8df983d578799ddaf01a5312775d60e55c8a5535bca05a0bd92470b3922d8b8e540dfe8a95d0cbe35b8c68" },
                { "th", "e54e49338f13ecf49773a987714ca3b89ad13a23148b35c23a8bc0c755876a06d116d1bb190340c034aafdf953f2211af670fbf7aeb670e7abfc4f46e79df8f8" },
                { "tr", "857db454d9969c1fb82dc4708209614c39684d15a597f0cfb6a246a7ffb865137546987bf59bca3549498b9891956f793d18cf172b5eaa222a61794b283b9e31" },
                { "uk", "47608715e09f9174697e4fea19e703254cfb24b4a953537170f65e23af15d4e613fe31388d93c64f5b96a79e5a692afa869a7458c0582dd946c41337b80fefa5" },
                { "uz", "0743bb5d624550dd8aea6143d6b143461b07fc8b06aceff1342c5253f9425545587b20bfdedb699b62d0b535b1c0fb7aabf17346e7d52b73561e59b5ac151228" },
                { "vi", "16f0f3aabf5d6ca01933adae8fb70afedf42ce4fd6612578f66c3ae6c0f9976acef35542ed0e61e908b627fb8e48bb55c536d7cf468311c9bb38f81ddd08c486" },
                { "zh-CN", "8b9f20a32f3ece43d3af6281e32ada8441e2d04e52ff5ec95c963d2ed6d13822f527422aa5e909e9b2d73490d135f650c69c3ee0c97454282a8d3b72017591bc" },
                { "zh-TW", "e3984fdaa7804568e3468fc61806f0bbe040945b4e06a297076483166e5347d86ebcd0b7cd4c4666c85c897d372dea17fc033f4726710a0d5507e9fd09ee858a" }
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
            const string version = "115.2.0";
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
