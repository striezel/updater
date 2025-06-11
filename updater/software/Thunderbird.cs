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
        private const string knownVersion = "128.11.1";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.11.1esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "c52fdb8818b36d945041178a41a73e3f6d44d7b55808f9045be931dcf661a41ec5d7a4e2e0d5213070d1c5a579f47e201dbf3ac9e040105564a245294bb2b219" },
                { "ar", "7f10e230c8afcf18883c0e53121450ec98f3fc0342131fb4df2c041f5a2d949c1da2d8314a3fb1ffe2754b912c3f9e2b2109019ba9f3e868060dd33a0b909e41" },
                { "ast", "4ce2a66620efe922c3df8a197207f27038422be1b06fe6517c712f919754820436c2ea574001d50e80fec5985a1085c9de9c3c3823b5e5de9984998a4a723aad" },
                { "be", "1ac304c5e8bbc3fa4db0a0745e2dea7fc4c6cf77cc7bc367cf04fff3e0779170c58a0a024d87276e186e0f94cd134fb66ac63eb8a4f58e47e0c36f10da3b8109" },
                { "bg", "93d446b911485b23e5a562f45e1450ecd344c845e060e066683fc5d8c47dd56f6c025400f004f0f3a3dcf04727f3bfcaf634bfe447640d5afcb22efcf807c2bf" },
                { "br", "fcc4780b2eaf43a3a5d51e3d48c2f32ffdb038751b52de9e5c04d5484ad3bee5ec29b0d1fc51ed06fc80d38a81f45d9a5b03d7da4c22de5687bd1f8264f22db5" },
                { "ca", "2e53c7f36d5cb0d4cfbe3cede531e579ae41c6e327568f76d5ffc098a799a35f099c28b6c6b8310f41f57b15c68feb2888a8f65d484d969040397cf57d7a5c09" },
                { "cak", "fd4519ebb20c116c4e72171d48687dc58d7cdc3e7268eea37e3b6a4a4856dbc66f642c58a91471afd899f661d58f29ca28079dc9ab178e65fdeabed1387eff06" },
                { "cs", "a865c0924a2f2bdff558d34d3034bb563268deb47bb74ab5b331ba57e60c610acbd002ef8127ab430dbea8c99c23eb933382d666b5d5edb60fd94f9d88c89e9e" },
                { "cy", "c33462059e14469b77ade98f4130978422cf9920c03153fa5769f7841e60f706fc7b1f23a8ab310766fb48c6a4bc7ec7ed7f6026701591828b946738fcc00a29" },
                { "da", "75f55927a019524561b2407df10ff8e892fc00cdee4acb3d13b19726b281a279c1c162cda452aaf59d4f0de34c69db7330f899608a3bef439b4ef31bf09d8c0e" },
                { "de", "291df07263eae4485e0ea711f00bc13496657ab7f3b31f07c4ddb5b1592e8b2b34aee89533a38ebdc8e54a11602d1cb82f39ce5e814896bd6b30be643e954103" },
                { "dsb", "a256899ff7d4701b45475001712b87cfa5aad2b10788095a5bba96c322c16b39033be611f7fd66b01de08d6fa4e5702f54c500698236f689c347ad41d3d12ec0" },
                { "el", "e11ae714cc4a69d154976721f57b517460827dc170e6d533cbb4668122b351b320391c844b91c1ea0eae3d6646c9fb150b6b7aa5fec2dab10866e29c66f38028" },
                { "en-CA", "1e0a05197451f48f69bc51c5a3c1a664b2d8aa785ee0d2c3d0754b1d98340d170877287be88182fb2789362a50f480f91e464e71dae31ba7388dceafe257f5f0" },
                { "en-GB", "05bcd7ca4384543c8c9c7c9e4213842f0e7092d045ff086d8f6ff970f5f0eacec5a2db3cfeed55a1bccfd86f7287534b17e28ee56d34992e6e29fcd7baab336d" },
                { "en-US", "76446cb177557ab932d77a0889af058d5d48d6d46d60f0aa1c9a04662146b44220cfcedafda8b7d2ff77bfd92ac28694bb609c93d765f548f1be1fbde4fc1701" },
                { "es-AR", "11ddee08dcbcf4d1cea144436c1ca8ac72103e73e656481a48e98402af8af07c89eba1adc54f20e8fcd1cd369275e41c3852695a21cacb81220b73e562133618" },
                { "es-ES", "27fd663d5b363fa1295d1b8a423fdc8d0776473a644cdd9f802659ae957de26a5ac929c532bbe391c00159f10c57abc9e343dd3a5008096592ba999e99fc9a7d" },
                { "es-MX", "35306f933b6ecd975f4f56c359860982ba7d89babf17b8766555ccef631b5a99370362ab3b78ed6f7431f953ab46d99caca0392e87e0d55e24b1f5d508cb3161" },
                { "et", "cb00178ad19dd8fcce9eff697410bee42f61105876488ba8096c7ab1641d6cc06eb6d87a9ac68c3e9ddb5df5e67173e4cc3a3f9c3cc0c07875a4c07ef8d56600" },
                { "eu", "bebbfb2cc5ab2193d6563ae51c7e27e71f87ef814d6830fb2a34c1aded36b858819c9a8b573b8eacad82bdea4ea3b64f460aece051ff9e133b614c52a3def31c" },
                { "fi", "198032e6396096d5ef09d27d89d3e997002fdcaf3f52b33e01f63f0eaa9494bc3d4f6d50ab3b647dd64a4ace84094d6540f0edc8e4bfcf448b230e48803888c4" },
                { "fr", "999ec2c7562dadc2b34c6d41032a2c3374e85217bae155b261af51d3eb4ec8d6b8a9db774a84863c9ab1b7e12052ee95c3d9732663b1ce934f4a418ace16a4b9" },
                { "fy-NL", "89f3337c195c7770637d7afabcb99524dbc6dfb97ba8459a9c12111c93af79db389e5b651cfdcaa3825b8c710bb8a546fd9e11d2b29719c1008aa8792b642627" },
                { "ga-IE", "085580382e3e7b3ae8cb524b8949a76510303d264f5422e7c80bc8dff6256046bfd0a5153dbbfa7c6d9c4d3e41590fc7bbdc9140c88c881dbc70b156ab704dde" },
                { "gd", "c395b9c48037e7f71c59b78478c687bdc4460c3d81cfbb2f1f4ed617636a4800de16d98c4df17a838504cf88480bf00edb5d8f4d45367038720f643ce4e2ec31" },
                { "gl", "55fbf73e04aa2e6cd797b13700769843080e68af32e372915e99a4d7aed0e15720c90b8afabcb16045136c74cc9479cdc263b68af389d9a2ad2dab6bf8f653e7" },
                { "he", "c0d75153fc50d8d970eee55a8728b042559051429073dc192ed17f12ba8596142a6d22473a9a66df567e116b085c72ce6db2e1b1c8189e3a018e3a75c346e460" },
                { "hr", "6e890d7df613e5d45a8a17fde86eed1b124d5465493fc7e42d6bff0e40c87b8e8e351197a8fbc7628452309721825efd4f72d447c7fc971ebc3e75dcb2885e5b" },
                { "hsb", "cd4798b9b83d005472abce16f5c9ed183045ae950279a37f18bfaed61861b415504bc4b9fd4ed1e91695b743b000f3c7a2023829a6ced54f21bab7182c72dfdf" },
                { "hu", "17c4ba685e5b02e58bc5f89f1acf18bb9d79132f9c2b0719b321c8c7b6466f48ffe4fbe0c7fd3739cb665ff13dc0516ed02370a780a644edd069ea8f3aa61987" },
                { "hy-AM", "3057c6707ce5c11a54ecc5a647b3cba4edf949a263ee1b0f6d5abd4f4cebd37eaeaf48a62945c7fbfe55689fdf6c8508e5438a6d6f058823759d242822b928e7" },
                { "id", "3efd50b3f118a70a8b66e22ea14254b951e8b897256f6bbe5b9d8697208ee3e4e601189ed1b0eaf25196c01ba7b4445e045e3c0706982abe73a70983c60899e8" },
                { "is", "9e566cf12ab5be8128d0aa9745e90fe05456200b4b205a897ab0792992ea586c44b9cd7a85f03f19449e4480cfb8f4702f9496c6405778f2dc14b01f3258188d" },
                { "it", "e0161d6497f9b8e2358407f29d17550fc6709873f28eb64547647eb1e489fa40f16a60b0ee15fc25ac37056694133a716fefb47d3b335b398340760b9d488097" },
                { "ja", "bf4462393edb44d6c30ca0a6cf1de5fd346effeb755f97240a35361735b0619bda38b7941466ed6d955d4aca67cdfe0de6228f3410c891088354426e01da1b0d" },
                { "ka", "6935d9595035f4020a808655675532bb30e9125bbe7d7f75744a283589775e2735289d164461f5308af924fdb7ab22b8add0ee3b7266c5810b35f43a0664c53d" },
                { "kab", "72723ab7b48e03e46a7b6d8ab3b8193858a7aae9a31373910aaeec389032a33e4ad08b8239f97b35c7a3397a41a2e24228b130ab21f618628666c756776f7251" },
                { "kk", "93a2747893ab3580109fdea2bc1383f29865d4cac2c7a08640af264e3d69b632ae48e0c01c18cd4b790c9fc4024e420ab964a6e0516b549ea3093d8670cdc4f7" },
                { "ko", "438078d4f04845871118e2b1855a80546c0f14cda43eb2fd76bbd4ea6c5a5f6d1d618cdb714f37d61ebbd8e89e216cd9a6c31cdc02dde0ea6e57ebd099476e3a" },
                { "lt", "0b2057227219af94096296542d98d5dc10c298540e1c08e706d3c690c728f2a789eb95ab6ccc87896accf838f8b0403a51298e18d7c1966b6c2aee51eb759275" },
                { "lv", "177eac7946bfa804740627e31dc6edd782e2610d67bc6b6c5a1c2f77684e8b4a4f33ea2476558784beb4a18a4c8055427a2de20ad3daaf69a531cdbc51f337ba" },
                { "ms", "45ad9a8e7aa20733d4a9bb5247974882597d770c72cdf3ef421a1b5db43b24f8cf60a2084ba5814bfd0f0a1dafcb7f362f33c4ecacfa00d368c1d5fd51d7e1b0" },
                { "nb-NO", "c5fd1100163ba5593451227cbc22100c4effd43a217e21f817fcbed82cd585c8f95242362d4713caef9f5baa6f874a3944ee75c6e7d37de4dc69ca504afea09a" },
                { "nl", "377a1c13fcbeabe6383f1765ce3d2ae10f5bb11ac01fc50b4852c03779d23c8a64751d0398f26c8199efeca8d86628bb648a3e770ee2e48f76dc9d9d75a14098" },
                { "nn-NO", "18706659a9b059453c0ae6ce01e209ef9d7d8e3f6dbaf025db7e25022a06c6b82748e8a2be1efc5e34b11565dbbb24fc75a7829d96ee31c90702d05bc5388d14" },
                { "pa-IN", "16bbbb269fda15ac879174c14161f739811611e48bc6cf173eb2b0f7bac9b9a02a0ffa4ca399db5d804deb00ebbef9cb40946cd514352104239831aa80de50bd" },
                { "pl", "cff655183f1fe87fd54db9e13912f8059880a443efd4bc57c48c28aa699ed06a3866aeba66cc357f1d2ddc37f13d3335dbf84e18c9d1ea0aefe18496ad91cbca" },
                { "pt-BR", "02723d6abd7e9d9f5082d4827094ea296199e7a5de46e1b503a289e7b67d28f0e9ad0bcd2a658e666d7dfac61f08a1ac576e0befdce7b910ee2c1875338b0b72" },
                { "pt-PT", "e8af45d9a032aa6440ca5138f4992c956254e9487599945df7c2e631a955e60b2762024dce400dccf429b7bc1a5e19fa0282e0460a188fbc6652d24ba5336bbf" },
                { "rm", "13e74389d06e39d0acce82b7a35c5935d5b0acdb6b494d43373deb005c5be3e426bf776d2053cb55ab16947ddf5505954d6fd280099d33d6a866a5e0858be221" },
                { "ro", "ba3bff788b8b75ff3d14f1656568f21c3f96875c56484392071a38f61e03e820c0ad88913ea75a2b50ff2b6fbce7e35e019b64905261fd15acc66a968e4d126f" },
                { "ru", "4be2d263187e25415274ffa9932ee305bfcf51f163dfcf3ff39fd712330fe01a6fdd3ea1aeac284571a5590283481b500619e0f982f31f0ebf82c782a9888faa" },
                { "sk", "d1f31cde6a39cd3993de7082ee1fc4ec30b3889610675dd9788e8a5667060b4aa8218aef52db4384530bc63bb3afbd6d0f05345740d4b7817ad1f1428e088ec3" },
                { "sl", "d884a57157a2b85aaf1f8a411198eab60b6c26081f8fe5af1810e825e913458f05da51c91de328ba9c89eed800ba5c723649fd7c888e786a29af877d904c6df5" },
                { "sq", "b8e6dcda7c27ea87678c0f82d7720ef57d21d3c17ea11ba9fb62b8d90f13704f78fe505fa46276fb1a5ce74bc1e8321fd0d6aaee5f576b0614aa5678481d5d2f" },
                { "sr", "33f46caca01b65aaa3766265c6cd4785b0817579d34bc739034c9d460931eede05071c47c9c56e7cc4e612eeafc3754cf6fce645ad1d3cc052c4a0774b90fac8" },
                { "sv-SE", "4b6f8c0ade1702ab1c1a67f1b52521b342eb2e627e011c26cc942c5fda409adbc3f6e6283c13f31c42cb977437787e7b6df20b3a13f50c3fbb32a462eca2d652" },
                { "th", "611fcc4599c6a094c46d81a42677f46f4093527638faee87920acefabb5eaac5073b7d1134a032f5d10385d8d9e8b9c9c563c4bd75f9db2eadd0b91cb14c4546" },
                { "tr", "4cca068398c7bbf9c9f63973cfd43379f932bae364f83a275dfab17a729ea4483b142c11f70320291ea2705ecac49902d0db32819e36010e9d770ecedfdd308b" },
                { "uk", "1da0c5067de7e3f23472788012a1ccd49651e730b38d9b9489385ee9103aea5f3bda001602d50f5e85b63d99e61c8455b71dccf6240a7c9670abbf1a47eb2dbd" },
                { "uz", "f6799dc9dce089f8ad93d27041671e4c2c9caf0c397c5be2becc00bb4319eda39b529d2b9b021081dbf44e5e17f4df0b0d396d5c02ef8ad2789e1e0fe311b365" },
                { "vi", "66a5f7be20ae6b97fe0473b74feb9cf35946ac8740b5ccd9a8f29c6ff0be207863069edc54226497650a7c2eecd96fc561d730f2c18b6b2a098a344bc68a993d" },
                { "zh-CN", "fe9c5f1c29d17e298044ff275a7c5d4e0196e228ed4674f4d4922177a58f4f8563712b1595b7740b01450d01b484391c927077639a951c984237e0015335eaf9" },
                { "zh-TW", "7d8349f651bb8fef3f3b0367a8f2e6b8dd146bf958be8fb2024e3ea77e3ea78c5284325c469c6181eee5196ee470ef4a79ed38c87050ef9cf8100a9105ede08d" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.11.1esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "5bcb6e669b20b4ff93462429cd187859a08a6f2001e3b90aa0c0fa03f63dd506b56c571e0bc0b1224e5f97d7ced5876950be725c7c1f3709539041b538bcbe8c" },
                { "ar", "608cd76a5d6628eeb9791fbbd85639244e96fa379449a23ecb592540720f86fed260ccae0a9bd56a620eb0ffbe7a76ff611314ffb8346a04f94e0d52a8ca1337" },
                { "ast", "8156957d2b4af9b798de435983b921bced6c77d276b4e70a9fa44978a62efcabfed3591ddad891f55fcebaad2a8cb02532da5d3c1a7dc27824316b8e201173b8" },
                { "be", "ec37d151b7cd4ff7bab92001d8cac90bd35b485ec68585d7610573d75ef704d9b23e66b3db9b603e7691bd488c9638aab7c872b4a395891fd1aa4f65775aafe5" },
                { "bg", "ac85f1774fd12f6dcab7a85b57f641f7541eb038f95175de2a243c2e31ea60716b88aa7a16efcc54f833ffe0c7d0fada50f865cefb27cacf98bb484f6cd85c09" },
                { "br", "6ca5a2866537c8d44f9e6b47d399312399239862d68c1872c66fd95f895786e48afc70d392a2f14d1200495504683acb3b6781af30858782886c7e3911fd424f" },
                { "ca", "1b985b050b5e7b7c2d7a33d0608e1d1c286ad614c9fb96e724dbfa111c04220336b5f01c29e475fb526a940e8600b131b66477d4c82b41f03cd02f4db5514ae5" },
                { "cak", "45151d9c88cfcf60897004d26bbe276472cd30d207e30658f16dd35cc17f7679f401b96950b52bd1290f87e9ffe167ef2fe4e9c820af170a461d46f13d8036c0" },
                { "cs", "2c37be0f8e4830472c76825faf9cfcf7444440cedc6e8772c8e7fbadd41631603464d5909e4ac62c1eda3e95629c372d325bb90b6f97bf21707d6e386dd25580" },
                { "cy", "d97e31237df1e6b8cfa7db50dbba4cf95652700d2a4e15ce022d674d87048d7bfaf08041d88f0dc9249bc78740b7c091e18e83559d2ebd80fba5060149fa0766" },
                { "da", "809e281bdf4a2b985e1ef38759d368949cb631025e97f9570a026fe92b37d1f0a91b8da8c6abab82fbba2c7784eb1dbc1cb2f115f789ea26953d86589cb65c41" },
                { "de", "76a44db6fbaeed3159a39147ff7c59b909fd6aa874a8f2bb8e6828db4d0281b2b2c806a19f8c8107be2221cc6bf897543e60ed78d5150c108d2a6c7cb17061ab" },
                { "dsb", "6b7959da2e310c33d944912e7fda094ee9a659c8efd61f062119de0454249833bb3ebcfc339a66f90398d5fb73a43391681e116a7e8dd232f32321ed5cc7da14" },
                { "el", "c97d406eedb0d05fd1df28559a6b0758d1346190ed208be0fce0783a8b9ff8f7a16530180dfc8ad30d3fed6c90071051e6b52b31159a99b609231f12e28963e6" },
                { "en-CA", "aef765136b076630bdb5bc8fd32f5a6598c5f3166ce05574539e3f7ae0e0e901d9fa690db27a4ff5582e38d7ffd11ede6aa9a0c330aa75df08019af075d2dbf9" },
                { "en-GB", "ecbc86a76be4218182e9c67f05aa654ac2d5f60834c09a374620730573bd58f0a0f84c4777349a7fc3d94125dd26080e6a08ad4c5959c9266ae9d0cdd69f6a1e" },
                { "en-US", "929512814fbe13e726b1818ba070e71aed6eadd680c4ffafb6010e696315039e9b6b5c319447a187e300a833cc63a580920f7a1c45bd836996ea679b637d1b2c" },
                { "es-AR", "94451b2b238009ae947d964d49d30d5b108d5834a82b64ebf9cd27f36145fc6f361b2da0c4ab0a3434e7056935d58908c195b5bce8f25c2383a1f83e1660b393" },
                { "es-ES", "1e291cab0195fc29000e8517ea4578a56b3eb0d5a06522e93110452cc0c405e17cc77e14b83cb239a5e37f37c427ee7c0f232109e145209761c0c009b9bc8a44" },
                { "es-MX", "ad1b188a97c68ea63b6ef7796c4b03b9a5b3528693ed048f9f313b91040533c83347e64cbac3e17dcbb766494419fafe5beebdac367a94f2976d8d85e2439807" },
                { "et", "43995628fef27cf7b2c469cceea88a6c209e8e8d84f5ab051c82772185f047dca4b2aab32083249fa7eda3e0351a0a292645a41f77a409ae5010c71cb8fa3767" },
                { "eu", "69b3f45e475dfce9f39363d1f696de3f605d42763c0ce13e06bc91f2b5246553cad062a3d1c88f3895bba6760a3730c276f0637c730e3efbbb87df1e7f736bf2" },
                { "fi", "3457fb3eb1bad845a4946bd2635abf68faa03306bafad57bc3c4353cf44b2cd601b4983e574062776d3e5502da672825df09e4e0466b97e29a70c3e697d66d53" },
                { "fr", "a817ac74aa3c35e9225d3d7f3db00f34cfe7151cf1369064431378209a8fd025bdda3e1d5f96302280937dc2e432a3919f9a3271daf59209f961bf5a55496624" },
                { "fy-NL", "b48b1d22678929da915fe71cca0b4ac4dcb12e62a3255503a963eb575f7d60723a5cdb159fdbe26e42d3fa2468959d862115598e46a5912966e2743e889a6b7a" },
                { "ga-IE", "76bcea9d354760e5313c2e64800d8856550ab99a39388b672a04d2dada897b603ea074f266e0cb728700719fe51e2117da0e2b278ea42d4d5af5bba04c8dd453" },
                { "gd", "6756eac79bfd54959959e9b5c522f8c964b9ae923cd5f8f962c59f26a32c1738fb28b5e555f8ad284fc5281cd5cc59e288aecde32412f3a39fe70648e875861b" },
                { "gl", "f2552009f40fc5933b7edd85eab07ed645aadb7020c406a4b9ea926033aa5c0c9055c16c8500ec05f33237f7d5e1ff107a0f57dba85c7ede314352cfef8eaef5" },
                { "he", "d2714ed637969af8999ec55c7b2f463b07e03fce72b83642a6ab58a9efa17b130123039c7ab0993038bca91f451b266d4e5b4b5b118e6f2d3dce010cd4a753c5" },
                { "hr", "df25e3e6e151632016aa41d970682a6abed6820c441b421cbe6b542dfdc9811b345ff136a27af47c13de354bcdd8ec2ce0e82f52c7c14a9ae12f955c0145f613" },
                { "hsb", "00090568dc597a66cb36164d8a821bf412da488c32994c1033d99d2666ab54114bbe984870e740107799995a9cdc9171185636516e2750463dbbf8ec6f827204" },
                { "hu", "08c6619af37dad091d808ba334c996e6fb7a27c5a666376387f23ebeebf864516a28396bbe6606575a157665e5ae3afe671aba4da0ec2b77574cc5239b6b9676" },
                { "hy-AM", "13cb8692c835df85a42dbd5bd45f31822b7b67b245dc4b36294d36cf7406b874907def57cdc6e416474035e0434226729d96f61296d2fcce2feb701dc62a0411" },
                { "id", "8fb5860e7bb4f74953220846e3a7f8e3650bce420c3aecce5e2827fb0893a7dd4aeeb7a869dc71bee09808234244532237eabf1d3632acd828ab7d30ba2a05f0" },
                { "is", "df71960b0a68192754d3fbf709936cac53e001c1b858ca8b8d99cb41b892d21e8ffee9b38ba9cc9070a754cc8caf0db02442ce6e15379acfbacd72f9c4f2987a" },
                { "it", "2b626601e88da75c02e81eb90ee6e1bf0657f2b1a97d74a5a73fa04cd50fa7b8a82f4d67ee4db9da2f959499741705d9fe5c42d3b921a081876d38bd496830ce" },
                { "ja", "a697955e6ef0180ce510d6afaffd89541b86734ec82e225fde484c37b2acc7ebfc5c41cb8e6f135d8516e413fecf90038d902c18c4456e3d19c8fce77109fd1e" },
                { "ka", "45568197985f96e80c9cefdd91eeb4b52b7ab3b0956247e67abab145c09e07ca9fe57ffa9d850c1aa75dc6cdc5748c322bb9835ee56c99b87f22e64064146830" },
                { "kab", "a4f4dc31c06817af99d11af9bd5e304e7a940e009bb8d31b13a2afe02c4a5afb8e46b2aa849c1bc3d9b7e14474db6e3c14ec7106a5db91802f781ac672fa747f" },
                { "kk", "21c65fb0eeff2b3349f36fdddc058315f29beeeb358b86a9d11c1f183e13699c612a37559001d83b4745eaac42efb811d07ec205364309f28785cda5a363a93b" },
                { "ko", "fec62722387805ad9821ddeb1ac19417aa8f3b66da71618cb7155bcbd55b80d06390583156d6cf82ada85dffd3ffedda6799e83195e4eece8191746c83af6a84" },
                { "lt", "33da042ce074874b44231ede07e0a12cf5f4a2790a297c27afedd8597129bcd9abd7358de4830e9a578833ee4111e01a0b6470e4a08650e2725c94a69ecde807" },
                { "lv", "1a38fdd876c5625cb66b26e0a1f49d7bdb0ad3946c0b3f089c060db3ea44e257b13e735f20463d096ab56f65c9ed9737f3ce1ca3c211f14aa112e63a12d3a73a" },
                { "ms", "c2cf82e9061f8e41485491ff053b07b8d7f1af3357555b7e11814663f1647c0298ab654bfdae300d85202c06e4a8c4cc7c8ddf1ecb1335084d22a35e1c717753" },
                { "nb-NO", "a12a1c312fcd41b6d68e9c00856dc2b2a036ebbb10651bc383eb9130f07d4aa101b9eccb01c340ca43b43a30ed19e5723451e7f1b09064bfd1edceb9cece9c6d" },
                { "nl", "0ab3e3bc6b3956bcc4484d088d73aed73f78f53da1fdd71d36ff020c3e94b8321bcea9391bcbd41d31433049f771978f68ef3eefd21b5eaf1fdd9d8f3e2068e8" },
                { "nn-NO", "11d550e3f83eea310bb63f413a4a136adcc732f4511f1a22eea19e56780b00b1806c9336f778b216e8f55283093ba0c9ba0f32cc4aee4e893f09dd926bb9c095" },
                { "pa-IN", "ccd515d4331d027f863fd09d7218c89d9177225de161a7e3310ac77c9ae09168a4daf7df1810025610051ea7e804c8edd691d4e981316da487280719558b1dcf" },
                { "pl", "13ef68b99a051b09843779518d44118182baa61879ca8769cb6c0de173cad367240d2e0965ff75c7ce483e3691ac4e80a89bc12f0d9406821b023a701eaf96c0" },
                { "pt-BR", "9fcb602a79d6f9a2add769fc666d7988b772cb1d500f7960f8223ae97e56263f9730c49f25d3eb14085b5b81a8088778fdc21d7f039397485e90b7861fe9b074" },
                { "pt-PT", "f134180ab6829f33a32d81859a88fcac9129b469bab6f26c008e2a539a38207810988168b7e01ee2d3b44d3cfc03e1e286810b3cea78ce10bbbd033a5e1a0454" },
                { "rm", "28fca9d44f791c70fab63f5e134a66046c8a33c118cbda3143a490aa409d88596afa7fc3cc61c8cc8bf8f666caa615394fa7c9361d0ff1c6edb6fbd584caef8d" },
                { "ro", "f68506aa6269bd1e52e00b84a8a2c15042b57cf855c871cfb378c84d3aec92e44be3e52ea1b340fec2240660d314124ff6fd1a888ad2c21a32e697c01f7d9a71" },
                { "ru", "4ad7a77ac6c74cbff962eee2dca18f9a046d010f7047f4a05092adf14cae3631529eaba1596c6f6d47494919a8cde8a44a282e4a57a3e786d494db0b26740344" },
                { "sk", "a73e26643b147e499b79e1dd46fb5b42e2ac0a2e39c7e7ae31e491c2316c5e648d1901433112e164f2e971362c2f832bd98bf9c4d498fc72d8bf697a60e7b275" },
                { "sl", "13a397e331fe19b604e56302ca1ec9429d8b0b481191bb2cfac18a0462300c654fd3977ecc2de467bcc9618c58f94a1fc34dfcb425368c0325f70241b810924d" },
                { "sq", "a85324d621a9d8936c2a129a9cd5732d916dc63210806f8977582aec34f1f64cc0f90a49f0ac1d9952a5ebd5f403cf88b9214f09c2b6d4e9e3101c9da83db484" },
                { "sr", "687c32c7e6508a46d97aff87d72f731cc161c3d40c95666255a5f6dc1af641ee2c208a459174c017742a756d7f10ba80792946f1801c2640a5aabf8aa198db33" },
                { "sv-SE", "8d8420273d7df1e22a1227fc4f9d12c977d8b7d2b67f916521a7d616b997e8d2f7e9c9318a37da0fd1a87e6f303fb0b8dbd0aadb75a919afdde3a25053ab8b36" },
                { "th", "eb955a0bc1458f1e4a799ebf2077b3606730a50090ae2de3ab366f455c71bd1890ed92323902c55975852d0cd64a5e90363078457102b9ec98814b969c4faf3a" },
                { "tr", "a691ad4eb2d8e2a87907c0ef6d062f96f5b9c64f0ff086580f6c927580a9f7ebacce88418ca8ee6e8df9afa8ccfb08676b11dbca93995210f8b7c893d1940446" },
                { "uk", "eaaeda656b5dc188c97ff33d3c629fc4d3aeed99a6a04e3a182b5173b9e0a8942353cce82c9d3b69f9d7d8f828537d67a65ff6876981f56c8fd0508fcc2c49d0" },
                { "uz", "d1b81a5557ae7aec407825fe34fa75d7040a8578f0cec8abc2e169cd9bba60b7e6acff1b2621217456cde45772c0854ef800b141569291ada6797eb99995905f" },
                { "vi", "d7ee007789352d4de03c9709ba95523722856246b3f4e6d6ba84c7d53f73e4d6cb5dd47e1a076289f8fb169280279802acd3fce3820c760a83ecb3bc3398f189" },
                { "zh-CN", "973db5bd12b82434162d2b37bd8a03fcb9495f06d4c68273ba2062df434795d70c64010920d01151989eca949f8e8a284239187e923683d10faebfd410711ef9" },
                { "zh-TW", "6a266ff6ce57e4e5b00b6ecea6421c578d27668e6fad598444370b0ab9bf757a4b8c6cdd251eca607aa56cf0abc4e8214df4d789b1c66734b2d03f122932df1a" }
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
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
                string newLocation = response.Headers.Location?.ToString();
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
