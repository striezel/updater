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
        private const string currentVersion = "140.0b2";


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
            // https://ftp.mozilla.org/pub/devedition/releases/140.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "80565f974d51b6da52eca8fdae5c729f7441c46ee89bc8e08a780ebbeda0697c427b6c88e570a374c9e72fcd30bf1cd48c246ba1d64451b8b82906c47b7766ff" },
                { "af", "b449e2e04cf2e7ab821a20fd8f1701fa196302bb916c076282ef1f8dd57bc6fbfc2b080d4c36142be14ee0d275255e79ae7a377c3a0f9db3300bacf7a9efe4c1" },
                { "an", "c768900a603deb86b9e2983d2876cbe401ac9dd04738ba3af2280c7d1b7102a37fa2f97c233e212ff850b08988b09a1c904fabb4ef510ed643a35a53fb0770dd" },
                { "ar", "47c75e6fdb0ce8fc5d9f2ddd37204801a7734364c9e2e3f5856fad430037b6e8e0ddd9990d09c6a16089b7fbda117b2bd9ecaf8c059e832e9c7db3a687951ff4" },
                { "ast", "c5380e649653abbbbc5a219cd9faeadfd7237be686f5ebd00501e7822a273534dcf83a0c9feba416b82ea234f718596482bb17b9c88a7d756df65a26e97d7a62" },
                { "az", "d92ef5ddd913a0c25d93e41f64a1d443f75d0ce7b168cef60735b412f537f615247c2235f02527de8f0ce918db0728ab8127b52b3d066936e8116d145e708a5b" },
                { "be", "e8db8c3058d05a779d2d1905e769d4d974f777c9493fe44b511f55a324d6eb4a06ebf9ead13faeb5ad162d6c742d510e3d697aaf62150c47b594dbb397721e24" },
                { "bg", "e8515d4ea61430cd0218f3cacbaa3708c91e4b35d0ac16c181e246bff8dba666ae891dc91bcf0e3312bf09800d319c86987043814368e1668530e843490bf6e4" },
                { "bn", "d351a61c3295b3097ebb917a186f068f8aa4494bd6618669864854677a5e4dbef5443e59b91d75ecb16ab9615800c145d8c31e68d0351d2d57ceda0788fa3585" },
                { "br", "c04a05138f27fbadeb3ee5c5512b7f1dcd4cde6d96b9d70ebb59f7773ff1b22da98da610beab8fbc9138b7ab88d7b1e293870b3071a35dff3cf1e59d4cf384e3" },
                { "bs", "ac485c4a7b475c8ab4b2144102b8c5cc1247195b1278c211626a8b3ec00b17c66ad8bc22821062870318ff01babd1ddc47ed67426bb50761003f1acad3a35c7f" },
                { "ca", "a2337c0d252bf4250e25eb810d6f743ec0ca48c923fc99f3c1630f1e43bdeeaaf9bca5a088379e21a06790e8a7a0d4bb1f1c7a535e91c4d4ec4811c8a274eb35" },
                { "cak", "179c3cbd48debfedf369bc5d8be9dafeedc6525054e64fc7cc1bac7344e4145406bd4ecdecedcfd240771e0020d53eb2c3f11f2c01427536344a5f716962a08a" },
                { "cs", "035b962e91a93d984f4fe3a52cd27c608aba32a16703b602a6906cb912a025fff7df3bd6b9121877d03f88b923a4f5fd8165a0def5a5b6a78db6332546d77e58" },
                { "cy", "8f2a1feacabf8a79b7c933e2b5293cbe78d6dbbbdb80ede9abdd0ba8929fb2a6f3925b4f5d2d9e4846d8cc0db3fe1b52cf82fbfa728974f2779460f93e53c1bb" },
                { "da", "027901db3e99b1bbb3de2f42a803574da7d6723bd0868be1318b24929e62a81c0372a85c4ed313bc973837e90eac525a5b4e6e8c3906c9ee808bf80de9864187" },
                { "de", "5331bcf77d48b5c17c53c1fa45af1edcc022d44a8160e83023becbe9dea724a222f1d29d0238db8b8e3b23db233605b562b4f34a89c37049c0de9a4e63497922" },
                { "dsb", "aa5bfedaa746f0f9262561b4c26a3be00b58866e05c02bd40b0fafb7644d87551a638ac0cfd43785815d264a83923ee6917f07b5c696cf315458e9cd2b111295" },
                { "el", "a370ff1204237c484cdd8250941157ddda0dd45e3aa25049d8f8ae8b2dcb4fcd942c02d58eb4d24ab0db556a80efdebe16e6506ab7b27fdea004c84983ac240d" },
                { "en-CA", "28a00590e6e3cb44b60beadfa2e4e188b165fa56977c46639c4dd0e40dee360de81cd3f5a8e305c90ace621f9766acf11852d32189481883895af385ca2828b7" },
                { "en-GB", "3c8d3d62518930545279d7b050eb9bcdb4d815fcd3603676c1eb72ac258057ba0ff3a903335275cb5c94e919e6516ff6bf016949e83c7f46907ed4d2cf7e0a1d" },
                { "en-US", "defa20c8212c246f0657696b5e1a433d0c72b5828ea60d8d69596a9469c5e1d06d5cc33ce7b2a1f0e1a90ef579301be6bb09030efc5480e9b9e22bf35be69383" },
                { "eo", "9065c4e8803ac0095949ba7f34567a924090ac73774f3d9c3a9108bebd8915e355bec64ead1789a4fa16846da5bae4ba512fdad096d6abb36ba651681e4a0bed" },
                { "es-AR", "d7af4d569a174cbb2c662efc4d846f5d2df6b75454f9007f7079a68ba06360b16f918a46d2a1f1d40bdb390fd7699607bd0aae61520e5c5ff3538b0d7c525070" },
                { "es-CL", "6f0b930209ca10ff6b712a9a56eebe023683e79465974158e134d21a6f076aa83e5b98e5ff2a092ac247b9f9869a9a6e0b1b6e62da2478b6e413181466381f11" },
                { "es-ES", "8e5f746f91809237e3cfe619692d217c7705f7d5da30b163e5d73e97b2d6f415482032315a5905bf4ddd15f20b8a01750ea3138b3a3eb98dcb427bd799058396" },
                { "es-MX", "ecc31c12c0d0dad26c58c7098b8130b1e9dc0ed58529869f40e3631e745e12686518686655b6601c42895f8c2397339b69dfe02dca130add23bff179ca24c06a" },
                { "et", "67aabee5a89d84bd63ed8a97335b94839d6247d358522a90cfff6071d0d5fa7421f2854f32fc481f51fa87a59246013caccc38ec91cb7610999e40b8a33a691a" },
                { "eu", "1a7333e924045b2579b5966eac1e8319c687ea8e90f7b12910a90576950c02a390c1fe9eceeb2b087c99c6ecc4e06d68d3a5df11e95fe217fd6fca4e15224488" },
                { "fa", "7d9bfc39ddbadba7c7bd0491c982ec0a24acc82fec3963875aa9fcf3d576c312f3572c9a8673534f5b32e463b18f86a821a58d09520e75f030188cbdb4a419b9" },
                { "ff", "35707afe0329dc455e012fadca918701f4bf7ea9dab1eed841a534d2bacd10de2110d8e820b459e031e314cf08f57f14a4e4089d27a485112c3a33443f0259a1" },
                { "fi", "efaad0db93c41c67ac9381ecfd23764aad3d41f531fe793713e823d7930ef4f9bd34eb724d621128e9ffc3a4a93ca39efce66d6ddcac4e20545cbd075b64d302" },
                { "fr", "f854bd4c8b4cf5d61d97a128913e8bdf62df1487fa7236078539e59fda492a31dcd135db3dd108d0244007a576ef79b4f83d5dc95d30fd83fdebfe55133b5593" },
                { "fur", "e5345b5b51484cc56226c9ad5575d977a0ae53c707fcfe799625cebec859c7b27d1371c30b6a222e3617fedb4bdd58e1a96a25055c01683ae9bf8dcd76cd6f98" },
                { "fy-NL", "429c2397ad6590078ec797a38797cc5a4f535847de6a4f9151255158bb48664885606768b8fec172e4f1ae78ab70122392d1f54270a778d2c687022af74ab7c3" },
                { "ga-IE", "9ff7141cf2c706971d28756b1ebc0c7a5007109c38590c99f78c7e84798b2d41387ca5a6a95db99cd937f31b24a6ee6d4ea35c6ee6dd67c3f24f3096a95f5d5d" },
                { "gd", "deb4f49f3251c615715078ab88ff8d52cabf6b05ed3b928b340d270e0471fdd1d5bd48e56bbba84dd49606ef2a966b5d40d91dcfcd163776aae0e63b0ab675ba" },
                { "gl", "383825051f1a933cc971cd5cc78f77280e51f3ca528badb6edd51e298ee787d430d113b755b83f10f41a479dbbce55631253d16a1e8559b83472a45d18642dcb" },
                { "gn", "2c272187e0635573a119a8fa222c48f88c8f6b13d7498d3e1cb09837f152095506455a0077855c968fddb8c4c3b6fd0ee8087e9512304dae7ba7dc25a0759e86" },
                { "gu-IN", "5952cb512554eecdb5c02cc29a3792827a19be411b319ad0951ed1f1a0fce1b314957bd4c763049d49bf40e7af77f1496ec1da92a67801bc6ce8f4a8ffc6a113" },
                { "he", "fa9984a88fd774adf4a95aa9ff052e90ce06f2560212fad2281f60760270058ef79838eb6c605c5d2b9b978d96b8342021a888fc06288fd24460d09d610cde0d" },
                { "hi-IN", "ec6d5c759332aa35ff2e4823fddba64bd70084ff28cfe4fd7f575d98a20ae7dac17db68eb106f1d082db9d15b26d569bc5b98762406a465653fffc023b7a0738" },
                { "hr", "3ea6f6abea6d288330e2a63955c729489db798eb0f11a1200b749dee512f2b4486903e5e87d2949ddffd390f4d1d9d349ef5d491c079395f0b7d1d8134a9c38a" },
                { "hsb", "c83091d7de2b4ce1da206fcd4ef67ad746b7a4b9b06c714847c6224a663fe5aaa0817bb8d5a362868f3640be0035f067eb2d01d4fd27950f3707e647e658758d" },
                { "hu", "be5478cd2112b6bc63f931918b6e19800edf8f61d2a37fb7ebfe9cad0ff3f4f7a6af591b7ba8b6c9ee74a61f3f88a2f1df7f5f52999a1115f9b17110a4347f20" },
                { "hy-AM", "2894f548674378c11f25a280e346bc026253607aa50428d4932b9fcc710976f293dee21978344c962839de112a514f9002076b996db8069542a2fcf179662a91" },
                { "ia", "db41bfe3d525fbdc1e21890603b43b9f559496bdeb20d0f197a1be3e772566a11381bddb83a99ef049e0d5da5a756f4c88a94d07956ba6973c45c49dcc9e564c" },
                { "id", "11c3cf0a4525a8af6c7932164f3c820a517d119ea4765accaacaec0f1c4f40bf54e71a26716d6d124b59947b38b3cdb59053a06950e29851203d17030e5e6f4d" },
                { "is", "ed458e68f399b803fcb890beedb3962f1386f4604d0724b8cd4ee38b6ed3b40454070ba6e7b9f874915316b37ca86ee74a9507d9efc2739a73dc2da1cdaa6d01" },
                { "it", "014b9c8a53a688f17ad6ef777340a0e5763db3edfdb77f6946f758b27c73563c37e496684933c1a38ab5e212ce3a290f4241b7634b48f9ee8a1ba8fed8dbf3b4" },
                { "ja", "c7e8acd9d62157489ea57af8b01b4b47fcf21338b9a1e377887c313d500c79ebac356e3eaae142c77586fb19038212a3c3df0970679830cb052bfbddc72db7b0" },
                { "ka", "9f9796e01afff26ecc51bff520664d09d311ac2c314ea3d6c9a3ada197852d6896004b7d65a679e0c0a5548dec035c0f1c3e72154d5bbeef2a31450fb584ba26" },
                { "kab", "f9a029ed4f24a6798484fc35c507284f39b03cd2c6c2f958b4c59898baf48cb800a1aa9a4c837585e8612d8c1dc10fa64725cb98f548c3502632deb3a17b0a63" },
                { "kk", "6b029cfd669ea905df0dc206951eb4533297a7daa8a158425997a333460028b605716ba14924f8df4214fe9030ca857188ae0c4d4d12e08203f17904e72a1f84" },
                { "km", "19073507e99adbd0f59108fe30aaddb9f7ce4929154dcec550420c5d8e276f848b5337155e964ffb9b58be44db6365ac98bd02ced917e7e272a78d3e10f87550" },
                { "kn", "3ba9193f0a6888c3595ed49afb5112d92b1653ef383c1d3005454024e60d038e206f836f1d57178297d14eeacf22e500efe2af458a9948a9e9b8beb19b3fa268" },
                { "ko", "28a203d17e35a78227d2dc3e1a7eb89fd7f499669d3f577ae197bd5df27c955f0ad3c76fcb0bc29e59e9dfbf0b4e573380fe0baf001f75ac3fdbc006cb2b68b5" },
                { "lij", "5e8561bef9e52be08295d72094c26361743f46d585c8634f26b0cf3124f156d0b6f15f6c38e76f341fa05b0a45069c8d9bfa0267057e5065ca99e2432c63e350" },
                { "lt", "514acf215f6406ee6f045f8b50703fd4d74e666888bba076ddecc470480f11ba62787b84cee60593df6d547098e377c9a47775119313a1e68fd23a00dd18c10c" },
                { "lv", "e43a0c6b76f24c67b06d02fbd40b5957946e0a57bfd13990bdf14d74d09c06d8f23413f680de38182018f799ad954a7e43065b83b479122e80ff073680ed063a" },
                { "mk", "9455b825c21f6b50c01583d80c1120c626956dbf420a9b71828dcd3373cd15bf04d01ba379174285934d3da11570636a4622e33428b0b0cdfd5d9f19af2a65f0" },
                { "mr", "e70d49c206fe5723c2a605288758f8f8dd9225611c5ee6708946a646b1c28cad151729b1e6774e8e90953eaeadb43738ef342ad7fbcde378ce5147707aa74437" },
                { "ms", "a49e504e82ab6571179b724666e5ee7b3d09a8e52374851ee7b1cb96a60fcb3d31bd6ebc6fe98b6e4e2c37ba678f1b9d2063c7f2513556c7dee6fe3cc235da72" },
                { "my", "1488c66f0fb1be25c3b0346adc86328e45d88ee74067a1f8c5a4744cc0b659614cc9662c6cacfca2d2a225e7f11bec46995fe517887372d271a98c1fba6c8b5d" },
                { "nb-NO", "592d32698995ec1014d900c9ad739bbcb5d71514488a4847e980eaac728bde5e19aac6fdcbc23216069191c63d709fb8c7d32af77f8705de0a48deca86bce815" },
                { "ne-NP", "2b82e95c925d6dccfec5e0b2bad1ab31709f68cfe2b891b6895de88a8c65486bac3ea1c7a2b48d02e84a64922dad3e67340bb8955bd89bd5396eff6b14b0f882" },
                { "nl", "7b36a071ebe51a489259dde92516684c90b0d96501e88a36b42f3bdbab3b42827bd35721cef56ff97f7dbe670aba106148fa8f582dac09663e4b734f36be9bd9" },
                { "nn-NO", "b86e98f559385dbdfd5a1600ada0bb44dcd365f288f265bad784481402953add13adad5ec5d094a34a17700fa20e2e20d62940a8d29b5e2d42c9b5ec3def8d1a" },
                { "oc", "89d511def78feaf4550c1973d6fb03aba3a3c8ab40ed5132d0767d22ba879da5b1a0e51977b8c3f8b22ba1e0daf48783c2278695cf2d15e550a19340c4812c81" },
                { "pa-IN", "93981891fb518e6045657ea9258b783af4c202d5a8aaae5fe11ba68c7474cbf2ed8c23e186c887b5fafa8219cf22e1206b6a88c20edc3c92eb2059f17e548620" },
                { "pl", "02fef07ebbd51e4232fa4db2b8c376cc70150ce780fe9d5387e841f07050c6b5b00f2cb6f03ee3ab1b5ba29666d1731c4c451d9d5b8c98c1a87d83e9a8d8fc8d" },
                { "pt-BR", "b9aa808b964661ac6b8ef71d36007f9aff5d5e2c874b247425a734f0e22fa2cd566e657e4e8ac637fa70b7fc720c7686d154a3e8822940c7fba9e899f8ea4312" },
                { "pt-PT", "d6328440db80869762605e0fb566b034e3099c04c98a35207e54ddcaabeeeb0ec12ea88ed01c7962c1c59f6dc317584b5eeca8d8185fc22cf6b677a82df6763d" },
                { "rm", "39e1f2b79ff830e7d09946ead16a2a8e1c794085eeaa1b2cff0804975b9a5ce445d519f138e9303651495caf13d759179c304b6139b7c177fc9afd5499385706" },
                { "ro", "8dcdad7de95dd5114d92cd3807eff570ed0469a2c4d9da8b2a09724f5cd1f527c8b66f061ae2750837e0bb0b1190987eca26e97dbe8c365aeeeb635ea0883765" },
                { "ru", "b044cb97103f5ad79af350b082d1e791b369ae23a8ba08833525561b784029320f5ce07c3f61053a55925cf1b8be51ff00a6f6b33c50afc5fbcf7e3e7583356f" },
                { "sat", "94a80b86129e0d595f281105e0983bd745081ab150b82f04a78dcb00910fae349ecb64fded439b2a3a22ba6f704d652adefa2cf8704183617754f6e58901c97a" },
                { "sc", "d544fda8525b36f1aa4b0dfc41c9152df5bbb395fa1ef843d12d03d1b2a23615cd8008800354d0fa207d46f6068ba1698c2074c94ab1ad8ec2d9a2d419eac65b" },
                { "sco", "9468e3c6fb0958fb704f95f0bf9fa771cae338dca68bdd0ffbd35acdc2f80635a1076c04294ff44e460ecd9122f2710c57b42b93110dcbf4d241ecbb5ba1cf15" },
                { "si", "b925f97c21e8f875f34ffc2d365e4c0146ed6e740a6551a208a48cbc0fdbeab9a41fce80981caa338e5b6495fd76db36acf392556ff93716a39c3de70ad00ade" },
                { "sk", "fb9b357aa231e61044e7c51ae341d5b7d99714f201d3219b9f69734b13154e00fa653d1fd5dc2de909fecf43766ef416ea0273a89efa0a717fb971bf66dba87e" },
                { "skr", "838be222c66a0008f0855a17d2b7055a195fe0028a78e15ffd9d94accd31a9708e48a89fa4ec4f3c43bd7ea151454672da90adcde254bd8dfebc39c9734b9988" },
                { "sl", "47e33e6e95ae7d53b9460c46d2e5d3a721e3639448742e1d5bd2ef0d597330aca9582b1b50c254cf0407d44dab13646b7c86f79ff095cae0c1e4262d77738570" },
                { "son", "7e5abd55060b802329a7b617f740ded94332ea7014eae6c85bf3806dccee1d372d2bfa0d074e7a8fdf88f9287cb5e5f3703b4b9656fe8706c4b3e38b8d7e0ebd" },
                { "sq", "df509fdcf97f1fb664def40e9bf92884dfda2145200ea3e8177470ef66e7fef0c8f11f81f660525f2a45e2a518336d5ac916c8acd832929a02ffeb243a7605af" },
                { "sr", "b716be38fdcde056a0b7869ff1cc33be1341c09980ae6e6e420d0c42feb48de3f0b4b5097c015166842f1784347f00b40dda6dd6f993c9c9b7e2fea4c142cef0" },
                { "sv-SE", "35f183e32cf64474fdae483f98d7f7287464bd7fce7c03115f6ef9119489634b359892c74f4102bda5c38f54cbd57770bf5c900c02181480bbe09b27ea9550cc" },
                { "szl", "7e10693483d9e8086e6755b021f9c0827d94429a2bb3f1f2aaf3b3520c4e0d2b375dba505668405dd2d8630dbb8813e75cad16f56e6f6ffd442519777d2eb658" },
                { "ta", "ebd5a93fd32965cee7bd341a860060f7ec09b9f464dd85491194d6f76836b24c88153fff3d9e7c9649f93c090f263ac5da0609688bddd3fd28fcabed9bb443f2" },
                { "te", "721673f484c412144622c8e7ab7aea0a04e02c7368bf14fc67789003700b7f0207626bb22719ff49dbcee1136efc20f1779df6a006ebef77be216a41d5cbea48" },
                { "tg", "2e5dde50de029c23d816117b44383c0e28cee783e140b405ebf4b9565f3efd0bda306b88fed7c8e303a9e182740cb0dc99b14ab61f932104c8cb680985e9edfb" },
                { "th", "fe44c2ed7c2e625781e12f6cc444d96d77523cca3424b96c824236fcfe353847098078b9de16b62bb436f82a20b95142bc7bd9a044356882c5bd485126ab07d8" },
                { "tl", "f9a09add098e6167d8a70d0d8f6028a25a28085bde7db9ea9e4d1c952f883a72c7a3e351859ab74641d0f0d26fb476b62d476c8446989b9cc8bb90a566c80693" },
                { "tr", "46944a257ffe44ffc4310f4632ebd1b9547818e01d6a098cd8c0333d4272ed9f62c775f4dd0b7c10e1f014431bd92e2555893e3c7dc1e170f1d508b3c7069e27" },
                { "trs", "abf62b9f8fd6c0a07b82b52a9aca9c8f6f7616167f7dd96802089cb06d971e62659fb76323f20a8ea6cd04b5fe333173816bacef0a8664ae3d8df56ffa24e4b6" },
                { "uk", "ce59867032ee5484c5233c7b066ba9a33b42327ca765e615992bf8c42da3f2891015b3101e9bf7cac38eaa1329fd1cd825f7910acb51d34ef690c59106c8b04a" },
                { "ur", "96ad164b719215d686d3e1cbda92282f99d5d41e884efec6ca17e4e3b380bcef3c0dfa5c6587395c9b365a7640244ba4d6fbe3a66fd053c8e0811dbe3bfb4722" },
                { "uz", "6661fef217157b9e1ce0fb40223255005b601eab7c6c1f38db6b50774e850dac60c092bf1f9a76bc9649c88df32ff36bec47fe3e224aed8a7efae02e2ecea609" },
                { "vi", "987b8a6dbfec1852dc3be1622d2d90fe0bf2d9e207d75a7f7b543641f50334033f0e716edf0e73f259779324423f81aa8e0c0d2f21a2576475d388b288c1e91f" },
                { "xh", "58255b1acd467f83b4e856e99f0b9ea8ab620aee63d83ba476f6ae3676a1442011f46060b9df4d4b51586af9c869a69aa7fbe488ce643ed9271d8bb19840322e" },
                { "zh-CN", "03c6b433b5304140ecd21a681762d5a02069caa1b39165f7716b878eada0579d26a10d0ea6ade729f452443b90179f35e4e04ef33254c7134a58682121f1881b" },
                { "zh-TW", "99ed7218e3faf243a5b23bf8eab53e5bf44a112914c308c2b45253b67e13766bad8168fd4200446fda93f2d5367b5d39d9929827cfd5fa089b4fefcbce3d87d9" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/140.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "b94b2a2d9db988aa1a5cd41f8601c8cbb6bb6374056d5329734471362be2c190b9df384e6412fc6fc8803e3123bb25a8db9afb131da14b43110d9a0c820c2665" },
                { "af", "1d7abd070ce77c68716005241ccc9fd8807f0a915b20c6ae9852207e17ae465f0fe2d70de56cd2e5aa41e7663b26e3d700a1df665ab7c428e7fd9385000a4dfe" },
                { "an", "a29a988029da1a72cf80a4ccee01cbec73a38ed6223b835ead86d82ca60450c2e67de170346f83b1a0be484efccb6960a4fe89ba809ef5bed5e7ccd1ab22d877" },
                { "ar", "95441afe1197d2dbc7bbce48b01c2403b58287de983d8b76fa9131491f0d20c56562ce0f7811b8bcdaf08eb4393c3c165870db78c41d16e81acc002d48b215bf" },
                { "ast", "8a1dfa8050752c692233590080e580a127383047cbc3acb0ff7da2c345f4d3597055cf32f591133047c8c7d07118e4a9db6e70b4ad4331bb52cd04cb4a5da251" },
                { "az", "04ad742a4f00a1a8b9324ea48ce3b6faee900e685a5a387118dac396b4efeab2c2ce5e9ddd23890dc0af3434a617e252ef4efb53c7d7d4db6505f1860b7174ed" },
                { "be", "73bf2f29c8ee2d610a2f74404237bd8b5b48ae464a5e4a1225ef94f68fe10d5fd58ea84777f80a23b7cedfcdce89c3fa9cfe20f40b5cded6b50e15d1f3f944db" },
                { "bg", "de24879e4f3ea2eabdb53ecd1b3b790d1372c70708fe4e73f56229814e0f9efdfca2dad1d4971fc9505c11bf3c2979aa92bcbc2144f69d5b645ec317b17a9f7f" },
                { "bn", "b25e74d7b284cadca46f01498c91eefeced879b8112413d59254ebcfc2a76a64df5226840d1c92e1039da64d2cae2b57819c44da376dd55ef46f99b80e8509de" },
                { "br", "d9412ffa84a375fcea4776a722397f6bc2e4dd1b266ffd3512f032e8fa1c55efa92d455e6108c0a597be542cc5a867b54d35711a6a84ce8ef2b9f82fe39be62a" },
                { "bs", "6066a73366aef48d5186856f7679aa2b207ba72136880b99cb84a31a65d578abd841435abdfb8bab8d08c8a2f56aeb197be3844c159e0b7217add6110c8cc638" },
                { "ca", "2fb2bfd8d4a12b583cc507f3f467736f125b700f1f0b874ff5aecb5b6a5abfe3377317fd60b60f24b10e8e3acf459c6b3dae4377ab4f72ab64bccfb85c9137af" },
                { "cak", "fd659237ca46f3623ef857e6892ec29053010e8063e2c9cb0f4c026ea5e5ce552de3bba111ed1f630e2c41d02a50356b02066148d32962e9b3cf5ba28af46a94" },
                { "cs", "cfcceae06b1e5732d9de1e95a956cc39e3e064c11da41886ac6ba19c43e3e88e3d49fce94f89412608b21035a7510942041a33717e050780689d21a6a2653c4b" },
                { "cy", "b20d78ad2ce1c007d0bb3f7fcba0923c3c4e846398c7ce8b6a4828f6c368d4302637154862a344f62596c874c2c1c684c0d14eaec814ce32eb4908b9d2d4be8b" },
                { "da", "89e95865142d219ef97b91994c07e12c3d468b0dbbe5c70347a71822bfdde6272f15988579131576cbddd78805996f6f90cd83a0c2b633453db2eba7692ad17b" },
                { "de", "6a89c225f18300e186a466e55f20ba30922a9fa369128646cf021bb1adafad72be357ffdda8bdc5363e232b8e21d7d6697ec89748596eb7d61622ab5b7e4089d" },
                { "dsb", "9944fb5244d903cbc714fa4ceacc0846c31599f7ff10988327242adaa752d965c8fb4bbd32e2f08fe32f3246f67208cfa15b62a637e75f5e7b9b26fe55bc3501" },
                { "el", "44f8541796f9284e952a05caa6df4730e5866da90bb3eb530e2eec0e17985894f47823d71ef58aa2c78bded1fe87d77c68629d12df90d1712d10a329be63b766" },
                { "en-CA", "c4fc7ef30bf00dbd2907c86f971905920ac88cd972b171b28e6410502ae7a06af79f4446da91788590ed6d8ee01945fc8b52df7ebb985d2248c584dd5e8acebb" },
                { "en-GB", "d7d6fa6f445400d17f6fc39f4d03d9883f34f2eb4fec2a367661c6ded09ffb62aa1055b5f1e7d9c1156f83624847ef224646f5af095c925b9413ed035988b6f9" },
                { "en-US", "49cb9567018c304ae2521c092001167975fe0527cc981a0caf7ff90a28ba3d2abc77404ea75b30be5648e3f4576f397034494bc931ca80ccd1c5abedc36bffd0" },
                { "eo", "2786ee229253d438af8fe3262ec2b769f728dd929578925e252b280f0ad1cc8e10f694bccfa8943f1b17e58b0daeb48c2a9e2fb9449b4671950a5bf8710e75de" },
                { "es-AR", "8cdf129d6a50a480a449e110f31a2d8a0c51801d01428fb7bf9b447718d56103725a2d46e76f3469edf9cd760f071970e083d29edc0f415b0ff4000676fcfe1f" },
                { "es-CL", "fccfcafc958473915703e08c18c320caf71ea3560b293a84203bfaec6ddfb3004c0deecb34c42414906ebc9db6225de81aae123f8101e8f5687f90bdfc2bed1c" },
                { "es-ES", "37304e993cca90a07791dc195aeef747ee100c18790dbc07cb37baff952d32cd79dbb7570644161a5e6d7a34014b95dac4eb851f214cd710a1e88ef3949cecfb" },
                { "es-MX", "045c99e134b8fec3e40e9324094de57cd2a1ac4829d4c0174acdedebc84300de6e6581268c0b2d8b428367d99e0845fa4ed5242be3552098633ae25d3100de4f" },
                { "et", "07fae38c5a7593866f6f8ca657e8eb568980b1380593fd8a488cbec1ccb073be080808b24e2552056dcc2328e8020c616267f915407adccd9d95e4dbd87dd50e" },
                { "eu", "927408378abfb2eb908f3eb62ac5d864284a0ac01b330584210590ba7df37779afe82a35c866b6614ad0ea781b08959b5c6a2901afdd99804102bb411e13ce60" },
                { "fa", "9d4d4a1298694348285bb03bc620578515b48f0210e053b889067f110e109820fef93e5645a42f8b529dd520362063808cac2ba7f4a2f482390f64aad6068965" },
                { "ff", "65f11cd2855d6600bb300311cfbbc49ccc6d3667351c9661a239d413dc44ce0a656edd8f958106e226f083556991596b7fce2f60a70cd7b9206efb156b3a9d15" },
                { "fi", "0dbe1d4ec7faad09288d52ec395d22e52dc75a945b43a7c557b380b45d39c52e6db0270200c74934cd3c341c30249db4e8ffc6fdadcf45842164fb177ffa758b" },
                { "fr", "028233332c2637c2a2e017424f8765f222900ef1e5818acc6c9787127a02fefb60eb556e0eee932992562caae92c67aa8dbae0f271debd7451ad8ef3b9a6685b" },
                { "fur", "ea9351861b0f8bbb747f299e58f626b138516cd56d41ab0e49f4b25908ad0834cfcc50fd6c9fc85bbda88af51aae9e6dfb31dd734dc5a034fb8cfc6c879db0c9" },
                { "fy-NL", "7f213cdbdf6eef572e9e813f5e5b992091f8c177db85b268f52bf7edeaf4c238b93728596dcfe7e7c9396f0a1a310f0cdfb65d53568cbda39ecc9419846e1e61" },
                { "ga-IE", "709cdcd2f190c610ec2e5fe4cdafaa9c6004cca09c1b726f56144c9af0e7670fe3cf43640e5eb33203c63bdab747766dc1f807053b81d8257151756ad2d1d256" },
                { "gd", "642eb2a227367f2319463de7cd3fa72aa9d87ab9af7800e8f1fa5cff3c02883410b052f7ccd180713911e5c5417ae10893f4656102353e41e4984c1e94312540" },
                { "gl", "d35ee2437c3360b92230ec9951f84c51f40978bf65656f7dd6992cd0f3521815165e83c62317b07768c759c7a108d9f251a049c7db32d48d5a6fa6ae03ed4388" },
                { "gn", "53dd33e8a3352761759e913ec9b64de11ff630f2330e1f842985b444f8b6c5e353f399bac119e9619b637299d9d05593e68f1ab99a9ab2a3034efbe7e77b67f3" },
                { "gu-IN", "b443b4f28c288686c2cf35d3cef7415248f07d732c73f0d5f2a0eb667afda655f3b2bc13d3ca5b7ecb57b20905b5304bf3c1b8e6c360341c2a9f13407f126308" },
                { "he", "e9a567442d7f66cbf968055f2b676ae65d39d368919d0448e48ff74137446a3715ddc557c9a39dbb21a1e8f4271f6bf29352d23508ffde55dc38ad4970bd91ac" },
                { "hi-IN", "4792e96d8c977a7f58a3e92fe3ef5fadeee4304089e42261167278b948e67f26e117a56f374a47ee0afa84b9502eb37b09ed9a1daf37c719eb389a6715157166" },
                { "hr", "bbc38038b7def880af9425686e0079430ea6cba46426deee052283e7dc412d6ced774b5eb67321092342d394ed9a0ce8a7a8d4f75b914c92a8eb624611be69da" },
                { "hsb", "afee7f1f23e102d4171c3daf006ac3edcadd955ff5f820017348b6c6dbec8b4e8dbc6214136e1d2615e4eb49b779f97e553c7ba704b6ed43b978b80cd59e8816" },
                { "hu", "1f9913760cb0229b3e52ca8283f7ccb5f6bac1cd79d9c3e893c26637b8dfabedf71ddf8cba1ffa35e6c6f6398f843df37e1031a19717d1f7d719c0aea5b0f22b" },
                { "hy-AM", "ea5a7661bc5d93a7f7635ff0a136b8fbd282d9d3a87cbc239af2b3ff46db26b2e34f4f4f2f56b50cabdbc81aa0ac97b72eb9810914a2849e8486608d51c549c1" },
                { "ia", "ed5d7de75e6ba4a557fb6df18e9439d288558db9a9c55a11b388d3117301896bc8e82f8fcf80dc89f0b9af90485aad90d1a44de491de0391d6239bdaad4f43d8" },
                { "id", "a8653780012bac4541213e3b366b01c03eda3cb53fcb0c2e986f033522246ad28a8237588d528428c8078c54acbdcf3dbb88f7ce9c1d25fc0c74e6da3c2beeba" },
                { "is", "ba234f62a0860882e76a75e72d4b6ddf791c1e7315d55bff83906bceb3205aaab31c0be04f9c6552196b3a55fd7f96b25f9e645edd389694a516b256a1abd28e" },
                { "it", "346960dd0b97c3554b4c973207a697d0b3cc658d22c9e43902f83200edf94bf3dd460a8087276fb7c96f0549bc06e3e78206295418da222834841aec0102da3a" },
                { "ja", "0c7c39649f1a85f944b4cfa30608981d3a129bf2a31cadaada54c4ce824813e74b4a60684315c60f22998b08ab2795a014d1935720eb95db13648006ccc6937a" },
                { "ka", "d49c74c27fb06c1771df5a1ca9174011faf86f0fd726a4384386cfdff28af87021d406a348ac3eb9a809f9bd3e62df06dec575f4ed9434d8edb812e26da7bd49" },
                { "kab", "80e445f71ea0189871083d4977c22d8decebafb4f0883a8f8e0644b394c3da325bf4986b1d85968107527a17c19bc636c0c811045be32fb162faee9a6afc1760" },
                { "kk", "502c4c08d35fcb12006822e29f5289acc20b7616f983a7f14ac12bec091dbc18bd261f436ec78e8e09b2cf76eedea9b3145142f8deb5fee451d3fb6dc3607317" },
                { "km", "cd534f9593a696efb85698de3a202758887c98638625d3e7eb8fdb35c15a2e035e639718836deb01efde88df6da0eba0901c10724d9de8fb14c293474aa11f7c" },
                { "kn", "38fe5aee82eadefda07044ae88e598f7919cb3aebed670a3f819d840868189662748cd5b9659902bfeeef9c623926f7cf2008f29fcde00cd40d6f7b044be5eba" },
                { "ko", "8e37785fceae1dc0683486a64a19aec0a74fc88bc324e76146f53993831480356b2dca033eedb0b8fd659c8af479ec9c31f638effed4dbe5bc2539a0541c02dc" },
                { "lij", "a35e63c52bd58986ff51057fcb0feaa9325cbc6fae4c786f5c7ed303f2abc4a190ff403a0ccfcc81a9ff8da555c2e3d9afcd6b44858aa5f033e4bd381b2289f0" },
                { "lt", "5c520cdb4c8424dbe43094bdff29ea7ee4cb3bcdfb342869aa5a04578b4a2de4fa289c1a11dda6b432d6340eecddaff144cfe4a5a3e6a910a7bae7ff27ba90dd" },
                { "lv", "6415ab6624d36d59261bf5737185320032ca5d5ece3c1acd3cae8b23a20bff55388c91aec5b52e501e8838885f22035920f8c18627e8086b16e2753ed3d068a9" },
                { "mk", "01ff49744f40658e05ce53943f2cac894c3a7fce6fc879eaf440ce551df493b4d9ae46e226f7926256fd54e2e978117cd89c2380d6fe28ac05aad76ab8ae6515" },
                { "mr", "148a1f090440ba39c37ba6c0afb664b17d9e272785c64ffc58c5d850035f99ea0cd1218baa1efec76bce3527e544c286cb89801b72c9d6a296165c5e5c15aed2" },
                { "ms", "ec47e918e4c03bf7c08e7d02c9b01f43240e40c065139a1bedde449ad022b9c6e263026474460edd168b10dbc26db4931dfa2a0c4a147834055aa7658919fe39" },
                { "my", "1e3bfdd214e6ced36464b1658342b491ccb5b3804c6cb49aec0610a33064657b3e50542de91c4513a09d17c24369a3c3a480c25834cf7c0487d34033e267615e" },
                { "nb-NO", "e969bdaafaf197664597abe6137e07d4a5eaf889abef6d2402b31e0dc329dc6af2034b7cac41bd29b2fee6ed090baf9e893a1bf245894269ccbf014763b42439" },
                { "ne-NP", "fc49f1a5265f76d48ccc6c1edd3271a00b43be68751c9c2bc18911c18e30ed819371f9a87ba15dfe28edc0a14aaf9e262d5760c282c13e4051753d6b0023aa37" },
                { "nl", "7a95e5060143b152968951aab57be20c1bb1614cf6f5a239816937b065493b04a9aa1792d38d6a580564cb55bb107c55b763a30f5703cd588a3f7287924c0aa1" },
                { "nn-NO", "e55dd9e72e593886391684a89d53f132addec26894a16dca47dc02a81d30fd08a857798994ffd2cbbfd7b8744146773b913928a8ca374496f3c8ec44c0631fe8" },
                { "oc", "37334deb5996e9a8239e03d450d9bc54be4754eba6ac9ccf6858da6cb1873e1019890433b65345af27d39f2e531315501b06c90701c91e622abbab5c29f4f86f" },
                { "pa-IN", "7ca9506ac7b7ed852fbbae56f26b71e0f11c154f57fdf65597c516936f256087025b4cf1980d199e082d50e3f0cea0b79d65075b774550b6ca92c04695c74114" },
                { "pl", "3ae38d04a4e907a7eae864f627b92ab5572ade5d768f60427eb457625f3c30d3698b017e98b632fb4e66ca58f2592dcbf8b997f78351b5cfddf878494a02b73c" },
                { "pt-BR", "c2b4b970d3189c548636e25e9df112a58458fcbe2a559d9f19361455a4e09ad4bae8defbc13389beb6cb7c8dd0803109164a117d941b18a2d9fdba878f339fe4" },
                { "pt-PT", "dfe592ef1f12bf1c13087945b0f1f8c3c3de71950c7b02749fcb6832dee86702b7b7f40fbbbe2e93dc8364688ad999c533692d48bbf86d3409b77fe961ae5b8d" },
                { "rm", "cd946f09a7af7a85eeeb95ce219d844aab5f8db6faaff338ae609e3f7557a035631a9ecf72d011233c1351010cc844320bca9bbf8276d771d4fd9e893749ea3e" },
                { "ro", "a96adaa09d8b44e3c5f9761be7276cad639fab143af2c3af6096eb2b9b4c33de1b3fa48c439e914f1b6e82e28ce828621526dcdbb5ab88e5c4038c0d42103230" },
                { "ru", "24fa84b7bcc668ea82dca39d802917ffa7094436e1bd40e47c63f8f94766f78df6a867a4b0b336d487e3583f1a0585dd169bff888a47adba3f275e27a07fdc96" },
                { "sat", "1874dc42e000c866ecc0651b85e96cfccc7ba775b5b9fd404371cdbe420d9820eae48f3cb01e74a5c1635c52a03e45e601d3378d4d996e632457cf82b1fdf8c9" },
                { "sc", "c2eec251fd8054a5016eb829efaec2fc507fdf8182b7eef74ffb4dc5c72895c7b7342b4b668c29a9a5475a317ab84eee4b17b461f07d0d821f901d562e9b6c23" },
                { "sco", "3eaa6cb0199f8b3fa66b6aa466076d737e888337e89c152fb8d78751c51bff66ba99efe0ad34a7adefb14f970d1fbf1b1506f91d488f6a240b5f7522a720db67" },
                { "si", "75df9d2baf224cfdfed357d7b324abde3f0e63545c87c161cb08559ade25cc62ad08e325ed878c12775638ea8f7b6d6150b3f97ec353b08e8a1a696bf2aa5c0d" },
                { "sk", "116d3b418d178b4a9b4ea340d8532e0a0b6e610e567afe59ff0b54cd3624fb9af79fa4d2016166a8c826e28987e2179bb882bd248c60b6aef926c708128025b6" },
                { "skr", "d121e7e898d8f0364e021f80409aa9ecba196a6fcf522c1b003843bcf4bd1f1b461d0ecb9eeacc98c5ec4ec160bb56a632adcef5691a60c4e6fe2397cc01b23c" },
                { "sl", "06bdb49d825ca66bdbc1021d0c98afdb900ae20d5c26d6d3a0d6cf296a5f1269233d15fc26824c25bce14b9ced1ade86502b3baff827324f63bfa0abe2be700f" },
                { "son", "4638b3c869daf9d9999da3e71e329f980304998f0ffb84b51a7774ffda3b008fb4217bbbe59e843601702c0fa389acb1af10b691b7025f804ddc01a741ba4e2a" },
                { "sq", "3640f373600f00782b628f1e37aa233824882a20455f3f904c1a5bd61ccf3e7458ca290a9e4860bc43332f97933f8dac260ff1ba2b5734d4967fd768f55d1de6" },
                { "sr", "b4f97162c74b576ae2b6e69182089d206ba805613cbcfaeafb29c8600090ace35e255b5b9ba2a6cc54eb036c9483ce1238b2330310f3c6ded8e3d152300f6c03" },
                { "sv-SE", "b72e2df0a55a2627c98f1faf2b20eac79c5f8121229439991d0d485972cde724f69429bb48a412260881e516435f3563a6799168e3aa8dd9f4e79fb74a2bfed2" },
                { "szl", "0eeea4c5439c4f3e3f7cde93c81787573c209c6cf6408953238714c3ad71b697e82521582efc6b7aba672f2170d561f1e5b83bb6f9de54e1759ff72a34d297f6" },
                { "ta", "65b790afbe16e1f139f8c3a35d1b2ca427654654aab7dbc914c7c873fa19e7eb607e09eb6d9b608e55809100a8985cc89f842d55aaa78faa1fb739e2d02707eb" },
                { "te", "fe15413cb2c740c521ae2409c79f8a622f6adf85342173c575a4a076d31b77fa1216c50aed02fc62686db611cb49edf0b9656a6f93acde372c5a28357a1e3333" },
                { "tg", "dc2c0ce3982324d6579ff5a8835f1207963cb233bb3ab7ee004b88b93f3cefe7293e65c2a9bcfa902717ebee5de55b9177f99e0b429fbdd69a3ed44af3404a0f" },
                { "th", "0c2f5752e4756a964294431c0e1553401023eaf75a04b791a37b45fc4093a5bfba96c540db139632598ce843c3d6787af0cc14975fa8cdb7b128769f24529409" },
                { "tl", "fe6e80c79da063115f187ce8fbe2a75fed841f19ee1902d4f71aa99338d2ab625fdcc4600a19976c56b38007b7d9d5fab0bd5f6f7fc1a24e1719e4a92f77d084" },
                { "tr", "ed049cb170208e54c46725a4747fc767382105d3b3ef33d69d6de9e7224d21fd7b6a25cefe9a169ae39a9d7e10031b6a90e5a10e3f967de30354a5cac61f34bf" },
                { "trs", "96971523a8d40efb08e8ab505c470da98738a77ecce6ae1c56ca6233bf3810745ac8525897cc1b6ae72af05421b231cb0a9e500e77046f16b38c81b4e7285770" },
                { "uk", "f49e00a647bd29f3acec0ceec662cba934e09f797cbf2f9b788b346e0add80e7abdfb57cc5bd20d2b6b3421243d68b2d9139b9256cd1a4374d56864953489836" },
                { "ur", "716301b1c4626d3bc19b810c198e6ee3be0ab5a7a32c063fd499f933a5e112d70c087573031318c9cb71ffe7d2afc3c64fb55b8e9af98c5d790403e19da79d94" },
                { "uz", "59ca4b86ee4c937cbf41e527b3247d369f714fe61d4740ff5e821831e1b9ab447966cbd18b654d332cbb29171418c9ba58d3267f818a16a6e6e081313152f66e" },
                { "vi", "8acd1db52b3538350b525a996a833b6f6d6b088960e7eaf3e95f74ea6da9bb0e5527e44ddd2e91857220f4a00fcd5b33ac5b53be8baa59e4b27d3c8d11573ea9" },
                { "xh", "99499d0b0f22903909e2089797fd53a58a0a7db99d2606f6ee5c4ef535036e50da36a86f284ceb245ec90e0459bbf3643136104c24fa540393f2ff45f6633c60" },
                { "zh-CN", "cd66e3e6954980a03041eb7628835ba29f69a03366e2ecafde7002629f86dd3575afe8b322e4d46b1439ce7bf98d2e30569f4fcd54a7ea48037420f03ae36503" },
                { "zh-TW", "d97c798c6622367807b8bfc40bf75243bd8bc05c7dda575056586e3b37eb9aab4ef84be145d3871353477c6e17617b40874b759d7cdcc2016564982bd2b23d4a" }
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
