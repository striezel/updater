﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023, 2024  Dirk Stolle

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
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
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
            if (!d32.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
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
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/131.0.3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "14905ad30acdbd821760d817ea2dbf30016fef456df37cdacdce7ec1a287b1d52f50786654b171d0999ace7a3b2de1d69be6f8fb8410efe11fa07737f56f1b07" },
                { "af", "b8add068cd72d255b7925878d87612cc7420974e51c27b00ff8326e2428962465d003e09dd1d02d373c9faf0de9292a46f53005027600127a0c67aa925b434cf" },
                { "an", "5580f6a4869036bc3a7aeaffbc44f8c496a0fc42a7c383f5737e1788847b60e86f24fd3f6f1fa3b04b644166b9b899b4459d2dc716fa68747655034e2a1aa5c8" },
                { "ar", "4e47b8d60ad237c1e748820658dceb543826cc3b04ec642dc9ba0c696cdad3315a7307bfc4baf9918be4a47d3b2878159670d099408ec02aed8d9b47d047fa9b" },
                { "ast", "db747c57cd635c57d1868ded461acf0b17691c99fcbca3354a1cd20faf565fa7696517f19c3108cbcfed0f75eb663d3c23a42af1b4e68ee4e06b8ac3ff313db8" },
                { "az", "ab6d0a8c0f1f923744c161699242af3e296df4ef4637ffab1f866034f45c0f6f4c72c5235c3de740f30c2950806a6d9462c4dabf0deec3467fa68e0269ae511f" },
                { "be", "2164a3d0ed0a7ce7342976fc6a6c5ab045b9681dc21ddde7ee0fecfce11d4fb91373ca0ccc13e4be211d79809eafd5177bc3fa6a3268f88724fc43f55307b112" },
                { "bg", "508d9e750762615a375f3a715f2883ebb6fbe4bfefc4d582a1b9e2433e309dba6185e3cde46f766d279a5442ebab47e4c62f7ae912fa47c45ba602cffc90fc3e" },
                { "bn", "e49c98da9ef6dff29335ccc6a73172b2f5518462aa7effbf6a0529a6b44a2a0e466a0c4ee7a071dd7e48f34875ff1472f904aaa2224de178fe5be268839c917d" },
                { "br", "d653f5b4ac2828b8d648435f4e9c0c5957685dc0b09b2647d0c68ed363c214f95d2ca25b84b269481b9f2a6e894dce8e083e29d64fd1d11cd073ef16a4826dce" },
                { "bs", "194530fdd7255016fec5fca7ad833dade8bc8c4595722fce943bf3e1e1c6a745ffe815ecca48de3cfaa8d2ab52422bdeaddd93eac8ef6286cf4787cb44868442" },
                { "ca", "33a04dfe7eef187ab1b057a3f489ac7c89e1bc2432251e206bc31b3e72940fcf20b93eeeb92e9f08d32d744af0e310791d4621f20eadec9b15bd36f2b5a904fb" },
                { "cak", "927629228d675a6a023b870bc627b836097da34dfed36c3a26e913302e4bc5cc5fc1f0dd2f4467341fd3adbf004bf1cebd0b1a496b6e24ceec4c1c5800216c87" },
                { "cs", "e9984962670cd412ff6f055c39ad20d03697e4c8ba753931dccd2f773f2dc32f49267c2bffea01b1b8257c670f36b40343f275e034b42b48de6f639c4cf3ff74" },
                { "cy", "53b01ffc373bea7714125ebe2ab02a1959ff6e7f9f0e212c0416640fc3b3806947715e145a18b5b7c5a8dc457b5ab67d24eec65875c818d77a1637f291193799" },
                { "da", "27452219166341874e9e964b477f0eedd66a127040c7651303e8a4e60de7cbf53d309de17f8fde50a13660f1a995aaa5c742cd3710e196a63ba108c62c0d26cf" },
                { "de", "af0643961f1b616ad6994e26b718f4b29426d3453055c60fa08f9f03920ccaf8eb7a2c471213dc81e43f525172c7f2aa5a4dad5965c617ccdc38f656bf84d19a" },
                { "dsb", "d05fc2cb7e0a0e5420bcdfcd5b4d1ff928efe38f1b04d2354f4814875cb7dc97bb7a2e27b488c9f915b8d10dd46fd5324ec1843548fb097f1c8e91f6caf68f4a" },
                { "el", "590aae349d289235d63c77725cd96266850bc7dcdc193ad153cda82e57e5726adcda5a86c1db94ed3ff04e4de364f3ec1b5f4e9ac9fbc79bdb11e2bfefe84027" },
                { "en-CA", "6d57a9a3389fc47a9de4db8465a1a5a8f7f49d1b10512fc3772d64ea5b5d1cbc5b5924f637e795f5fae4f59c7f509ef040a4e6a208f1be143bbfd3e0a527414b" },
                { "en-GB", "e635419faa08cf2b35f08d1c4fec780b888e9dc87203c8ffa5ab5395f4d4b5f1c6c952ccb6721caaebdd9d35273168172bf49bd0e76b0dfb8720ab6f4a5e2243" },
                { "en-US", "71f4a7b9dc2b069e2874bf0b8bd153215015371b7edd01a06559ddc49b87fd13ee5bd621a4049e998d8c6a50d66ffe3340fc4cf51e17d320afb2ba7d7b9fd874" },
                { "eo", "4d08a0490a63cbcec21eb71ef2b6a0dedcc0ee0f2f3282cd38ae00deefcbec3b12d8be51518bca368e89466adb06d46e7728838d5b9898170ae71a31355d8da3" },
                { "es-AR", "33579a1384015e87c7532c8d6cd09bec7b62c9d96854710a14c71b883e4f83cee4d291661595e09770210766dd0d299004021234f2d40d3d27231a52b9c14f5f" },
                { "es-CL", "5c16ad72a6e2cb137d41036e6a2c815ac91fc02fc055f336ee24d7c0455895eaf84f77b054b778ae5351ee432d1e957c4faa93f465b65080ca0ca1d5e188c00d" },
                { "es-ES", "2a9075934bcea8c1c9a541d5a6ca4eca8ce92974d44e59c1ef0b276f8f426ba29a55ae94455d98ee1cc30f6b73f473ab9b81eeab536124c1ed221012f296318b" },
                { "es-MX", "3cf12074d27bcbe87b751cf3dee6ed938c65762e877381ae4e9aef438cd0d2a7fe705d2e208afa65e52bbf408218fe4da4dc8de075e4fd7479f3f522dfa72099" },
                { "et", "bc4ef75447ca624ba0941d3ab31712d6151b1ba1afc203bbb23da65a8b6fae62be56451036bf01763c893782f3bd2aa2096b2b1707cc873f72bb60927adf7375" },
                { "eu", "eab8a64b4914a5a1227d1230a265a1961f79a8e89c88ecd434079c35fbb9e94f099ee8a5e1295cbce4cfeeffa8a31948763d06e05211d830c8b8779e62294c31" },
                { "fa", "4edda19fcb9be233a81606a4d417793f32bb7ca6e492fdc3277e62f7395f110edd3b0ac2c206882cb39248331400390d0ad6025b7939fb68cc56d7df33f4aa58" },
                { "ff", "3c03a5abb5163cf113e0d96cc2ea54f8a8d9ef17b6ba99627f381b84f3fcc658f82d420ec62be4b1b56575beb44013b8c457c351ec87e84abd8faab015cf0950" },
                { "fi", "f246c4f0cb7037ac390e8f7b11e0f4afd9621fd6891e5e8387457f51e63a2c736ed7b186940852c4d8e8ee7d3541d7c69d9be633cf78a28c575605d4a94f6b40" },
                { "fr", "aa909685886da5d95c4cc338228f874a488bdc72a3e871573a8bb620fb3fc0d0cbe29ed845dd848123c3a90a262dd827b3a8f5c3eb818d8daf443308ddeb63c2" },
                { "fur", "9ea10ddafe26b55f6d399168aa8e9d90c727af45a503f12a53624755bfdf34b489f8eaa7ed97715cdeb4ba2f1b7f56a2624eefe271988708b87df37148306014" },
                { "fy-NL", "9eab7873fd7ce55afc1b681ce9406c0360e8c6b99f594630445e7c8e79f1b6790904c906c3abcd19a73df5721303c40b1201f5d3decc7b5f7e70dcad2b6ed054" },
                { "ga-IE", "8db60a81833c64a0dfccd0b6322c1c07b4783bca018bdd9d558542277d4001c30b45042ac4388f5b54c091d7f277e1d93187f23cc7c9ff097439fadd5048a04b" },
                { "gd", "2d5988f42b789dcf60a2e3b80967044094969f535d5ebb040253d67083c0500ecd6bc5a5990257e7209e40501ab21d94256843bfb61cc71c5c959f8d9fefddb1" },
                { "gl", "d9be73cfab443d787e1d2378a3d05c19f18b865c316095963447d5cfaf29a1df6879ffa95147f9e1dbb9cdf98696a85cc400cb319e3cb9022b635bf80a723def" },
                { "gn", "73628f7e6761311ac96c1aece94c594b36ba459f78b307948fdd4f1b30008c9b6b81bd844097549ee3b49d3f56ed93fb5164e7cc625fd5da5f232fb826f7fb95" },
                { "gu-IN", "c7aef8a03879586b0af10c4767b73dba6140b65a3160491e093e2d2f0c4016aa1695f5b2164e4fc08e1f99791e526d1aee75b08cb0b65b7f2ce88df4ee0d1692" },
                { "he", "e3b58b86ad68218f148a82adac6fba7e62e34afe57c8806f2589a80223ddcf21dc63dffba91cf989b40176f305e11f9d686901934640cc25a9d52fe1e8d0456c" },
                { "hi-IN", "5e9d9bd6929a4063c75ffe5779e14b2597bb6db8694bc4782c5d6adf76dff6e36e164fdb3daca07476f05ae34ddbb773aac809d8bbe6104cc4200aa318439968" },
                { "hr", "c456d020110c9830f4b1619e10f367208bae5e869d76760f2cf4a95d4aeb76ff2549fbc7beaaed9caf934e438b470bee413636079dfc057b711f1cefccab57f2" },
                { "hsb", "8c15a945738c82a6b32b200a4d66cbea0a46fbdfe46b62ce26081750867e908ce39dc787dfed30f7c9ce37645c0c39b96552ec339f24a8b19b0bf9df0889a7d8" },
                { "hu", "ba67a2cb7592af007fb18eeaccad3dd588a1eee090fa0c120a5133257128b1b5724291f6ae4d29f745f253741f26e2eb0845a0454b12e42b19f00caa2cc2c6b8" },
                { "hy-AM", "97da160817bf93daed1bd92f4ecde84369b0e88c5627550792f8372a7b58f4936b2a9149e669ae31113ab2236ffa4bedb7f95770f20e5990a47702008be862e1" },
                { "ia", "56fd3fb012d57e218bb3b60e2502fb18557fae117ad5a913679e46b5b17d059d557f6b1f13a17fb490b141e47b598f20227fa2939bfdce527a25b0287e1bc43b" },
                { "id", "6f6d3ba8da2d37f43fafa6dede65128ec8cedfa1ebc2e4f27bc19825bd39c449e907b2a4de8b00f0be4b4e9b7b97482083f46e977b82c57135457c4a2b2d18b1" },
                { "is", "4e12e1d6c9f6dbeb031d03edadccf74527d9f5bbc46c0b627943851e522bf3d6a9e9591b565be1c71bcc93bb9e89d83c402b7484345ab1f1119c789c1b9ef598" },
                { "it", "ceb65af8c92cfa44d735f97c52e741bacaf98eca075728ae5326af05e278318da1df953d8e2fd683471b935b1fa983ccc135adb2be6c3f25ea816eb9a497959c" },
                { "ja", "566360ff20c91f6c4960fd6ab48c1d5d821b4bab2703c981b609b468cfb8e3019421f24c1249d13977c77062c69de8f29344657aa8ad5851f0bfe615b6ed729f" },
                { "ka", "4a6b69885e0ed985975cb23b838f4db3f13f7f0c917d8ea6080d1d1c8dfc5fe9be35ee4ae6f34c0c5398ac89a81c230883f5241c986c09e9d401800a2823827d" },
                { "kab", "0d9d31207a447cee784c7342c7c9d49246e71c31ec9ea219f4f69c16c51724e6d2ad4bd937f8511b2fb54f5dcd3cd642e50731cfd2b8bb081ac04e109cb4d52c" },
                { "kk", "7e7a0a1e6abdff09b50041002e5a12221b4823cad770af1524469b8f03b93d17065d148bc2950a5d91a28a00357469a3d7a474bccddba5069d308666c7d8e2c8" },
                { "km", "2d3f13070b519f03e5e0a9ef4a19d815566e9350be65f7186735fc27f4840d5a89f3240be28fb2e32790e821ef7cd1d2496f5b2cac24be2f29639cf2604e8b55" },
                { "kn", "eab069471b4d632024fc92c9f1c42cf44eedde467ef018d445d387503894c0d77ba587ce3a0680a3c3e12ecb35447e017d6630c9f5ab0a5b56df90121a40b4c1" },
                { "ko", "e131e5e997d4e0bd16f2515925cf446cf14e30e75bda92b1fd11dd71193cf824d65e69612f4acde3fd85c2cfc70691280a84cf20de0efb876bfa0b8b00ccad86" },
                { "lij", "b579ed44cb7fa20628cc6affc2822f19e784baa6715cd547fc62f3c58bdd4c63bcc27758701ab4c2f8701235e4c2d33f1af474bbd0130046025ff6e0f67d0c6b" },
                { "lt", "d1e39a4646e7617d856cc3f9815c612228b7bf740c8ae44220bc0d8a958ef7e58e48ff61eab470ca5a59330d10d59b2082932dd7808d24859210cbf4a21b2dee" },
                { "lv", "65e98c6c0292703b4c84c7803e3b1eac9bb2b377aa4aa629e8564ae62886e5ed98692400d908111b664387f1b0e6b54a000bd2bfd9eacd0c42f416419cd18f25" },
                { "mk", "c531ca97732d8cb4c50c83692466e7c3f469ac00cccb294ae8b4efabca34f72483201794435dc23ece1dd51f6606543d16de1870305af1e9c7192fc8899019f6" },
                { "mr", "2db24326618984d5c7b056defc62eb476ec73f38ea2348ed462489099868d5812b1ca043788215b048170f9e24c71534a82b3eb07b8bb2e500d7ef68f5470398" },
                { "ms", "e50a0943c217b595a674446e69bf550129f1dd0b7f25378ac4ffc765055232918e954a737206c11b3802570a2c78e04aef1e72a0e4c3baa9b4fef39ff17ec8f8" },
                { "my", "94b3a0aa279247dc2f9c8be64758cf65be390594d8da50a4ed869661129ec9261089a45dbde8b10a1b10d1802fb78b671c31c6a0096d70a59905ee4b976e865f" },
                { "nb-NO", "6ee4ac5d6ad3524f86dc6ad334054943ab6687fa79c2a1e1050da689c7c296dcbad161d9bb7a3e29ef5d2bd45219b20ef6a694f599161440eacb7132c051fb80" },
                { "ne-NP", "384ccd0bce29e30f3fc868453acae629134ba162a62a0a7925609a32021f295db4c37ab083f9ef41489b41f2eb7ea74e2cbdfdb86a34fc2f0506cc14944de8ff" },
                { "nl", "e456a23124b1474b4f56853f223cf3caeaefa514249b1243b50b70aa91a1877248d6ec577ea86a8a8f635ae6c436d684628cf18c4273a70d2f8570d53ab2d214" },
                { "nn-NO", "fbbef12386ebd2b31888046ca79915a37f27587ef9084098e0da07d01069c2dcd2a865c7f6170769f8747b1318d53bfa2de9dd3ba2c3f860bb3390710f03ab29" },
                { "oc", "f67eaf015dbaae6d345d8ac8aa82a819373c6381e74bf051c31222a6494c8e5d9bffb9736ad128769b6fbe74a8e0264bf8582a90da1636e8a7049b93fe9f7f79" },
                { "pa-IN", "65a1543fd430e6f746ec1276a286c4c17181a7fb10314972f7dae615ff580915aadcd5164e42edd4f16610de6931265d073fb666dfb33701edff37a1a0d059bb" },
                { "pl", "9e6300ee0ccb6adbdada18f5f73d41ad0291e1a14d6fa758f212736ab174d02f8fe20887c6f6062b32ba1b380e521fdef539b80e087bc5b2c664305654b58608" },
                { "pt-BR", "55d93c26b70e64336090b4d691b6cd9a0ee0546cb17147fc1a53a0ec0a8ef5e52273f11f298a54a7433d3dea72380be81dcb7b8e2c9460494796586eea6b5ef8" },
                { "pt-PT", "4b6900c3de10839619b6921225e517decf094d45c7d90fd9f30199c587e12eed4a62b31f790ad2ac97fec7340592660b889dbb98df0795e742242168031eaa59" },
                { "rm", "94de5894613122d6d329ea6f29cdd42109002ea0597acda8c02e75bb7f0843df9a518cae79f3aaaa7b5496eca814e55d91c3da87b4ab9546c26db9abe9392767" },
                { "ro", "5318e60cc8a181d36a90332ea9aabac9180b6ef00a3ef4bbe8f9a080c12f1e0ea3c36ef037de2c6a24adb7d5574a1578e67d45d698413a20764b1e0fd877c67d" },
                { "ru", "2dd46650d2b4620f92f6fa038d8bd2bc86c2f1b8100780a4b2417f351031175eb26458cb68ca9439ccc87877a832a59bce2e15fb61af8e0c20759b45b576ae76" },
                { "sat", "b51bdd13da636eceb7978dc943b436fb39671149866c842a4736a208e8127d5f8e5c270a06db87678ef2a577a0a19d1e2fd3d876255512a1f3eb299c72b82e12" },
                { "sc", "d210fcba4d77e4c281ad9ecb1630e0a273e4c7d14a428aa8082b562483fc47baa74fa65c86b037ea4998cac6ed7bf53b75fd42301e3f0263efc25b40a0c788a3" },
                { "sco", "e54a433c16690b13b6c38a199610bb24d10e12e2821a3bf48095a4985d72f27c3c193d824631301d32f507ec417466072d313e9bac433fb902b81a4f4f5cefd7" },
                { "si", "5d6edf8cec022a99d69f1fcd2e9d561f4f2a36f67fc5055ee24d59bb7fa3471a21d6d449bc3a123cf1889e5f7edf0cb8e0f89beab2051831c55bd362191747da" },
                { "sk", "3e606871551e1bb7b2b0db21cd55a384f8520cc6c2bfe7b796c82c4f2eb2049212bb48fc4847548c9f19dabeca6b3e24013a32a18bfb026cf822fead903e54af" },
                { "skr", "ba5d4417688e02df82cfb0e0fee386ede5beea6e99e6083faf8c78e3215f7a8f2b306b6a7c0a72c1d63d7d613128622f118df62e1fec1b93cf7aac437a43e15e" },
                { "sl", "e3eca2df8c6e4eff8defd3d1ce67d308d3a587961250adf7939551289e2ebd2bb37612195b1bc802e9fefe9a489eda3df6f1f956e12ee3783f8f357bb93aad09" },
                { "son", "bf7be6325ef7af0dfbe7f953f6bc459621acc6c5273866a8cf1fbcec18f72fadec167b204be9d41778794b728e72a367eeaf62fffa00f2ddf49a7d75754c5b94" },
                { "sq", "f96e3f3766cbfa7b334a9d23d1051b1cbb1d108b28238550eb1a01f28ece257430b6b805acfe977de819b7406f4e3570dd4787694d99afb00e395ab7e0aa08a7" },
                { "sr", "879fba9f375e10747009e0ed3b21852681efc55ddf36f1cff3a99bb02cad14ac0e7f7416b37ec2c15bf5a86842fd91e93ee407b75b50bc0ff0a517a5d1ff5251" },
                { "sv-SE", "79ee17eee1e125a478bdd80cfe03175f96efc91a2934d2dbbe065a377f88e00783e11dd041b585a95637c04d3be770452949c41ee814212faee6f2af89a439c9" },
                { "szl", "9f4867ace4cb94bab728a0ad0ee19c3ac237792a9061f0ce7269b224387edd5b2489f13ced0a169b72728e0cfc33319e2030f9c97f7d97de8113986a2e28e57c" },
                { "ta", "6045dc1550bb692776b60b8398707ff35e8f38860e1efbfc17aa42d96a6fb80bb7ed46616348d7de7b0e4eff09356c3d35add08d086fa710f24c56d0a6cefab2" },
                { "te", "5fe1931e9a4dfaa519aa65e9ed932b0882b3e96939edb50d8a1a7c1f800ce401697833cb3f79a8fc0543643e9cea7d35287bb160ea2e625b201eb497fe0c654d" },
                { "tg", "fcafce5ba40c7a913a280171580df4e6556fb0f023917a49dad9d225ee92f09b662064e64e2e3a667255b2b2961fe40762578221d40d780c0680a0b63d555ca6" },
                { "th", "07e3093642584217534be504c3c60aff7999bf66f8ee73ef622717ce7d67a2edb3f409f8fae258fe7b7e90d4ba00e69998c3eb7876083bde578d16b8c9def922" },
                { "tl", "4de81aa12dd6575883fbc2163217e8557e13c926822ee4c91e21c27ffda14a71a35d8e2e63571f922ea1282ccf6cf116ab2c3ca47f5e55cba40a022d36613e32" },
                { "tr", "13c973a3a15b3e0ded59d63fc4c8b276b1c29eca3c708b17b1f529bf684d85930929d40568b18b5f1b7ac20eae25c139946f649cfb614e712844165bd918a801" },
                { "trs", "13cfc7d0e4dede0e5cc2f943b84e13540fb3e27b6e8866abed4829bceab0c7d75c1def8c4cda1b308b9fabd0e4a49f9555ca2e50905c007afdd40843106fa034" },
                { "uk", "894ca83fdb993e2ad903b22985a55d5c9ceb618303c64675339f492720bc1ebb9da9838a6425d5611d1e42d41744b1ab611d74e94a7c70c6633f6506757667cd" },
                { "ur", "32227f84e77d0b3a03a2c8be83472bbd1927355b942b1ce18d92f31027da573ffef5ca406ecf37ddde804d13f6ef8e61e2afcc42c60323454a17da0326b01a21" },
                { "uz", "404eceb29645ce402996dc5584d5c17a7cf4b9d3ab7f3cfbfba2dab4ea16d04686cf7fc566ed48cb22908e6441cf568c027c409aa09148dec7acd8d501b99bb7" },
                { "vi", "cdeacd8261496b8c32728fe5f87c0b323ee47f3e6a1799f860f5402b3a01bbc01790d481643e0094e88aa3f2a286013ba3fdb8c091d0c4c0c1492e8be4e4ccc6" },
                { "xh", "3e9f610b6370ef0439959df3a543b7134c5d4330276503d5efe6b7cdfa63c11f0cb3d5a20a53d64b5adb95e725d9184bce4e0fd02d0dde3eed88ea4736e64829" },
                { "zh-CN", "288b77a2b312166e9c9178498b97bbb122a97d74a9c088ad2f1484314822a857a4db7e51d8b90051c18359ad7548e8b34635565d509592b4e6d846715e2c2fc5" },
                { "zh-TW", "6885eeef6b8165fd955bba4aa13a742d7ea78d3341f4a4564bf98a1c9de2b1d80f276d62a5ab2257255d169fdddf5dcfc19e7edf3a52f1f01f4698d46041f668" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/131.0.3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "d1f11df81a468ad1ee21004549d8b9be81bf5e378fe3f9316182138160388c5cd88f6e43fa61b8dd40fc1705d2d5f1f09797ea23270680e5e7c85554ae24f9e1" },
                { "af", "509d75ef6c9766d63d53c216e4bf61ccb84d609bf61004893d8fc9519fe0099de1e421abb95cdeaa963cbe46e968901d774d40288dc936b3dc391d754793c48f" },
                { "an", "c4883065eb108148f3af7019afc3c9d1d986208908d6147fa9db43ab39387b2291b8f3815085f11a91159cded59cb435a67e37438252bcea745d2fda43f0cab3" },
                { "ar", "225e471eb5da04bd2c1e88d5387cf6614ac2ae4df8953e920fb7cf42b1d336303e8fd7c7a0b4983399fa02a0150650607a660de416de372f92ac6f63c8a845e9" },
                { "ast", "8fea7098404f7ff2878b7398666de09616e43d920d444b70f3048895a00e5eed179e306634efa7401d474fe479b530ab58c23c3b0c7cf1b961bd29593fa8d29a" },
                { "az", "e88b89acb85b452e7fa7aa2418f47deb4173065d1edf36b7f3ef378780eda04ec70a530b4131350ef6e3d975d1f139b75d7d1a2ad8d4da57e8f8fcf22dedd31e" },
                { "be", "7005cc9edbb4c0bdbb2ac0bc53bfbf2f7e885123d63fbb7630125f8ba0f5cff63d9f5054d4d90b1766b05d816d0a730b8c190cc81836ebd4907b74cf332d1880" },
                { "bg", "d8058fd7bc82fe1f312c59c3c65e6f9d324e9e0e459c9fa930ae13c5658f04f3e4601980ea48b70b66ed40ecb0218502aeb4941c82afb155053f5556f4b72afb" },
                { "bn", "61f9b5028ca4e64704764979efb79e4e0676994eacbde8710b9ef6663653c570eae1576bb390350f78b5da9b6cba72bb3c72b98c5b5f69d688693a1bf25f96e2" },
                { "br", "01a4be3ecabe03baa753903fbcb7758a6fd111a71836075b1e7a74651f0f2b122c4d8c5bdc995e6a6e259a8192ea23198d40b88cb050144425151e57930108cc" },
                { "bs", "329fa95ef5a8b8b81c70a5bfb1401bfa8fe0f528f89bb66920ebaf46461c35f4c1b03fd564793c772fdb63afef46cc3a9fd07d7f3c2461930a703582842e11ec" },
                { "ca", "dd936980783bc76dc776606ca24d73024cb14ce36c478b35313c68c92e25fa68c2655fd77a8f58fbb4e829f017911057d7d066142ce9b9a544b3ed4cb585ef27" },
                { "cak", "8b1a2ec6d936be02e67c697ca4926d0779893eeaa879a2de7c33f4f7e5b065f1db628439ac6d2c949c21aa7be1cebcfd93f02add171d6100e14219fbcbb7c2b1" },
                { "cs", "50d12058f0accda51ceb23865d1342f9f2655cb0233db2f225ee4b1eb050bf0c01d576c0693056e84c0922e8be27deb896332654ab53194d7f441a94b85a0975" },
                { "cy", "e7394364c553a9bc0cdcaaf8db0df4adb291738545a6c851fb4c024cd868a7cfa8335aeb558d14dd90f6abd969b3c6d836a9fa76840383d633bce6a70f4e7389" },
                { "da", "89a9844db37711c0454695f3bef9886a4874d44a1c22337b49f93d78bed8466c848ccba58e1eae70e60c33c834156e47fcb10f7fddb709bfd47db8db67783221" },
                { "de", "c0c5fc68d8333cc4c44615920d8dffb8e152272c62da18fe9c1c26c4a95b296431a72d7c900d8c30fc57b050ab949319f0549aacd2de66d9112ddf6d756d724d" },
                { "dsb", "82901a5b97db1ab4ba30f4ce18161b59161d2c680bdcab84a65d0bf9a7e7d8a3335018eed81fa9315d50357437ae29a2cb785787504f8d8dc2273a6c143d75f9" },
                { "el", "30509b78c8f7122ebd4825b3a8fde15fb240814cae4b89716e66dbd665859471a316017ab0303b12b2f5fd7d1100f3ad113807cb417eb1935ab55ed32fa6483f" },
                { "en-CA", "8eb20f1f87d43720f14eb2bf1cf3fbd321dd2342f128afafa166c2ae8499e4451a04745585f38399fd9b12a8b05d5a5fadc42982357d96b9347fca67f87c91b3" },
                { "en-GB", "256e95b450cbc517caffbc907c81ea2d8b0cb8213db8e5918f44b2e2d2acd54e53f1c9b8ed4c2d597a1f7e0d56257b3373a0665345053ec00e144bccb9ae2528" },
                { "en-US", "e4b8a3b4f342fd59aceb15676c38658fad35bb81ee116febce8717b1906f430e3dd568f4de1bf12c398059e9bdb129f1d2ac1ee4ebbb70021b1307a478faeca8" },
                { "eo", "3cbdcf5e1dec4269883b84218e7bc585918d9ae7bb193a4de6b28b644937eecc0e3211a0d214bf6b7761abd92026a5392599fefc51ffc979e43368fb41f3f803" },
                { "es-AR", "79a9021d34e3004fa644e335c50e676e10559062dde3532932a905690a6125586323d3b8f3e2d11979c8d8ed7952d6ad7042de4d6abfbf3ef4fb630777e5c2c8" },
                { "es-CL", "f77e0b384b789c2e9b08136f9297da7527bb1345187fe10554d3ddab073391ef580f4d1e6891246a2ddbfc7390e5aa3b9052c0e8b0221d895f4c32b6ad762526" },
                { "es-ES", "bc5b7a162a92a0fa805420df498a0d274bba9e744c263f11c9d13caa837e01463f47cc02f77f0a3a059ae6ba7c93b0dd58e4eecaecb3b63dfe296a39aa5632e7" },
                { "es-MX", "22e81bcec3590458d7841f5a67406e39ad94b15e34903edd48e083922d33967a2ce600d18b911e369ecc656ee869d32cab7ac37f72cb47379872068f940c112d" },
                { "et", "929c483adcd20d4d097ecd5c5181ca1aac24a82735835f1f4b37e9a7c35ce821d1dffa83850a37596488fcda4fb77b05f2cdfc6e9ca15830f3414a320423a124" },
                { "eu", "81218d9ba3993be4609013c431fab8f10676102f3f470649b1f5ac40b0149874b92179564a179c4f8fa1e89a61d7ae9dd2a97f1d658dd86877c85140d7ba9838" },
                { "fa", "4b5224e689faecbe1a49ba854cc0284fa7457e00b46f75f53ccbf055531373b5adabea38aa5f7fe53f27649cd35f8322a932415d3ad0f93dd3111e1e1bfc5d18" },
                { "ff", "436ae9974de99d9af4f19ac75f8c8f097c0e6f0e415265ebb8045c62f1622768bfa8c8d6fc1c561e46014aaa91145be8e9a46ed3752db2419fc8e0a720518982" },
                { "fi", "dccf6f17cce69cb1147cce7e700df97c7239632be44ff72106b28a5dab5d549e7d45a64d70b7cecda032cee510e6404366b3d57a053cb058c563a5023a35abb5" },
                { "fr", "26a5cf1820ef91ae77e42c37dc9b0db4925d2f94955f3152788d4898b3f9084b56e40042209ad32bd92d15adde6223cbd5f2d0b1022b45beafa732f3cfdeae2e" },
                { "fur", "952a1e7b535e18815cecd3247a6fd355ddae1dee57d106dc280fd69d880bc8c4fa1456f3657bd7b4951218f0c68006215de7dfcd286e69a3631170450f00e1bb" },
                { "fy-NL", "9ef2194953436c952bf040f595edca971169b5f750d357d79d32dec085ce83a123ddc13ec031d1801429bdb6cb37c5e6d2cf3f469d4905e8a507f4761d626299" },
                { "ga-IE", "fd21ea90949092227b98940578dba5646f55562519f327f38433153d1ecb7f72237f9483f503729b38f74af12461b8f281c4327cba860a5a784716706879b6f3" },
                { "gd", "5fc81e2305a8eeeb3b8b349a4bf7c0efc1ffb707cf9a4050d2f5a12c886b00c40818a5770ba53d81d98c1d45076d3228012c120c15e85de10a96fdd5221c5aa9" },
                { "gl", "fbef951c27ee246e59868b0e794346b9489ebc0e9f1fdf5d76ccfdee622162731be1e5c95ed2ac3dce286b9088c94e10d5bfb6a0ba6ea4db881e720e09ad6a1a" },
                { "gn", "165cbc0609df2dd39f230b960a604ad99a5bc9ee70ea80386246964e6dc75b0cc0094378aae55ea5e5dd187fe3997414819cc798af549ab6de06209ed05f0190" },
                { "gu-IN", "e1012d71e00225abb343c1139faadf388d4826c31cf3421892d536200e785a2ebc15112ad88f6b281db0227eb2273858414ac9f30b7fa7d4c11d04e90f47573f" },
                { "he", "95c2527bdc1da4efeb0d548f68efda7f3a12ba39ed0e6ce5677b865116da6350fa39e01719df36cf742a8d498f9440e08b70b39bb169261b907351a4333a5737" },
                { "hi-IN", "7d6e78323889d3e016b5d3e7562d35d6f28f8521138fc12091d2fc867410dabb11c3921e2f6e46fb11870e5472e745ea9058b580e1b9d2d6c37d61675c3d3394" },
                { "hr", "5438286b60a374eba9ce71ec386c1247c7e8500c0137ee081ff2abb525500c1a794cfc29a341b793d696648ddb56a93acdb8677ccef16dde985cb49f5330ef2d" },
                { "hsb", "3c91697115688b9ed3ca77634d105331858829c94739739cc859871f96271b13216622e3bc9294fed11a21ad37d0ec44033edd14700e49583182d7751aea6113" },
                { "hu", "b4338666423d6a97b8dbc71824b2e78a48044739c2b5118bd588f1790e5074c18d499f3a950f8ec0cde8a2b1f8e7e0b07e76a4bdc1cd3ad7df6537b35e5eaf4a" },
                { "hy-AM", "f5c9b5699d9fbd562770da457c64dc8ad41410bbe5ae8e4d5435814424097fe9e27b738f776813e37647062ea6ecae9ad6543489bf92d2755e795e4bcb57edee" },
                { "ia", "3f88e0d09a17c4de089fd57d03da47d4291a38a944740b0a45db2e8b394ccc8dc39e22049d9259421469b0c945eeebd43171c634ee745c6bed7950bc36b632a4" },
                { "id", "6ce90d3519014535ce9325d98d93f7d2b60868f7f2259c498961ca9e5cd675f714f506186cb727c2695d05acc3c49cf5593c17d47c0161e6fc4901657ee88046" },
                { "is", "bfce89458a289bc26a40dcb76febda913bbfa178e270c29cb56675c2781780bd24699f9731c2f1ef5963ebd6f4ff4a6232b10832de179f882bc5c3664150ec5b" },
                { "it", "b257307d65ad3bc2c9e9473c77ffab0a49bca2116cd29b6c9a1a2c18f1d9ae0b0dd9578d5e21ae5f319c721f1d1872bc7cc3e65c35d11292c710547c4e364e4d" },
                { "ja", "8236a25bfc624d5728eb3ef76efdbc0c67567e09e13a26121839515ad624784d162a4b104fb40f62efba7193a50661c0dbf6a848a2a551ebfe405f87d0aab9e2" },
                { "ka", "15d2b451a70b536e235a37ccfc43c63def0b61c21532460165bf5fe205175b669741b02fff422538bf4e90380bde02f37884d8ee3d5e202606e95a3ce5d09da0" },
                { "kab", "57f217dc50c814bb20ab10910c845f32e2f5f66f481ac04d8bcd269038c86b75b6929aafd53bb443ce2585561c14ca4c38e5c2d0f9126ecf24f567d6730b0e18" },
                { "kk", "a481d7bf6cd4d0ce9fa46db6ef1a5b5d39c51782425c1118d9dc9a8477a26c6e7592b5909721a1700148a3f162b033c8ec76a750409fe31b812c8cc1e6854a9a" },
                { "km", "2ca737f4af82280a104f20fbd1dd5c02fd83af8daa813108c3cd29bb680ddaadeb42bda31be02097d54e9159bed609bb811bc2625fee508d0569c0f5fc75642a" },
                { "kn", "722b1ca5e07a6d7464e5dac1c24d344baed46d891d3e4e0392778f55972785c649472bdf3fabaa5c85cbdc60b438e7ad16917911786d0c20214996f6879a4aa3" },
                { "ko", "8c2454a3f3aaaca9e6e9b445c111945bf4124b95c4a0e38fed0572e7f53a655135f5e45d87e9c6b3d73a508483e5cd914f3ac835bc1c9b9c0628260f4e0879bc" },
                { "lij", "3604a4feea7fda6ce8f665cb8493a25e83758d0686884e84d20b6b91d501eaac0efc55641dcc2a6370b9fbf1a847c2b7925bf2bd3820455ec81804f7850006c6" },
                { "lt", "b7f73af91ec2c15f6d6720de4e85c21df8e69a986b2dced5ddc310ebdc16f20db8c17909b1e0282abe389a8234f4644d62d5964ba0ae85778ff692de0a9d9785" },
                { "lv", "09a6dd48a7cd90237aab0e47d54abc66e482c86cb85aac870662c815235057f277fb85eee82ddeaaee5b5daf6a7699f091059086bb817ba16025bc9ba0d3eee0" },
                { "mk", "bb3cfd6709714f1650ef516f1c858cdc898dd89a9860012bfa01050b61de92befa1c0693c06c63b8c4a9df7f9e06f619410142a01c276dd0a44ef86f14b089d4" },
                { "mr", "c2d01cbbd5137b057cdcbcbb59c46f81956142b46595387fd00b3fe3938ff0a3a08587840f2a97a25971cf2fa9c4bcdeaaa4ef1a6f6657c24d55c50c17b5e1d1" },
                { "ms", "81a0724871df6de7ab333574d74b8d4bdb177addfbb76800e00abf7cdc1c17383975553c3e9a5c466693f8f18fc184e50aa553d09e26ea05ec7c0af278b4e96e" },
                { "my", "1d074566730ef3c0ad52a108e2714523003c4d526387dfdb70027e98b92ad74a66fb0a478c0a271d31d25a0515b1aac8adae86872201e610f77ff1605c477a90" },
                { "nb-NO", "44d82ebc3b40a3103861257b568f6c57052582fd5deb0fa8432258bcb57945b11b196857bcb4366e55e6a53ab832862b8cdc7a178e71f9237da025b6f50b9dfe" },
                { "ne-NP", "e8dd285ede17f24f64e3cf49bf32030f561de0840638f59511651e155744ac55c07c2cdc1fa525db870f8fc8cde570fd2222c6798369601fa4cb3d4982b2cd52" },
                { "nl", "701c731d23abc2437df4c5e2fb1134796e044eb48fe9ad5f9973dc86fc443af4291236ce54842dc93a689b594ab1a890325866065161b007922aeca1f568d6c5" },
                { "nn-NO", "8910de4dbe0dc17b8b69eaa41ddfee5146c108c81a95debc465705e64520c92c1c8b1074b9126f4b1b7e7185301ddc03abacd158bc7b2675eae9d046b101440e" },
                { "oc", "67ce9215f8f5650ffee605f00c7aaf2fc8c526a0d6a7bc6a3ddc69e60c2934dcf34bcd71b7c4a0412c36436e3037f270b1220939944e85f6873b044cf5d560c7" },
                { "pa-IN", "0ea27976420ba798ea20b75dd0c371307f4b6e20b1bef0b5632da782870b789bccfda35d870d005bda077d9b3b4f269eeeef812057f89d430f18d2cd7f515e10" },
                { "pl", "3c2c57f21378c290dfba9c38cd1d31b689cfb850ba8b8fc626fc40f7138993bfa50a48de348163b9d02dd145876ec1dd2154de3239837a5953b4401dc93169f8" },
                { "pt-BR", "43a40916fb1bb8e478f1ab810f62b3c8a3d039dd3365bc627cb13c6bd0687cce0cfee5d189a925e876c7a57f34c151fb96bb9d172f1f286ac1ec5477e952fc51" },
                { "pt-PT", "00189c3fb8c030fb423d595ba5775e9492af9a7682772f52b43ec8f929337ef533ffce75e42b3106e28d984fbfda47b7b68556e8455398b42c6ba634dd6c0fb1" },
                { "rm", "3e71b60cd64dee824852fa10d32bbfcb2d7de96127787c68960fbca22f6b54d3326b410c6b1ab3f927f82509cbea009082125a028072f9d7c170d81bcd67d86e" },
                { "ro", "a4c8485fbaf2fdd0f549cf55ec7746a2ba187333ac05bfb0a41bea103cd281a9fcf5dd49da67f5dd7c23abbf4791c7ea5fed1d785eff6a8bf442973125d25a7e" },
                { "ru", "fd25911fdcdb746881978cc62fecda03d40e8cb4c556bd18131665de0a4e3ac4098e45bf5b549282e10bd7d38595631e6e680894c3a7f5323def8aaae165c36d" },
                { "sat", "11e295bbb025e2a4934f43aabe2a1305909326d8e8593381c164eee5b674ff1aa0a468ed4d8f782fa54ea355a5ce897afa47b985f01df1bfc9f52062e7f0e9e6" },
                { "sc", "26a897c4d823f6e62189f394c017de7087aeba5cb02d65a61800fbfb8a59c601af2c2fce4dcfd0e947efe76eb89e721e41815b610c1a983e593ce8fdea32605e" },
                { "sco", "ebf20c97be0f9b6769a0527a91733745288b045f287283005e92e996ab153a53980308da2de1a23344c6c4f7096c0c360b74053122d2707c92533307a33c6dd6" },
                { "si", "f858ed064a73a60212fa5cc7d2a913a4dc0539573a10440b638198585812affa2418e8006b85f3b02bcf42cb2055eeab3e161ff53b57fac290169fa2e85fe261" },
                { "sk", "dc31203902c2025fed5c630fa0341133a8127808432c9a80bc62fbfae08a1fb5186f17c08722e38bc959482c7a0c5db9230cef784322b3f8574fe1b9cbfd073e" },
                { "skr", "8e5a8ab8cce2fdc4376768790b91d2bd77a202e8c00d17de6f3114f71c374797c6d6d10bf90f35c57d2ecf32ea164db84e95ab24e8328293d69d2040ab29c626" },
                { "sl", "b4395b8877f0ea7d727983594b538806d0443a5e8e2730477f9d2434793ad83f911b27c5bcfa4d45a39c6903e36d73119c86e6ee64a47b97621756978c9e6dd9" },
                { "son", "6b378799fc3a1989bc5aa916d94348856a695606556b0f954f4f3a0b417be4bad5deb58f8111c72623d075beac2c3063ccf6a01557422469faf98197227672eb" },
                { "sq", "6d871aa6136abf0fd7b5b71e0e019191a4fb06cf0cd7e800830b5fe7a88d2e9da38753860303f0e39fc7b4e4f0169742d0cfbcc26d86511b4bde74d7375c41a3" },
                { "sr", "9d205a0ab69d62cb16755e0befc6e6a33a205aea08b948ddf139645b21b375e31bc2f1255df972998193c996067dbda1494db161a300d39154750488860188df" },
                { "sv-SE", "5b34d23217b2b450542e1a6d1abeb88783a9797e9da600a41e4d7c3a8b327421aae8b1c30b4a96a808ed1061769352a24f1f3cd8bdbbd357eaf5cdd01470cdff" },
                { "szl", "e62d00c3ec407b1fc635700b1f191157688864facad8a6ed5c03e720399e0ad4a9a2395445932cd3c08f5888d3c4c6d62858dc1c70ed12662aa1c5c182270eb1" },
                { "ta", "2183de059c24dd5fe095d36483863a83909fb732140062b73a71f69b87a5e7d03fbbae6487fd3ed800c2dc9d40e8c9203b4e63e1ee1e6c417cf895ba28fe6a88" },
                { "te", "e6ce84346af8306bd99f91f02020ba76bda9d9f106aca37cf67e3bae56f7f089fb4778eed659f2d651993ff8033fbb09fe54bf6123014137fb147f09ed890b65" },
                { "tg", "414980012184a419cab23d70ee4cca8fb0d5462325219439c3673a593590b6fee02313c651fdf52cab860d362d7d78c57c46b53115cc3bc439226e3edfa69dfb" },
                { "th", "40f1dc1c2bbbc89f2496c9272cc472ec35a715f902b001b0b703b67b21382353839c7c83080358adcf015f5c925b75d51356993f6a449ba7279fc770e6cd428d" },
                { "tl", "a102dadc14a500de22f6204dc4fafc03ac8f17fc2dedc7d1bcc1ab63371ff14e3085b22f4beaaf214c122f432cf9984aa6fd607af750da4f39550af441c1983a" },
                { "tr", "e489b8398cbc7d4c2e51de96ec4e60cf644f3b02176876592098819fc525895dd5718658edb58cfb95023ba52e3aa542bab58bd759114485594b205f7459b57c" },
                { "trs", "5d4e023f344651d17b1029afdae71334888aafb1e9d9efa13fd8664afdd05877d9d7173111d182ce2c41360a2cbccde8474c58e04fc116bb9c90d930714ef4c3" },
                { "uk", "17abca09129421d13717e95dbda6f2f4211b05c2fd839d0e82c370b73d9b755246fc5dfef1722427b8a04f89d55c364f8a57eca269242c124498cb31c7e76546" },
                { "ur", "3f263b41ad6c1f702fd9eb0b02f9f8a93988aa15b74f4b7d80bc90beac828c413461ba2a39612874213fcfaff1d0560b6ba638c8bafc1a07e3849f5643ee4fa0" },
                { "uz", "d3748d4dac415c199182ef11bec2b4800072ca7f0b22e740ad7ff3baac675dff1cc304b4a2c53219728ad231a94e6779279a578c20f616aeb238818ed168dd88" },
                { "vi", "d46babe57f00e5b6da6f92aeb277efa50191f272a2a814c0f2c80275d5a6578256cf68b9fae2484ea1f2baf50a2e14782bca00e414a34175d25a2fffcd51fd50" },
                { "xh", "be8b7d81cb54b3d690c8b006c34408c2b93e2466b02fa44d997898afb43c5b15e206ab8275eaee5233903fda556574db1c7915c96ca8821446ffab0bb2c2e30a" },
                { "zh-CN", "73d808e15e5f697a195cb96c0d93a8ac13e487ff7fecdc0300cbfe664994257df41f71a72d22b7786f70c8537a5162c5b701da6617b0f503ef110093a0dcda68" },
                { "zh-TW", "6521e12b6a421af0b9b97dcca816ce30371048f340a7c7c86c5a6822e25d7c174e0626cc86f85dcc063fd12dc6072e49cd893d05d3d193ea06aaca3aa6d4d4ae" }
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
            const string knownVersion = "131.0.3";
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
            return new string[] { "firefox", "firefox-" + languageCode.ToLower() };
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
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
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
            return new List<string>();
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
