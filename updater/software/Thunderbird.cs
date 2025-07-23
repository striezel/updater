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
        private const string knownVersion = "128.13.0";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.13.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "a8ee89415277e35979f33c258fb92565a985eafb49c54be4650279a412c02336fcee4379bdec6fb327de31e2d7d0e224a7f9a4ce31ff3d24bd393054b590055b" },
                { "ar", "3a527f86feb2e1bd5f445789f7e99c9d393f33a6a53c385cbd01179228177a481056be2a9dec8558fdede22d9ca6b3bbf30dc67a05cf0e474869cd33f0e9b485" },
                { "ast", "edd48be7e6f7e5f25d3d8a22e9bfbe3b25cd0cb67559d0abd77e13e183f15eb93b53fbf312a990e0d91365a0d832c7509f9d3ba586f7aad13adf07c15ecaf1b6" },
                { "be", "c05257300b78b9281e02c4cce0f6785fa26b6daf583a1775ed745264b0dd42b6c24aec32115575d9cf8c8e369d2cb6f1b9427a372ccee4002e13aaff519f3a4d" },
                { "bg", "a303e7d7a38366003556cbf1d690a21cee173a8105025aa7a44d297a514ecc62e64859bf965183d2ac55ef0251d5350e4252e64ca3dfea4c59f4fa77de8c6387" },
                { "br", "a7751f71842865dbc64614ce1798942ae6f332644caf0cba0a563ebe5e997a8b7b72785add123c4b619ae5d0c505f4298d1f438a6bce5aad9d670bad4cdfaf8d" },
                { "ca", "1550480d6d9b4ab509abc770fd7d394fee46dd5936134d1f59455c8c371165c8bc751b218e017144c2e883047724129bfaefba4835c4ef474415344a9bcbd675" },
                { "cak", "367d14b816ab9c19cdd86a324a60efa388ee56b1167383c0df1a1ce5f95c86aa185ba1ea1020184980b0742606c9e7e1ea0f63efd716a2d049ac2e107b8d511d" },
                { "cs", "0468d14e9f2ff26b4031af8a54d2fa33d8634a0643c113f897bc6c215637d46d6436a3be5efe318bc29e2996511f12f54ab50f7cae43463d7f63d15b8260720c" },
                { "cy", "759780a0af74b8886c32b93dd11a0a36e772ff792054e238cae0f88154e98a24a485a086c27b2160c132b86530ea385da745be27d345cb1dbe5b3257f44cb72c" },
                { "da", "ad348fba22ef770ec628a6a808191d5c1e4952440a9022caaeb9532211be0a7cfeba5691a3587ec89058ddd561ac5a9b4b04fd6a05af6aeda0d01cd8889ca656" },
                { "de", "b382355a2fcac222561e15dd468ea84c1506614c6a0d9b52792350cbbc45c3e0c3279b1b5adbc5e81a8481ea8096adae119669cdb9100124dabf63d1549b1f84" },
                { "dsb", "cbd350c906269f04261816984be801c063306ec5f54726acf4b747fcaf45a48ae3193f233079b9415264143a4477073d1056b4a1872eba01d93a4f775acd7d1a" },
                { "el", "06a07ab7decddae50f4e69e5c784f0b4ca133320e640c727ee75eba6281d087b093f932161938b44b9097085ac2a1a32fc72cf03d1f7484606ad35d23223eda1" },
                { "en-CA", "cfde46ea1c7995f9d6f946703a3b89eb85dc30b5f819fa0f1cfd4bac52ac3b442e7e65d23d200e907ec1e6909b715b6ddc5c1913670f701609ad2af55f814f28" },
                { "en-GB", "66c460945c75db784cc5c058189b49d8ca4797d68491c48080e3740f888953fdd1c6139cb34a4f74dd9e8711bfad7a183b2672fa55420b532bffc3825ca747ae" },
                { "en-US", "d691e976608c4006fb84bfbf33c21e2a9c4a5bfd9dcb3b21c0c1884b8ff2d8b4789cab1c617c44a859953350cf05748436676b30c5277a82eed303354ed9d364" },
                { "es-AR", "5bf466cfa587ad9642922bbb258a37d43fb608988d5aecbac7b5be2a2aae167ffed190ba3c15f777b80fc390e4acc612536db02f22dd2b3cb4760b6f59118e3a" },
                { "es-ES", "b8d2a99cb69480629a7395c540fa6ef4c3e3e86391f5302a098573eb3c5c3b28a6748ef39c147f69af01aef6a97d2297b3cc60c05da770090f92ff9f32ee08d4" },
                { "es-MX", "a2d6a1c7ea83aa783ca9c743e02536092f58473f4f59c88b233712754364370d0f6e94fa6ebf123c97cd81ba459a5fb4f105361051a7418252496b58b6322403" },
                { "et", "a0374410cf785907c4c0852593ad58d52e9c55fe789f940525776fda3ef149eec62aa8f8ed07f719a88a8b5e33cce5bdd25d73a30b4884c2500fee16bf5c8022" },
                { "eu", "e5a20eb7cab679cbf245f41f0409015fc77997ae925411983032fa6deb7a62730c3cf4aabb3b0d9856cc54251debbabeb394ac419662cd3d0590bc1fbaa1a9c7" },
                { "fi", "c7fac913aafcd2f0b3b64ed571367526d47ddcbe4980d3caf12b8a2e588fa5210d2035218db6d7696f3bf057a8fc46eb7e7acb9a8cd5cfae6a09c5a142a3224b" },
                { "fr", "66b43db37f567aaa5ec3624761661a8ac63701d9577036eb7eea76c664c2324763bb32338a5cfaac8ac1b5f830c562bf188727f57752f654b0a4f1b6bb188ae1" },
                { "fy-NL", "0cf8fcb8a44a0e95d0ed4f2b56fe11e19e2e710215bf7fbac82b8dabdd79d53ddc83557ff483b9995ecd43c4a567a970c84ced42ff8786af7670b4d8e58c2efa" },
                { "ga-IE", "f6b55f292912b4b66e93c02981d1132174ff946b00fb639ec9fd8442e492126e922a054c6c61a9477f752b0fbde3925c9079681e01f3462010cd87c4d6fa0b2c" },
                { "gd", "29eb2df398806ff487c97ea33bcc00d7c71ebc6d363ba6d796e0c7c246c33a5fadbd87a90567faf067a244698a33b92a5d71f3fd1f13c941a6478c501bc9446b" },
                { "gl", "874847e9fafa6e673d1a0ee0a0460239200aed4d3e2c77c2655b2710607b25e47afe0bb62d02cd32c2f6c2b0077ea32b55a62171346c408c81b3c36c5b323973" },
                { "he", "9d514e08eb0243b33104d1053c15ec3fc6820641a1003c7dcf0f0744ee3efeba30f8a0553f2b613afff53806e16e2b17d2e2e8065165fb043685f351b15eb84b" },
                { "hr", "d79b222d1d8bc9d22addfb9a985dae468950102e70b4b8a8181849a77006a2cf283a095b0981a8adcd6eaf2e73d750c6853c9d29576944dd5c06ce2407b24829" },
                { "hsb", "c741e1c54b5711e70debae708c60be75d00da85f2104121217e8681fef8f9bae2685ff8e37497374eef8e2729b16668dabd5f1c7a207042870184865caf64b6b" },
                { "hu", "4ef6eb67505e4b64541359e256873a4b8f4ff6b2af2715ad402114c78c683a0f384caf7e0335af811d6d7ce667c8d2f6917c9b2690ccd751f1af6b1b5902583b" },
                { "hy-AM", "444bc87b866e98275fc1f8f544ac46a139d53311dd03007066ece2d3c751818570d29cca420e2f7e8b30dc97a50dda6451f520ede63e630349d7c65c0b399ef1" },
                { "id", "5628e93001c4466a11b3758751704d3097556b03bb3788f916697eacde5c8d0ee94478731b5f806026d20fc3a670ebcfe8a1e75150742fc7485066620c41579f" },
                { "is", "87208ddd311a934036da12a98a7f386b8667062e7b36f73aabccd11cd51c8ae0b814285cc695623842ab140e2c367be32895efd05979fbba42efd44a1d506ab6" },
                { "it", "0e8655760992abb897efb88bff34d9d45461d2ac0930ff0cfb876d8eaefc7f8c7f5c48fc9b5dc9ca4679edfe812796e3f73a83c7ffdc8aad2e6df0931776e3ba" },
                { "ja", "c25615d39d6fe8fda90838799829ce0a54b012b21ad0a23c4cd6eb70c7ee60f1c9af6056609cd979b64a64399e73b7391c6d737190ba53f8f7e10c0a8b14efe8" },
                { "ka", "17622a44fcbc0f14cfb40e21fe7fe6412762e7a7d96a056a4db7fc80300f032ad8b2d4692dedd61950c4f0f2e27f6b19eb27a9bf2dc7a280db94f4b019664fc2" },
                { "kab", "9e8f65739ee9892b7dacaf8d42efdc839628d69ebbeb7e609c00e9862f919e4981b11547674bd275853a81838972edf78f6732a0c12f0280cdc41db2ac6c9e7f" },
                { "kk", "bcd3f3944a4c7bd2d5a281402e74a2e30b4a3db76147924818be2c32106bbffc8ab6ff4621a4583969e130b1aee6330f60c189bab9c1f2000c621fd11f9c7db0" },
                { "ko", "e784267204bba72ebeb54e1d31dc37457e6f1c3d4ed0c41f3d8451dd51994238d4d427348998aef72f40ce855b0b9cfc1f42e8bc6fcec158ae5cbb6f542598d7" },
                { "lt", "e2a585b22a7568c8e64650e68ac6bf9caef8eabfa64dda15c8a7acc817eb9e1dc8d710922e5e371292024a1a1832575a43cf7c7957050118efd71d072b0d9fd4" },
                { "lv", "2d25f37f8a1979a22d1a2d496bf54fdef7fffc29298748681cc5dc756f211b8c9b7e57dd6900b5f791838d0a9636d964f6d21c14d6ec0d02f5af6c9707971e07" },
                { "ms", "f75f7255aed98f3adbd8897bd8e9999502690df211992dcbcd8e00400942c96711fc59af0d79b7835444e381aa80c65c254fd1603d390fe1bc5d112d998642a2" },
                { "nb-NO", "3ab02085f73b49bc8dbb34a38a50f6677fcd6206d26cf04564f760a868960ea0715f4ff821f5a7712b35f7d91726564528f4c44300cc72fdfa92a462f5a9865b" },
                { "nl", "c8b45196b6150f1f579984f9cfa4139e128dbc000329ca143419084efb51c79ffc8245d56961787224e9ea42e8f4195950157d3b0080ef8eb046a7284fee50a7" },
                { "nn-NO", "093273c1581d11752fed3c594f8f96bc6754ec7ddf7f8cbcd0b198c8fd7d8a61dc75e2ebe79a6b0abb64e63bad37a5e2f7a71efb1983b6a38a34aaa281a35fd7" },
                { "pa-IN", "602bac41743a9c761192da26f67dfcfa5fc55c7b5c5de2806a10bba96eb9d239a3e7cbcfd2e6d9a82f7f393ca9fe476e26e1a85099dac445466b911e08a422f0" },
                { "pl", "098069c81d51730c65f93bb24cf726248d9a15bd766bb2b0df4061b885b61cf009269287f0fc3334c9a5157ad9a5bb3aee33941a5a0d829c18d1b70784d50402" },
                { "pt-BR", "73123c3427fd0780d4454e686d852d3e7f296ead2c533f2148b2bc4a7ebfe320f7fea98beab1d52bb775b488d6614910fa4088b72153915b18f66fc62a64eb77" },
                { "pt-PT", "a13f325b3b7a12923e341adb2112fecdfb5816bcbb350cd6634650439891048d78d3652c169c9edd2db05ad3d500c379964aca96d5c41643aa64af80bc901843" },
                { "rm", "9de2f3f3c288579f8102778b0513e07d5abe2a27dc567ceb481afcafa5d9268b5295d2d8d18ddcd661e5ae1718935c851ba0dc8228b1fc348cc09e0f887bfdda" },
                { "ro", "c06edc2cf4f0cf2c886ecf5038400b031201fb7cc59ccf9d9a979430af597f6ae49ad1ec123480108237562465a9d7632a1f28560bd91f505b6d02b4f186d169" },
                { "ru", "61e1c864cc46d5307760a09135099da97203de4c079fae16e400b5c4db170334d4d2c3c900a031371bead680e4fbc027e6042f44b850fdf52837e6932ae42aa9" },
                { "sk", "463473c7bb09fe26e1fcf2f300bf6fb05c5c7161bf146375e54d0ffa594900a1e5625f880a6744d770915e3903446d07d61a4db96062cc8414b7e0fdabed7141" },
                { "sl", "24e24efa90a052e5489488237151017972e23e3b32d8f5aaa95f8dbe0475953607501415eb0b4f7a230f3a49d98c6f62dcdac09d8755b968e9d41a606e6082c6" },
                { "sq", "17661e4642dc22967385e35c8c1bb134defc08bc0c88be44ef5f7557210d22fe98c0a9c9e1447eacbf0448eab3d0ed4caa10a2d9305971370b4734df2a21bd44" },
                { "sr", "70fbbe5e0d5549270b72e0439793781fcfb13367b171bc5d8156316e7adc1ec3ea779d2f954662bf9370deafafe6918d26aaaa5afe20851545dcdac36333f972" },
                { "sv-SE", "e7a83c197ff574701c867d2ceeda23f7ca8f144baa567707d0a8adcfc79412f4d441ec95278a831a2c6a69d9194f7c5ca66dea95196bd7a34ee2562ea9aef86c" },
                { "th", "2d03a8fd373e567451d15a1a8c3679745451d5f915973bb3e837fba4e7f83799beb4add2f093c62185992f23d0e91f1f0a27701ab4f41d88f3399bdfade56031" },
                { "tr", "9db4df323aea2c27905b51f1840f38c4ec34aa686ad4c81418261a80c3f05c555f8b81028f58393691b7acf87e9b7a2d2e90cef843e903cd111d78d19e7f597b" },
                { "uk", "14ad18b36cf2beb20f784f6acba18dd195c2dc3702db8c356eded63a3e4887f85a156b24eb56fadde84b3f7246b4468044e8b11d8656fb033b6bdda171041f6a" },
                { "uz", "57e0c92e80b03e1d6ba9852a43ef2f37f66f7337c97d112348f1c055e21c510613b7c219aa92fd47e906099a54703bd42c61771389d5c97b7756da6a4c2cf11e" },
                { "vi", "3d87b3c83d6730fb241232a8791c3e4d20a8e587b277d2578265010126e20c9f44d5e8f18daaf276553bccc99fd17b1006158ac8ea93f61a282deba02d65b7c8" },
                { "zh-CN", "13f5c09278b4a048f99813503639bb38e1a746e59a66bc4ccdc093d494fd6c170d3f2be7d5e801497bc67c626fdafea0275942c95bc1e2cc7a446dec367d098f" },
                { "zh-TW", "0d92d1e219b337becf598ec795937a8c5f5eebac23fd21dd7ba16d8a09effc498b64fe27f8016ff4220555bee875f752db948b8101ad53dcfba889c81ecaa534" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.13.0esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "43be47747ed9fa6e1145f466d6e16709e0025455946683d1d50743a66c8e64ea70e90e971b34707f4bdba6e60db6845937ad5ba97da6e0c8ac5db9f82b1960fc" },
                { "ar", "7da6f921af60d5e658daeb7c702ee5add6155626f444dd814e78d835ffebaba30bb83a4acbec5dfd5c26fe677bfcc5a26cce3caa7dabfd0ea7b818c666edecc1" },
                { "ast", "6529e7d82b38c41ba48affe0944a86a4684df98f426e65e4b26847d21a29d4d560a2d6e875c0003a3df952c4b2bec886c2a95a98c40adfe40c8928984689ecc6" },
                { "be", "be0cd69ff6cade60fc60e3cc767a840783d57adc39edcc11b3c0914013ef974f3cac287dd149bcb9bc3e8846aea7955d4e681aaef730320f7fee988c41e9ab28" },
                { "bg", "21534a4673ff85224b734901786fadf7f5fcf62d122b226975e3635755454f824574b34d598047862e50ed184cc249fb8251b1b5980fae1137135216fdca31c4" },
                { "br", "d3ca22d09a7befb774dc55f56776ae53c562a668d0e5d460e338e67a9b59e6f127338fdc8420c0fc8055cacfff57d43293c4be875fe7c23201fb0c3c0abbaf2d" },
                { "ca", "74fdb1150a732133c315aec48fcf640988a09f9dd5e143ccf9fd2834fc5e523a01f7efa185e8b368fc1468d08d4f2028c7c32ba91ebf131619b2f55249ea044f" },
                { "cak", "f0324377d0fc9436f8fdb3c80b429b8376f6e9870708a2a73a374c560ae471389c6a6f3c82337611b6d8b6ccd425272a3f5f3f7c8ea80d12cee6a24318a4a58b" },
                { "cs", "d36fab3c2a0892f645d9060a54dc0e48ab341d827667827deb42fab0e6204f011627740e18ea2c1bc37f08e858beb2ead159274d11e62f2ca873f6cea777f01e" },
                { "cy", "10483e9aed2a96107c122d6fa0884b95844d9d85d3aa18d16aa703e5499c0ab832a98bf904e8fecd22312e136bc038d99f82f31cec453921c0742c2510814f1f" },
                { "da", "48003febaa0baaa7a8b056aed08491ba40eb5e452d77b04987f1ac72b4c83d83a349e19c6752e7a09820afb2f840c69233ee969abd76823909f20b1ed0863d7c" },
                { "de", "384f85c6b7429ff35423454fe57b987e8c325c9781f43ab336bc995b791a68e44d6365555566eac368e6c1a3cf0147a80c95d722cf681fb85258bc2788e4632a" },
                { "dsb", "dfb502d0d3c7f1ba8cb799ed89aa670bfda50e477b6a2b25fc62788d6a9754cb327c79f2efae8002af98adee382f4878d1dc83cbe13717a0dbaf35661b7ce8ba" },
                { "el", "44a75e270bbed12e411004315e0a1f0821be3d6652b6f73f5d8486d53e329273edb5e15baf2952e722419fbeb93a123d8622a6954398e5604baa02c038bc51e4" },
                { "en-CA", "1725abf1af7862cec54bda6975ec26ab5497abd4c67330586438841b1fa51eaaa8a70c4a5a3926f6b7291dbba0466808b7a1b2cd4d035c192c384e6d852840dd" },
                { "en-GB", "d964a92c47d9868cf40d1128fb59fae8d03e26f2ee34896ff1df7328268113644b7e7a9ce387f67d4b9dc85e0ff4e4d1f0d3a495f41f82701caa2e134c9d7c38" },
                { "en-US", "35814eaf01782e1bc0cbef47edc6d6008e54ff55ab4f0f7cc87eea507815ec6b191ed078bddcef9341a28b560da786030b07dc54fed7534a0aaf61ac23660abf" },
                { "es-AR", "29c9e7d5b5c9c31f7481f54eca885474843137adb3f39b6776c6ec42a3fd6bbf79d2b97cc6ea5a61b49211ce07ea5feac260f88924566ae89be3ac5b235f4f79" },
                { "es-ES", "078485df252ead4abba36c1a3ec032eb807a56c97fe9c6c2f8bbac7b26af6e3ee1c281f99f691e92259a1eebe42a71fa39220d111e727f39f1b869a09eef2561" },
                { "es-MX", "ed2db5ae6fde3a12585d319bc3e4d0b1be7b159965f88946bf21e53c9fd6eafff783ee9f17725bf7e94fc36f087bbc68e83e92a7c925d70e263789f9a1637d00" },
                { "et", "ac794597375e0d3f5e5a184ff1cd10118aa8f97b243f1d9d0288d082c315edd329bc6b3e51dbaecb9c8343024a9588e8259eaab5a3af429c3490defd0c6ed87d" },
                { "eu", "6c3f73bfd4d31be2429d396c69ff99f7e9753332020db4175210bc408a2acc5991317c4188736510c7519d21e36ff862754df0a7dccf0b4d0dacb372b8453695" },
                { "fi", "adf808fdacc98947a9b471ba2cb346fd6f4507a03abd2a1795f55a4e83ac2ff3249e15f3b71e948a359e51a1b4f8d5898922f9923849c8dec2686433e79c3068" },
                { "fr", "1d7621e20af98d68bea812b420d2ea5c909c1eb9b32a8b8f26b935b0551fca3d84abb9b00bd406b87a50a052f962a8597161eb1fa0f9e0a6f6a31ed6104486ea" },
                { "fy-NL", "69d51cbd3577f20dd0792f8783fa2abf01e1f763a525cef7a764722f954d229d51b899309a6cbb4029fdfa77d27fc9b6b36dded2e0a26fcf9f3cdcb5ce6590d3" },
                { "ga-IE", "aca154e5aa8351964e72af51b188d45d90c7e66b4d6fb1f90b31a2da3c67a91c68c306549248e9bb2f9d10994002cb95ddc8d218b5d10132662c43762ffb186f" },
                { "gd", "2c396e6ef696fc47db5099cae4cea07c70def2b9f0e99b3a32d13ea35ed1f61e6960d23a65e96b733c204510367bc9b1abb24a76c0b34f16e3f7e08b2dcad266" },
                { "gl", "9fbfaa84231b12b4bf34585f99183e1490ebf911f3046d3711963206baff1d947537fcea00860558584022a44b56e80d0165e75de9ac7757fcb0d92e1e971a49" },
                { "he", "61b786fdd951cc6196fec88dd7527ee7cb3ca122870490740c5e72339196c41299b908239b184ef90a6b113e8dc9d0b7dbd2d3c09ec25e052cea356b7ab0513e" },
                { "hr", "c9aa516dd3ea0157d4c68e2dc2bfe564570968f44242f60d0d7a1bcf6f38eed7cfbaec18bf849c5af3b1545e8b1e01ed533b669ccc464216d750d84a182d1ff0" },
                { "hsb", "36fead1cab3f2775ce5a2e67d052583600a89ab3a072130246857df1738c3f6f8d555262f2f34bf9990885787fe957506f68b3c1c50adbbd19e7345fc3fae18c" },
                { "hu", "893b12dcf3e8ce82ad746ee9cfaee523d37a10c9a22ad3ccc5cfe48e0ceb2f1b37cc339062c70c464cb22c7576a7526c95515f5a99f52b1120d2bec5f6851f57" },
                { "hy-AM", "64fd124837e48575e22a8a812796b967a7bf1a93d6fe14421a7ca03cd91e9a7fc7b9b3d6bc2019f8a2c4242bdf00824a1637712510891a047a11bf9124ac2b3c" },
                { "id", "afc0a5f599edc148efd6d84a379b3fbecae8a8120fa5e7a59474e4f4275330310e87047f472cd8af9e69c31d2a34ff4840b089d313d4a73aae9a83e287746cdb" },
                { "is", "4d2b7055998d2fedde5e9e0bb42923d4ddc75393ed7259b5663088daca7d343ee66ec59fbd165d95eff6010af542437c73225b2ed0195f0016ff9421e81dde6e" },
                { "it", "b28a607224d9b5c056f9c9bf048a49489e8c58c7760cd19013006c34d40da92813b067b3295701e4d727b544efc2e20ce2519c7f76ad491eb5df413f56ab6c3e" },
                { "ja", "71e3b77cf753b33d9e84d08b8653f1131118ff63ac8a025d37c2ac7d0036f0f76c1afa676bef91a5f96e237550d6a6ab5d5606f83b7dd0f57954b808f87e82ad" },
                { "ka", "6fdf15d94210c0d621402091ff4039826407f16eddc121dce4410c68d82aa97323136d6a6d8504fed27e2dcd245e8e58c97b26e51912de44e19946ae8c698422" },
                { "kab", "43de20196440cfd5433e6a72c5de1ac6dd8a53fe86fd556878cfbf64d58a988e7c28241131dda439e717d62ba8ac921494462321c13d20ba591a1016dba64548" },
                { "kk", "4e466a5945f333b8a3b964d498cdd13b3126a06639f24d64ff7b901862a9608965908aa0cb7ab349ed02edd308c60f3a6e5ca78912c309759e2d739457881a66" },
                { "ko", "93760d4d6ad2b8aa46c9fd56d58f879d406f407d6dbc3517ab2da686b193c4815ec66af55a964de099d833226fe64d4374034e61b0b708aae1d533e773fb58ed" },
                { "lt", "b1b0e2fdb2e63868dd8064633380d98d34a8304f4603e01052950b11aed3682292c0258a58ba6018a03c8bd5c75ddfe1976b5eced3f1b5ae5d28c0b0b21f94ac" },
                { "lv", "a3e22c76185ee117e54ed9c3e7c0228c1cc2cbf01a49933834ee95bcbf54920aff974b44665fb4bbf3ef60bf4d28a6a7fa008610c2f35d618fabc99a8d2400c6" },
                { "ms", "113c9a9f465e6b0315542b7037fd9a35709968823a013c39b81730b37f62ed4b5598132b0593968910d13e9d5ba2f915673feb9680b58dfdd66c5e80afa78fdd" },
                { "nb-NO", "6456fe7667a8bfb78d0dccf53c2ff128e8432954f116738f96b1399e82ecf43677186c6f4524a3d6cbb0efa8c75868b6e09fd0ad4983d3096db1c3e0d2651052" },
                { "nl", "442ae310f4ef9db51a0cd05d674442ca83062bedb3695f1ca428bd79b8c8a8663151d0e49ccf3cd27b4988224b69d3e4cd9d1b32c3e12fbcd9074854ef489880" },
                { "nn-NO", "b119fae7225d44f09618ed675df326e39c7866727bae042d74152033ed417194918ed086069a3885c5645b5d1d8221f0bb6cb97c6689c32cc2156eee37a10de8" },
                { "pa-IN", "865c259a8e507b5beca39d4373be682467b6563680bcfaceb089b8b80fc257e6a70662f91580c9ef1c7de6c8c74357209f043ef074456908377a41b40bc20dd2" },
                { "pl", "6c2533aeb7283082bb621ffeb7dcf839da4010ac891316649fecfa55040cad1d0c4056901400782ecbfeadd35c07e3273e945ff5dafb3f6cf4c9e200e8a5629b" },
                { "pt-BR", "4596d273156a3bdb68de8e19810174cb4bc47bbf4f3216688965f095a0afb5e5b050315b2de4ac43cc35a58ca9e4feb10bd9ce47f675919a34ac70997f8a7fed" },
                { "pt-PT", "e47dd6573ab25abca7431d69f6481af06a70e34b15128b404b77c893bb1501266fd10dc45750efaf0dcbd350861246ea0ef5ea2cc1d4e4251da68b8f2c995e60" },
                { "rm", "c86438cd4398ea853b53a1c6be86f2ec9dd303dfa6b671d7da650b332522aeefc6657e7982f80ba87752a8ab9e25c7b43573e10b578d72b83eb1ded67bb6d79b" },
                { "ro", "1f71bf93c0d66df661999daada05bbbc17872068531ac55092800cf5c2828a5746c2c999a0240aab936a38e604a30fbf7a7a959780a350a13223537fe9587e9d" },
                { "ru", "d67094381c293b12a82afe520dd66565f75bb787015fc5992ff80471ea6809724be759f2e3f9bf35be0a69d85a5d2f95ea6e362b0d66ea148eb54cba1fd50143" },
                { "sk", "70241bf08b5cd8da7621717c9d57310ee9d0754812b63a6fec2abefa686042e7ebd00ead73db53f5246bd616db5f92d38ff97dd67dbfef37e514f398b7f570ca" },
                { "sl", "8f4f7ed7e81b863d2db13cc1dc07a2ffce3c666c096e49407ce375bb56db1b17ddf5d8181cf2c5fedb0b0a638e937d811d99a6f65864a670e4e60f752d162cfe" },
                { "sq", "f8642fd4b2c49b669ed6a19b1d59c42067550cda6c1bfc3677a351cd542e207777f3031839f89dcef5f085dbdc6dfae26d0de5903ff951f123d58dfbcbfc062f" },
                { "sr", "9caae132a4f33c0a6733c2f468d45a3ac80e2293c44438afcfc5f2f936a0d25d63e288dd679753e5338b67b45140b34366bb35488e4e5c6d0d84f57ba7a7fa8b" },
                { "sv-SE", "ce151dd924fe5d1b9faf09acfc3c46057b91057da773e3c44db2ebcc29e51bd5afc0b43d05c0838d1a97407b4973dd60f25b5a39a93a76f7fac215ac86c267aa" },
                { "th", "24aef308223b74beccb797f5e8156dfc8543a2408067809717221d5fd2cc34a3168d84d2e371f634075115f5249bf179b7cb3674d55bd182a8236021fd1e2dce" },
                { "tr", "febb4fb2138ca1216b94a5c1adb111a9bfd5fba995592b4a100726038b484868b8a868788afe5ecd260695db6b17cfff3ca4c981439a6ae579cf3073fe8c8f1d" },
                { "uk", "14c5a2a20d61972a0627a40cb0d32b90eda8e5455bd251bb9527aa1169e49161eeea02d70632e795530582d84117a5071411ca3aa3d1c0dc8ca4c92a479040c2" },
                { "uz", "76ff55bbbbe2c6c9ba415040478cadf685fa329476becf6053bff10702554360d34d1b0edf8adb290557836c00079d741816539d26da7eae422fc0a75ba2650f" },
                { "vi", "bcdc25ab0e495cf75b8f5fcb2075054c679cdb6fe3788ca07c278f6a6105b5ec31882f2f475f8f1c649eb73efca8a9c88134533326c65a4e982e8996f2786e83" },
                { "zh-CN", "a2f33e2bb7d71bd29976d1c65085ad4855b06cdd9bcd55362684a8c5bdaf8d9cb9b046a499706a89883a7adbba1258ad0d23ef8c77bb29a43c921399be991811" },
                { "zh-TW", "e2978b93574c6bf250b504a630260de2b96991e200d602fc123c6afdbced932b05bf24eedcfb5914dab2bdf3e78ca7c042dea22eaaa54c4f2e9c4f184ba64825" }
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
