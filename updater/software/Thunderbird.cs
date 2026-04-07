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
        private const string knownVersion = "140.9.1";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.9.1esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "3b986ae7c645e0adc697a96f257987f668f54a7464556d9414ab2f3dbe50c3fdca3e911c4f7b9fb1dfee0aed15aa046c9033743715d7d6536b75627a6ca72e7c" },
                { "ar", "c1b7aa45fd9ddf593d3086d523782820e352476aa06d6f500ac563f9300b011251c9ce5b77f93162fd245d33f2be537e7100bf7d8f9122d2c6caeb67b354743f" },
                { "ast", "2e692bcb2c02a44633f86c2c9eb1201d9e55df9f4a15bb1f689c02e8de24ff3fa6441571fc14da37ce8960d1b049f2f9c427d1758c5cd8fe735f4f6cddf28c28" },
                { "be", "5e589a62332a649bdccd0adb7408873b764e53c0bd3ad4b6d7d92d4ff80a56166295e9665a0ee564619bd3ec98a66788cb5c2f90e5e9c91a481f95d53665a0c1" },
                { "bg", "3ae780f45fdbc89affae70f30350f58e255987676f2844fb5dd6b9d6cad8772f25209212d9a306c38b57463e56a689181d3d4faf16d146d0d9bac8413c9b9406" },
                { "br", "464d0319d84bc24db885ff09b5f903ed2a7e87b7e4b308270f32f37990de3e831b730a8c05889bc2f3b23fdd719fe4c10382cb2ba2cd55bfc15bcbabbcc9c196" },
                { "ca", "fcf69e8ad5214f433a5876c1ec84a429630170e110b4dfc6ecb2adde3ee41b9cc3aa5c3f92eb4f78b22fb4adafe4768d320da6e1b9f12248d1e2ec7087664032" },
                { "cak", "72ea256b94d9ea92e8d51ba53b5c1cd714a154abb0a62444ad8a03e0e00361cd9858fcbe708ec8a6022cc5da90992c14781fe82d0c16323ea537cecc5f834940" },
                { "cs", "e414266f3403a7a672c0550eae9947555d9eee5962733d2df8af8eff56cc209ad5a720f1d154b85cfe24c61cfaab8b543dbb04ee56b9625b4b5141022395cf8d" },
                { "cy", "544dfbb02fc38ccd8cae9d3b39a0eb88fc41f5e2d4095f47f20aa7112208f21ceaf04c8c9678a18ade72f89407a5f63e77a4f27f07e45e2973b8f233efe9c376" },
                { "da", "ff03dbfcac939e3925de25f07d5dacaef825fcd92094abbe1f7cc1d2753768c46cb6a80b8a77be2e7ddb1acb9b8248efcb2b22535034c44a25037aa08cf9224d" },
                { "de", "6667fac9ac975b23253489f12ea7ce2eaa376d2d3bf336fead0598dd150d1b42e066e74a3f07b139e7698ab21d9c5cb34294991d341dded470c0050eafbb2b11" },
                { "dsb", "86da399497006ac1a37b8e5617eedd50fdd1a370a515305bfcc432afc4015bc634bfe378ff73445e293d9fade7fb0ac02ad0acc1637405bd17f52abcc9078f36" },
                { "el", "15ea55ac017647f11efd948a91407e6ff8e08be8c2abbe84463d694bd87330b75a96aa008ed8ff858f8345cd856cc774ae64698229e3795acc93fbc9508e607c" },
                { "en-CA", "67b011203c673d4a6a49437d05a95349331351cfcf0f2cff7c9959300a14eb74e2d93585233ba2f98e5f89dc1021037e28d3c8c96c2a38a604a2c3a8781cd53f" },
                { "en-GB", "e3419991651672efefd5f6ac72ba6a3958b563cf13c57f44b9d9f093947abd9a758200c3c5f60bb259b8e83d6b44b5faadf64f54c3ab39545e608545d7e3dd7a" },
                { "en-US", "141ee9d052c84628dd337167ec0768ab107dfe57b9414a487e8d8f94af26d3fb1defe00c3199bd72599634ff055f5d7ae9a731e4dae3b5b650f54b28a025b7b3" },
                { "es-AR", "f53cf84b646b969c68f6c669b8590edfb2b2cda3c43018bf28affbf646d821c7ca79bec3e1b583c425729fdcf03732c62dcafb12a02006a898eb0043e11ae594" },
                { "es-ES", "a3871c66e59c6dac241ed648276f3b51db144e8cfbc17833e19b1d7c956e38e7005717decfc928383285e81aff5beb9cf61e9d7e315d8831c0bd119827cd361b" },
                { "es-MX", "61596ea5e059b35a4e37b57df0bca09dc14a6f253a543f8d13d2a472efb4cf8983521dc53408ed668a99a92e5f98dc52d4dc44e8ab757f9419a6d4cfad7531ad" },
                { "et", "7b0d13343bff88268ac5c52f8f0a494ede582375d464b62dfc830318345629a2b6d496a7816a72c7bdf71f817b02c2f829b2b2f86af680e4a229e06164cdbd6f" },
                { "eu", "d9ec5cdbe42cd5e2a4608921308fc58bacc069f846ecba5d9998a9d401b847e1d981f71e39cf859038b2b5220529a3bb22c5c09c43f1e68a51597d97298e3f89" },
                { "fi", "5f0eb73ec72116610f80a749ee75105ea5ee24fec88592a81802c43cadc78e44642c55ded28d58697510af5af1420d59b1da7381454807b8dfe6fa2cf2bf809d" },
                { "fr", "bc3fd2a305e0a64ee54632209b9bf0abba128bd23c2f266dbadbc99ebf548fc3e4390380909b32025407df37c5d874a6142e69fe17820ef5ae870b478b275d2c" },
                { "fy-NL", "ceda6c266fbf4746ec463fbc5fad6a2ba4dae15adedbf57eca222cc3a91890338b5f33244df555aea1dffc4fb2ac5a59abb568e2c46662800462fbc2cdd76c74" },
                { "ga-IE", "5700591cdd0c5c5ecd94d46f091ae6a4a3b58b657268853262d744bff63f8f4eebbd3b19e504f098456a5476782a4da1d5196b6adcedcf7b7095ce1b8d60a1dc" },
                { "gd", "5333acd8c6caf3fd147ff0bbe757132a21777c2ebd71e7f2b113cacbdc291f43600d6d4851a85447ccee4ba170e3a777036f7781e79c7c485a189455c3dbf195" },
                { "gl", "9ddff44983abf4186600ebb0b2a2bbc69112db02a5c1352934ec4e026202abe1fa3d417bdc32eb1a1c3aecaacf7cfc50e5f1b88d73377bca963a4a4de45a536d" },
                { "he", "8398aede7bb14d164381842d8cdac9303f97729e42cbcb4d5bb760d5e11d50ca0410e5f8b1b1a0332180742b4caeb48a6136abc9edc5876fa2aabb68db8f6d6d" },
                { "hr", "bb465b548b60c082b3296bb2d32c077129ba67ce5e47da2d05c59863379cdf6b8b450fdf289fa924acbc59c6aa20dda9fa1d73ae8222fb56eee980d510158a25" },
                { "hsb", "ee9cea87ea7f4a7847ff4da25f53c296bbfd76d0c229d15ffc8b05fc18d98470ad5b659a5061d0c32433df78fdb2e747981f83b2dc1cb49a1c559b2f29710732" },
                { "hu", "45443f89741004eaeec5c6d708a14fecd758a2e596d315e697e6d738267ca3fb7dbfd07a86d64cf6b89f8d7f2b6f3768f849b7d8c7bc8b5ac87050416a8c319d" },
                { "hy-AM", "bfe8bedf8ef367f3783493c78c6c73c478caccd588f4ed23ccfc23ad64d393069d4a825e5f12092df1a0f2a25effecfaa616066016243bfc93a0270720079415" },
                { "id", "7aea1592ead7e6447ecb2b91504ecba40c102ee06f108e2129fabe84efbb59b60ee745c5ab906b760d4bc07dd6a1a7d710a83c5d38039608cb8b777d4b52d702" },
                { "is", "66378df4f3320c11ae67a8b94ff0ca777cab573fa9422369acabc9df98caf4c0b0d5cc448eae0a07647b653c8ef6018026c6c3e3a049fa161babf2b07967eebb" },
                { "it", "abbe5007058b03fb385fc1b1ccccc05bd318dd4eb8e89c8e4e15bd038c660c01f1c7822d78babc1219540c30f89d72e4828422302315ed47506185966c1df42b" },
                { "ja", "efea94f6d6c390eae56527171c0d01dc8abd6025a490d47528b14a260c953605eae005eb0ae958f98f7f07bc9f43577422621cc6e5e83ab09d6ffd3b24e7d916" },
                { "ka", "dc38f9118bbe6f446e223d5d5bbbdaf77556e93597ab2768930543361a3041f45ee2a6cbaf71787c9d7104ff5af0b50f3a02b82133ac8cd6fe6c0c936e574d37" },
                { "kab", "1700e8daa52f161ebd50d9b004990284b2d199581694d5d0ff0f92a7fd9faf6d87c129fc7100e78b23e5c6b73af61e472d1fe142a1d50765f950a7355fa49200" },
                { "kk", "3be53a609aecb96a3e2e7853b9345a6deaebfe7874d740d0a1f1708d697f5965347e4fe2f561af30b3d432ccd20b1859d198eb150772c1e6cc9c74e23a6854a8" },
                { "ko", "8d923e7c998297e5b0a0292d796e06bb84c549c76271478b324e233c7978a413dd2c9c51f0760c06a640947da29c185a010d7302d28024bb8efb52be579e6667" },
                { "lt", "ce9849cbfca5922ed7ff30ce97b4c42961cd5591c59ab41650af62a0a5528b1d694ffb2f4666f4a6b9bc496d5f7c1aa4ff2ceb2a0f021602f29dd3076fc00f9c" },
                { "lv", "c6790a4945aec381ee0d0b7191015f0b14eaa0dffd660ca4b8dbc4fd3f4975cca607bae06d916863bb833bc4d81fbd7b276eae9b95dfee958ff5ea9a05053d55" },
                { "ms", "6bf2f02b2e9b1e85f3871df9a7527a7c2334462f908ee1c05dabb07ed84e186fefae64f6642b29775e86b91e08a58248a619329c5e49795f5c3dce035ad530d4" },
                { "nb-NO", "44e724113631b30ff359e7e8c0f4c83d1893cf9dcbd2713a21d89cd8f13f13076182a1e77705ff35ee608a6d8492d1165bd9fa7221473202e24bbc1563dae29b" },
                { "nl", "c25083d4ba8c828fa6768805c97437ae8899e682845c556503dbfca7be38faa4e7909389f3b587457b0359c95292ada5656959b7a2aa46b5b59916e76a048b75" },
                { "nn-NO", "08d19a5439aa79b683caff673e7bb594262acf926af141cf666ee27fb03dc8208a3301d2616123a6623516b395d1da535ad25a160cac60b02123e6f94fdcf33c" },
                { "pa-IN", "33bbd633bea3db500c7e0bac78641cb3987f61e324315383ba62f7a4c19a155229f62973711786405a024bd6c74ee9c8c4022705810ecbff1600915581ef4077" },
                { "pl", "7239bfcddb2c2f2823053edf00643aa83e978663e06b0aa7a93cf012a6e851280fdd416081f1394a1118aac971cfb3a222a6477124a00e301d99edd1b30b41f7" },
                { "pt-BR", "555e84d76a5d8fd3ec4b8b248f0def500eebf36d996d1d37ba793fba8914fbf436ac4ff90d2dba1f51147af780e673a5d62d72192eb8f43af762d18908afca70" },
                { "pt-PT", "2b9b75a1f67955a32d382bdb661b2d260ef46e5f3970a049c7c8635edef730ff4dd9eb987012e393aa3362d784217a412bb734989468c2888de727e4d51b8e2d" },
                { "rm", "fa3cc56e33935ce7996a1cef158de9254f15e7ab21a7b55cbe90f429f5f682cfe49728bfd48dbb3367c26e3eb4c1ecc9e41a3a5f6fa8acd26e312354440e06b6" },
                { "ro", "0b379700d4fb93e7972927462eba8defafc50624dd72a07cb978bf930f8969406c0d95eae24b64e31648752cd2576139173c339d3f3c424d57180d1d6aedebb1" },
                { "ru", "d20f2a42758a2a1e91718de593cedc63013f3305cd280932a95aa9744e8c42f323553cad74608116dee457fc492a7e3d71f1a7a0417e0c4f87be8db5b4938fbd" },
                { "sk", "ecbfa262d15a134d9d1e69d873777c8f8ca086a153c694ddb08507e9ae1cdf78a033ad7944a2047f8c76f9a7d72a5967b5a93f67bda25d9de8613c12e45a906d" },
                { "sl", "ce6db18b135090041f140c6667c69160f7f310d3dd8e91be87b01addbe9542187a5d378b70f998ed405f685abf91ebf26b1b8ee4f608f4aaa97c05c17bf16812" },
                { "sq", "26f6e4badeb59cf81b7d830b845a2c1a473425d104006fc69a08d2dfc6ab19879aaded98e915b36e7320c868afe09bb0b41df50de362689b9f7821996cb51df3" },
                { "sr", "e4bbb83841c88c742d0d65bc7a835ea99c05c4a10bd05bda30eea7c868d5f77eea5c1b39294c71edd03bf115ed3150a9980e9f25ae04139aa0a07782444ddaf5" },
                { "sv-SE", "4d7113b63a7759730b03d50e582fe048824c4d75392c13210deda582874ad9021ce94dbe94f5bd8a1f3f35dc5262acd0b85611366026d6d9ace9688b87d400e5" },
                { "th", "3343755908f2fed5ccf69ca1c075e76eec7876b50a07aa8424209f2c067de5581e248da90bf7dd95c35c5f9f22f48b8fdd06f480f62cec822240cef487ac2611" },
                { "tr", "b1af4994c26f16d8b263234e04df7172074a39de35ad942dbcd941cb85751a797b47368a4e155c0252b63e18156796d2c878d001c49384d4142a679ba1e81a59" },
                { "uk", "136bfe7cc5ae9a82776a9ba6e30eccfb27ed147f59e4c46b0580ff21896b9edbae12db7e4fab258e0b50c2e2e2d74a032b6cc55e76fc24b10b276a911cdf6539" },
                { "uz", "28bd97fd8c57ced8be6fc4da66006e361d3af47f207885351146988467b8d8157ff0d0577a2743a3735d37a35ef53fe7126859ebb0bbf9041febac14fdcd55b7" },
                { "vi", "a34cdf843026bf8b9ea241a83f9c5925a60b2a055165ca78287cfb0c02c642bac589312eccf7cfc8c8c427118ad3cb06569e0985014122834021e90c992fb838" },
                { "zh-CN", "e716c9277592a546711f872ab05e7b25a1fc93a6299de6f7194a8aaf3c329f00d45040dd102879dac4f8b10b078d176456093a98a683b9f7de8651e909b400d2" },
                { "zh-TW", "3824684fba270fcbeae9fb8ff2b487d34521c49c85b7193f5b72ad4a9dbcef502e0184e582d78668f8b342305c9aa2c4cd8658327e9082854399f8cdd5352bb4" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.9.1esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "1cd92137cca8ed64dcb83299d1761328204edac3f5399d51408ae36c1d1985352e9a96dcfafc017688b5585312fb2c3e28827778e884a10e3f3167b46df1df29" },
                { "ar", "18302d88cad0ad183ef4c7f3d68d71a006a13aef4d83f9635cb38641cd8ab514ee257cab1c7555b607902d2c70dd9fa938368a2d8e271c384874a6504a16af36" },
                { "ast", "28932cefca236cb19e6c459139c6ff306119f07e47293137a18d406546c7840f760d1f5d7e24926296bef8a57bbf963d96cb830b227ef2fcd0826a3ee9432fa4" },
                { "be", "0b9f4c46baabfe83f5c82de4884477291f5e7e98e9bda3373aa99a7beef22fe527d8b4bd1b246caaf189ec1af19cf04f7c68f7db1dfef1eb0426980430489f2b" },
                { "bg", "dff2e2197450c2d367892ea33f663830e48e391eaa65423505ebab442443f02df9865055afca76cf7201eca76581d37eb2d08fb0d349e697a9ee9d4bb60301e7" },
                { "br", "5d802747e39ece70a37864fa5d8649fb82f15749095360cee887c954649023a7f919de0e8e2d91cfd24a271090fccc94a2e7bd75e9e6a28fdd514c953224242a" },
                { "ca", "0222e1823b7a3c057e551c68ea0d11fd3862fd37e118bffb73baf00aeb8d9bb87ec198e49ed95ab989e289ad9a669ce8074f8c205b808031c3fad1b289705b16" },
                { "cak", "5c60a939077993413814caa612ff01db8cd03a84f0907f96e74cbab64d6e4bd646d4cfd5e3ed3ea748d665887470f300b60ee19c9ba95479072a011d3b33aaa2" },
                { "cs", "40bc04d1b96dfe4ae78103fa5137ee97a5acaa40852b1ecd4f09f048d3719e55eaef493a6bde7f283c95e7040dcfa30b4400badbc7a2ad16a81c1b74c0740b89" },
                { "cy", "eb7e5ef81ecc411cd26272bc69903c05ce080d6b0d6a1e69c58d5b047f1506abb843aab892d702e9de01fa98749a47e19500b73f482f3ceae8e4cf57ccc57604" },
                { "da", "be2b78525a7ba5a2f0ad0134649d5fba3dc4070808b5d080a1cb97a557c9960b45c6ece305784889e76e705281d0fbb55c8005d3fc2c8d1d6891edf70cc5940b" },
                { "de", "cb04369541e5a5a3db2de4beaa325059c72d46c1b46c3dbd0f9a0106b98993318620e175d31d4d0a8da2e8a5b8d2fe86e6ad95946f83e5e6d4767b3b7c35e68c" },
                { "dsb", "23b404abb05d2e06e2732ad495c4fb482a725d5fb026882cf5d3043136281fd798ba93a0e9a1d545a28d1bfd2d13362475429088b8a9a9b38d37d7870e12be01" },
                { "el", "09cc073e40f7b4604865314b5ab3ff8132bbe341376de27a01757c752c06983f231710d7c750019ff208e0aa9ad13301ee8fed38b61291adcef3c79824ad3796" },
                { "en-CA", "459a21148efe8e2e6e831a39a87a766a5fd548f6fd92c32e0cf2fa71d2bbd4063a7858ca362716864833c9d0390069ae225180b8015d03fd129f03b2159dee04" },
                { "en-GB", "51ad15fa2464b888861a97e63cb7eef343745ec5c98e337a0ac18449de18438a5b00c9d11a49287a50d61d825f26f1ef833e911bb02733ec8e98a89c9e52924c" },
                { "en-US", "dcd3cd6192ef8918bffbc4292fb209b4805da9012da0c2d8fc89767c752aff872c8eaf9afc08b97be60cb4a86d22bdc3a62c198c8327917fdef4da9daca1b24d" },
                { "es-AR", "7d7a3942254a134b9f9bdf5b316cf0aa69fd65350fd0a76093fae68190a77d2d66c049cf19cf131f71b00c9ffe679b99399a8b75bad233ee9e85d3f40a49d5b3" },
                { "es-ES", "d4afa7e63a39ade77a792814a6f3d48685b452e1afb2dd002d96ade0018a86d1d87de19fec24d82d460f321ef2d00117486c6196986e3e168775e4463e951756" },
                { "es-MX", "23d58dfb8973851978b474e6a269c476f8e5f73efa872258cb12149271091c14bf87c14c7ec88f36a83df866e943985351739e5e0d75230940cc57162a5c75d2" },
                { "et", "f5655490444707955998443a4cc444a4391be843e629cf99fe349d86118610fe8d3576bec6d366fd4d315bf2829eabf409c6a0e91cc55b6c31c4cfc9c6f59f88" },
                { "eu", "3b88ddca772a234f8e76d67751d54a1d71f396b0dad1a26f159c8186ada50ff7ce3e3b7ef84c82168fcf4aed0ef2996910464f7087d31860e531179b41a3fc8d" },
                { "fi", "c7e5b5a4a5bac063f1d2a3caaa03e092f287d9fdd8aa2c737a5104f860e85579117a8bc0d227d011463e52888e7861add0af15ce8daa3bcd427c79534489180a" },
                { "fr", "90d28f49f16362c85d5235f14454cae3496dcaf3c4285cb981cb5ca45eece383e4abf6a792e9fb50ae575f76e73669045495641ff77be51491decf004a062910" },
                { "fy-NL", "2931c936a5457a0f57681d10b5737b20b82e0b741370939af0dd4013b29d271e8ab879b648986436b1c8baffe08f6a1c10554eb341b66b3c12e498e49ffe7e45" },
                { "ga-IE", "8dd6934bc37e4dff8e5b517b691a63f4f5a5ab30062c370dce003b55963416e9bc256aeddebca9eafe8a7f1900971a21b105209ec8f25fc8d60c92013a63e5f9" },
                { "gd", "2a81776927c0a564f316cecbac216fe6319bdf215ff40389f72adf5221b02f14d55e4c180e18aee32697396be8008e2a5c35dfe13c2b4f97ff64d673ff6d80d9" },
                { "gl", "7e0e894024db693d50bfefc6c0951e0619365b88554f4078393c339c1c89989d7411d9598a4eb5f244c6b60476bad1341a39f98bd47e05f2ceaac2fa143cffb7" },
                { "he", "5b2c91f3166502222d4859d480b3af2eb986ceda9bc68848618496148bf920452523a20694bbb2dc2f58cfd3bec01959e44b66c4201c2f0b5f34ea055e1abeed" },
                { "hr", "660b64321bfbc3089209327649f92345ce1b5083392f75a8c2d856c5f6dace0de47320086acfcb4593842f3027d99247050343d1102c95a68795285d245a6633" },
                { "hsb", "92f15359218a1fb263e0629234edb6496bc3af790e85c6c238ac7025e8bbc673cd7dd6e8e97dbf85cbaf31909fa4a8f3708c84f77849e4045d91067a1a58d6ab" },
                { "hu", "698fce969a0d63b620376e863d53d892b29bf6ce80b6e162c89a4e5be508261bdae5ff04bc6733ca85774e201db42796aec32ca33d2d8f0d8f0a7e8d43beee74" },
                { "hy-AM", "40c693182583df7e807b9060a3a8f999d565b553fa2c546321857d0879ade2fdc17bca7ea2f362a7a13afe0a98289de03578e6331e7c28a70873b7f76a932ce0" },
                { "id", "61bed0704f0df224eb8fdedf57d9390866a3112d60763dec0e1e36d75ee55470b5ac59f998e3411d1a0f4b07ebbbfbd8c5ab0c9a051a85b11ddc821ed6f4c87c" },
                { "is", "6e2b32105c4c60023c37585edd47c2beccda5377ed6d435e718a6f343da929513db0e33239ba31d84a02aa766870bb692906d315af96aeee9d5fa198e7f560a1" },
                { "it", "db4dc83a1c9a1787d6a2a354c6e032ccf75400e5ccadc952b6bb5390ddd229f786c585d494dea2813e448b2a95931e568bdcfa3796880c635fb3b740772a4bab" },
                { "ja", "36e02a76dec5217dbb199d885a0c7c0fb500c6429e29c83f0dcc1ad284b85b7f0d53920cf91afb55061fd0b7422611b9b5512e688210f3926f462f17db70eb3c" },
                { "ka", "6d666733c9f34471091781674b175b4722fe8aaa640c33c9fa8d6f708a88431735d468553b01ba8534a8d62ece42b04b28968b0b9ed7f00908015fed5ff553db" },
                { "kab", "ac68599997b268d5f9260a00c4fb15ffd6cf92d31a292111f37f6d09ac20ee74a7ff86f71f318732055d5151ba8ed663d5e9dbce3d6a3278bb412c0a9c86cb06" },
                { "kk", "207656187d657808cbaa63a85f1b903cc0ebbb3254dedfd7f520c64d4861a84352034abdddc9001731d26b0927fe9a59ae414c1181dd9699b32c83f363922e57" },
                { "ko", "daecb6f9ec5320625c0e1f39154f537f35b7fdcceabb347085268b9188404693ed8dd7b007a3f90b96263cfb5a6007b7abf9adad7355ab3b535b402aef297159" },
                { "lt", "c592a8d880ffd66924d21f748cab5e96820467a6f0c40606c824d27551e797c8ba4bf14431aa2b3f51dde52dbf7193f5661d2f63e7a35c05f4c39c85501e7dd2" },
                { "lv", "931ea1c8026ffe782d00a0b7c485bfc58887bcacf6f4305b9cbf0a115e692f33aba989a23ea9948c0406fed04fa9e5477f3b6bf2a941c2b77cf3342c8021b8ac" },
                { "ms", "2428a9d577024d5c20ed05de3f0974c6a48fec3e0a659905d3095e3b7da2e9cc47022f9a001ed74915bc769ea9193f666fff9295da27e030fd818812f81e47ec" },
                { "nb-NO", "0894b8f7fccd870b16bc9398a6412c8d82d850679a68884d9b9df744d5568f52527fbc07e5867cc4e118eeee54d99c64835dc4d8775a5076c7b5a0f8d7bc90a4" },
                { "nl", "7ab9ef91ba6163c60aca9c296399ac22d05cf9298d85f9f3ea55e23d06382db0ee6033098ec425520754c30ac7af7bd328de50cda911b7bbca3f0e998d8b9263" },
                { "nn-NO", "44f658989ceee956753ba8f5ffe17c6ce5994a5880e879c234708b37552e6ee5ee1599047f64cd04d9ebca786415c46562e4c350d57960fc80cecd224ccebbcf" },
                { "pa-IN", "4b494ed8ef3afd2995e1cfa71ce57f71c50385eeadef365aea7c22a23c6529ac04c97bf5d96cc3438bd6e8eb084833a8dd9df6888df4787181a9c227dcbc48df" },
                { "pl", "ec685a8663127b7456eb003edb375a988ac1fafcbe275009d4c3a48dfbae15956cfadbcdd0ea4050d84acef5188b6b2d1e2d79e5714a18c27dd0f0b204d8ff79" },
                { "pt-BR", "95e03aaf2468f477938b86cc988c9ebfb87dce78e40b75fba7f6158b97eadf609006513090919d95a89ad61bffb460ff6e7fb21ba218eb7273733c38dbefd476" },
                { "pt-PT", "7051b781dee45a8d467fbbf3412e5d25e7e5658c03426a8b3d41d41dc937164a1c0216d60ba7def547f6b2d25f3923ec08e3b445156636bb89f058a58a54a82f" },
                { "rm", "b2fac8fcb59d514984ded759612d1dd721bacde362e06007993f38f9a678d5b6099739ef9693db5680ee138a3da83ee98e5bea85514b81f86d2d8c54c7ed1de0" },
                { "ro", "29a7df8020804165e8f87c5554d4147d3da12330ebd6a0b6af9d4d66bb2a6d30be6f01d7db830167bfda79e81b39c0c157c55529da27771c9bb0fd331ae61089" },
                { "ru", "6120c429bc6df19bce73d2d81a557992eeada8b2636d7f16761fc59e1ccdf6458d51c8fe7439010b7352609b9a706803f0baf62cea3ba4d448add5f83670bb2f" },
                { "sk", "f715c70cf6dc2d15f4529b08e74e73ab03e5dddd593064c96bd93822a942769f3365b629d13061d367dd5bff8a41650e4001bfddf71239b79e4aa3d0bf6f868c" },
                { "sl", "a2f179bf25b1d139e5fe6eeaef179f8aaa5ee6e0cacf73a166ffdcbbac99a6733ea3a86e7b7087c51b94c05dbd5093260f237cd78351f4bb330e33d9bc1727fc" },
                { "sq", "d1d99460754d1421f214602b2bbb7d465f8cd38aa975b2745f3c3fd95d3be9c312de0c1a279b4389fddcfcd2ae3e20c31ea9b73f184c7f742c39f430928fd1b0" },
                { "sr", "0c31242dd83807b21cf1c277ef51b8c681295004f9f0dc8c8f2b814540bb22d97a2ad50ce99361272a8341d4416da6cc0a5b27cbc784b6650ad352449894cea5" },
                { "sv-SE", "d3fb9079ab7fa8cd13c8923b8b7788ee9808cf23570e329c16700ff6672ae06f095afb45f696f1bd716cdffed4b187b936a24531ca3aa188cf611d0de040bc7f" },
                { "th", "bd28cee3eada8f9e65f736723af95fde31f18f8463facd1e7b077ecebfb58bfc7bca224bb18cd3bf58e29bbd8b022d0826c2cdcc5282448ba7fe9db67b6bf28e" },
                { "tr", "19c849c791d7af7307efb369ad82e4c4d8ebdc883034001360f187c4c702848029a0202fd8f5635cb00b893650ac98342ae36300e5329e81258f0683d5cb485f" },
                { "uk", "cebbf98df448ad06a3a9f6ae9e44751723fff77f01217e454155655b426b0e45229d8ff65d027d041860ff5e02ac59e346c686e9d0e090b22b8b3c7b7811ec8d" },
                { "uz", "a4e677490d4fd50d4f915ebb9afebac245a8ca27d326d4c8f33d79d4848983d8002607d42dd97e7191dcbfc38ca89d8a1536bc75e2ce51d01ac369c6ee4feb3d" },
                { "vi", "84d9f294dafff83a7f92c842fc200a5a01490365ec8eea03a1f6732746d07a79279b2d7744309fc4f88084c2cd9708119adaa687974f6d09a74d119f59c83c2b" },
                { "zh-CN", "3bab7b3199b6fc4c3de8df5e19e5850b1bb1782a7fcf0949e39e516ae2b23dd61345825d1572e3c55c1ff0fbe7d1bf9b60550fb0c3ae334457c16107e8d3e158" },
                { "zh-TW", "39bdfbb9e681adb2aeddcb88bc6ba47999c151292278948fefb42aa0e0fd13480ecacc07f7525d0006eb03aa0836e979e48b41cbd3b092fe5254316072e92699" }
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
