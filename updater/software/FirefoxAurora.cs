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
        private const string currentVersion = "138.0b3";


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
            // https://ftp.mozilla.org/pub/devedition/releases/138.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "00ce9cbbd13cf0509a0cdd2d9b37ab7b73281aaa69415bda5c59005455ba4a7c419c05abb8cd2d1c9a8218a694e2feba1870ba1d37855113374f51ee9c7f4764" },
                { "af", "a680db21fe1f28419a3d70cc520f8b042a6b05391deeffce6c0b0e2a1d27ac88c05bf720d57783a620681fb9bf7c610524fb7965fb1d004d2c94e3fb47485bde" },
                { "an", "4a2408449ba52682506431fdf505be59171361c1f23f7dfbc5b37f957315f1a3c27ef967033009b758af9da0086e0ba185e7c46353e1848f39cd81761a5c862c" },
                { "ar", "1756a9208bbc0acb18da50723fc48cf8df52881cf8632c3151cb5607383c6287f117a44bd87024db8f3300cd9f70dcf4753e75b2a81a768cfaf2f6fdbe9ce6e1" },
                { "ast", "51a32da8586103f84f742cfc33c085ef32382f820f074ce0becec12d8facac41b122dbcdf5623458027cd71d945f49c1c66bca504fa76c004254e1eb591ec033" },
                { "az", "a1c629c0338d20fb1497cf724551892194141f6482cbc71a421231114e8348e0009d2d6e694b01ef212a993da1924009403cc92382385794f24a5cc2a2bfd7dc" },
                { "be", "587e70b4e40f33c9777a93e38de9917f17a2201fda1278392cba0bbeb6b789b646a467a4d9911c2762e5e62c49469c290644199e88b978f6dd74030a6a8d464d" },
                { "bg", "f672de711f44b23be06a2ee08db9121f7901429395940ac0524d824e7fcf2e427350f8ed2cf8758e6085a3f0284dc857d3c6f4476da9952062604abc598bed2e" },
                { "bn", "fce350a465ae483d73555b3fa300caf1b6af9bb3858c04026db201772b12bf77fe08140a12ee5326503b633b6692eb56bb2dae293e21e04f1515f2911542a403" },
                { "br", "ff4e6cce78f92dda42fb8d9a7d68999d46670683af45e1c4fac035ebb6f6aa69361a079fbe43a7295dae3c702bdf05ef586f13b66d17d70f21af1264da112d16" },
                { "bs", "c5cba0a564d277ce9c21e522780b09c17f7f56ea8d4d0a529b04600d525f2358e48f134589b052fe27d298ff7c3c3117f54cdf6d3ad7462c2ec8b59f531588ca" },
                { "ca", "01db400fb53866589e1c8501d6cee2032880443d7b17909c7b574b5907ac9097516cc879d53a2de925c06ac12f24834e5ea646a739b62d3b9cb7a354fb8984a2" },
                { "cak", "60ab4b6e2163a365346cdfdac000f49d43197b923fd9123366e97aae365ce5bbc63e696afd6a4b38c1c721e31b52f5199a9efb314ee47e60896b924010a54169" },
                { "cs", "7f2b34568f7f18ea96a8c2d9ccb81d32a8b7138b0d74f276282e10d569f13382e13a44319191973410badab76cf5269c53b023d5c284b89b26c6203268247c6e" },
                { "cy", "bae6706272cee374191e6a0ef02adf105137d613042f5bb6e6915f085a937c30380c0729c6502556d7092c980e4681d2be1536c83fb44e68824774a55c5a07be" },
                { "da", "c16fa5514bb0529546d903516826c6d3b4f7f92a483b41fc0e11dfed69e0ec39474db233185d92cb22e8d20724e28f68c076cf4ab81fe443892ff413e53ad5c7" },
                { "de", "45974bc1a48e4e0db7a0cfb1b94d81ff8804341760eaa701012156c14b998f024c432d239662f118bc63d4c0cdfcc203b3e3ff4e712d8ec0ba8967d0b66efc3f" },
                { "dsb", "f972a5a3f7c6f355dfa01891338c22efd46a03390766142bd77ba7aaa67e43347a953fdf0f15265bf5147bc8b9180c3b82424b0bef28070f8fb288b77d001b72" },
                { "el", "22ca20d7bd7dc88afe7c65d46d8c31022bd4b457d6ff21f3e59de3c8846c6eb1ad056298f86c2c527faac6011ae57efcdd9938006e32521813ee40c50ca9266b" },
                { "en-CA", "66017d2732d5ecfc707b9916d1111410285a02420d7e09e47c6c48c42acad8eedf37d50a69a9a91d7927844d54100fa1d7b3b6dc9951af90dad326e1e7fc9ae7" },
                { "en-GB", "70765e17c717ea51f207277bdb1baf433bcfc76be7e3d2a270e0dd977c7b1ea7bb12eecc090c04246c43e8a8ab12927f1d0b23bc0e174ea0a4ee07707ccb8d86" },
                { "en-US", "6d96112246b645c8b6ec7cf53c11f5f9b5e94abc65cd22c4574c09311d6410a3972a12876869203873bfca019d2ff2f191bf5d3a60cd9585804c70abf074bec6" },
                { "eo", "f17a9186d8e17729330351f357cb54749d7db9cf68bbe1bcc02bede7888b930060336a6597e51f6f34b0800d2984878e2167c189a5368c57ce2c2f7f8530e68d" },
                { "es-AR", "43c5e2f3617cc31da1d5652a60d1b72d5e653f991afa2736ebc0bfe3f77af71627db146be06f3a5f57369cbfb6a45606a9e9e46bb5de9a44478b5d399ffcf73e" },
                { "es-CL", "f3e794ed0b0f60f27c943a095b1c9c3c7396ce8df44bc7443330a012ad89ef24091bc4a411927d29993ff97d9b9ad5a2c4c0a1f162ce437b8191ff780c8d6cb7" },
                { "es-ES", "5110de51b04fb22ffe05d886cb987c766917d90314180888938d8b78b0edbdb59cf0d6720c3ebf89ed0e846f5b999e93e99bf9c89088849a2122e3116b351dac" },
                { "es-MX", "4cb5c51780815dcbe6e016663bd4bb1fee3da08e6652d22ad64a1f1be09656d3320e0d312131ffb2a878ce4fbfba6ae527e6aad31f1e84628be3ad3784a76316" },
                { "et", "f6708eb7ce029a80b747d42d28a73ce0e6672c2c3987dcd819decd5f90e06941204b599ec89ae5b3bb927c074190c19cef5152386d8d60141fb0f6310335fa03" },
                { "eu", "c0c515b144b309e3e38a239fc6495d687d5d7015c1081ee77334159283e3308edfff4a10ac785de7ca510407847d01945f7a91622b19ef060493eb7575aab078" },
                { "fa", "3aead4f4116ecb49368d85bd192b665de2c817049c77727bb74d5b7497beca6793ea2cf47f4c5d0dbb66cd9b0164121d6a986b4a61e07ed7325b8ef8bc8524a4" },
                { "ff", "f861da582c160edcb8a205cd079f1a970d52b94967db0a5072951e66dda6ba2e3d0251af7617c8e2cbccfa8d764142b4968c1382bf303aafd7712de435158d3e" },
                { "fi", "fecf26bb2186c96ff8433035b00bacec17aa09b018640fa683e93fae1aa613fce56ba03d0dd626bfbc95fd0315f42c9842bd788fb96e18a7ff6f31005ebba0e0" },
                { "fr", "8784e39f86fe6e1824a60c0cabb35f2520db554b49843d3646c4a61039bc7506e6df0f0cf2df8eb1011c79c01c47bc35c45eae14aadc0bb574e5db7d5a5704d1" },
                { "fur", "129c2051e8ee4ca86d3ff42bdb4ef324835f2d4ce2028c94670eec70524630a1abe2d5fe1f8e801d15f9f5ac63d6321e94ebc674b6c592d810048d056364d2dd" },
                { "fy-NL", "7de19d9b45f177e1c018e08504530de016b93ffea1169ef538260f5cb807ce473d8d5e67be0f4ed4823e70e6b3170dc64fbc370067498f8ded0f624c85ec5388" },
                { "ga-IE", "8cd762dbaf2e6cb88b918fb54f8003e4241a9b3cebb8ffee13ffec890417cf5c8055354b6f8c70a96258203e0011e8c6e70e10042e7e6bdd5fe50c8e4bcf95b7" },
                { "gd", "dbdf8e4d89b863300545b2447fbeaaeabfe9e02694b7d56ff983f1d59b11c6932020428bc2afbc594968eafd9a1cf8ab13d98c9412c5aec81c7e7764b823dccd" },
                { "gl", "4d8c025d79dfb47ef5ca985dcf95603964a2890d6d61e1e9f8870dc00b9d3d36513489b811652af58322aa96f34d6e977d3c6b499342a122e35a53bf3571fe19" },
                { "gn", "d7c920588cff35825daf7ceeb36ed81e0f01a5a65d1183b45e3e1183453748665ce7d616f8ae2868ce699983485bc063b4dc6cafc9ea5ab4f4fec92c7c075b3a" },
                { "gu-IN", "369b7c36047543790d768ac2b2a9598804cb09fef30ceca5e79e799608563d8cb1c78146069dfa2c7c41c27c91642bbe25c10833b554014389bec8da35e13108" },
                { "he", "a6191c86a3ab2d0e80e6411b77ca8f10de965aaa672f2b0a668eb4221e695d27373c17bd01a534726d62a02e584159cb3059fd7374cc7a5d17300adebecec194" },
                { "hi-IN", "4c1b657274e41cb50b8d24d6a05177ef58ca7131644851075ea908f2499533a3ec8f365ffa2f5b3b4edbd45fa115c3b3fe1121b1e1dec8a25c2a1c19fd3d7996" },
                { "hr", "3b8c3eca21169388c082cc1fdc49b61ac9789d4ff2bbc51614c3c073609613c264ddd69b441d62c5295f178648d92e11664688f68b8735dea89fc90660adf935" },
                { "hsb", "a18b5bf94dd747a40ce5bbb22ffbf44f484ff276e73559e759624f7a50f0e43c5326903c5714031344e36e5f32b9337739ce9c74a3e4e89027c7826894d156f4" },
                { "hu", "ee737c045430ce0f2343825e0a657448849c19e6e2d2cb7e2dd5e5eeecdbf557b649f182beab9db77bef1ed0e955c5e858f5caee1bdf994196758d7cb4ec8d02" },
                { "hy-AM", "f6772d8198de6828bc7ecb2eea135111609adcf4c359c93d0616e3e1466bd74b05068ba300ae8114d2a8f2c27839c65d4485add4fee37687a0c514d7a6a00dbf" },
                { "ia", "0519f9a61181533cc928147af3fa49250eb46e496df99352a3b16132f4d8d55200ad44ba676b8c647da7308fd266775422ea778a13f007573852c2672312bb3c" },
                { "id", "41a88d23bc7deafd7b8f39a75ac26ea19ca5bdf0595c3f7c3949124a6598795ce32dd5dc259462f64d6e38e9f14da5af6e203944d6b6e0673c0c7d915344ffb6" },
                { "is", "1ea6e60984dc52a2441d8dd7b9a5de0bb95e6759359f32c92ddf4a2b6f6db4ac5ac2849b27f2611dbee44a179eaaaf56c9c1e4c289ebc05c4dd088552c82789a" },
                { "it", "353b687b38684f446f3887a8933640ca176e655dfc8d4b41c2418b275bc3b0ed01ca222516171066cb96f28f9211ad23a1426862d4efdfb3444d2a2379483cf1" },
                { "ja", "a8403bca9931df58a5d0ea1b388e015d245521794b12ad58183e485017792659570d81383922da5a62961a7fd8fc19c890d4b229374bde2979743fed8ce0101e" },
                { "ka", "6468b56edfa15d15aa6a5506956328e7260c515b56b1d18a4426b00c723fefcf8c2a34edc1cd7e5a5cc442f0d4819caa8298690fa2834c7090ed9d9d6d5ec570" },
                { "kab", "4722d3f33c93d10c403081db8b04d10d37215b501faae8c17e9a5df4327a8e4eef974d0c14f6fccdc7519fce262fc711e423c1f20e89b3399eae8e3893e22367" },
                { "kk", "f86b00974698ef935cadf9fb1514660baafa33d05f81a49cc74aa070e82e2f647218927eaa903cfabafbde9899e6d500d81d82411687aef33ea9e19fe64fbe5a" },
                { "km", "eea044f6e107b22eb52722422c7a0680f4593d7b9e2762eca365df1eb192813a1b9fb074859e7c050d6f0487dbcd341055ef1ee6f88f3e5ab6e3fa6eb80650af" },
                { "kn", "b829fdb91479e89cb061231c5e26876aa29eb0d2be665c2c99dc11af9f6b7d3e27a8121f7312406d9d99b5b33c4c15c6b28714892a98ea07b50c68bfc777c0a0" },
                { "ko", "9ad7a7dc56b6d48eb7afb659aef8c5ca088a2e3656ae906e23d1dc59e44f8501d5c6747b7afaab34605ce138a8f92373dbf82571b96a18c845913b9dfff2f33a" },
                { "lij", "8c8273c9d992458eae52fdf3be8ca070dfd6fb7c4898741681ba19a01562cd0d9e98066e37dae4a3db261e9cf7eb2a0cd86bedca2b6e3d013a6a7e6443696772" },
                { "lt", "fe43108c4d7677700ed91685bda9151938bbc2848ed123aa8563869b25b26610a9bd89c2da581d99429bc14273a088bdc17299039df7af836ede8bba799f92d0" },
                { "lv", "a5dcce21a575e5e153a04c0ad728b9ac357f3c1867459531ce58d456cf0fc1bb4b66f00bda2a366d7688d9389cf358a734099434bdae37edd30cde9e0d425519" },
                { "mk", "7ef08a7a86b4163ef913e576c8fa0a066ad66a2876cc168a8c0f3f9b5249b11eb9ec213cf39c1a48408d7c809fdf621d8dced1ab3ad7238f9f321ae5e0659ee5" },
                { "mr", "cb91a59cf921a849c10ef7263417788da360d2ef3b3d16012ac7c92f0771391232dfc15948bf223ea92a49eca6c5ae44ea77413d1427c75baa1ce435d67375b1" },
                { "ms", "4d7b5f899b821c9838a7c05781a6055424434647cfdd71fcbd8738669115cf9e7438acdb07fcf50173fad86b4918d0495a326117761bd95af85f45935c94d54b" },
                { "my", "67eb570334389b97e1c2a59168da4f8c97696edef1bcdf89d26d0b08f3f1a7160b7abc8941564edc02d8abe818a77671500eec0619385cbff9173df99d01ac88" },
                { "nb-NO", "7d0dcad53ad54e28c924cb6377fbe0438c4f09efc5391e588a8048eb8e4473514c7ac49de7741b01879192f2182c609e37142e71bc347e537feda952fd623914" },
                { "ne-NP", "d54cf20c81c74c2766ab88918001ea6e646964f65f8098ada9769f115294b583e706e0139f08e9c9640acc954639dccb387760e442c01d7ad82bbedab9e1fe07" },
                { "nl", "266c62a73c7ac16f839085dad7dcaf5cd3677d169b4f43749234ef78a5437a2048a06a3e92dc2927e502d9f02d562fee9bbfc88673a1217345fcc5f041425b78" },
                { "nn-NO", "4344ac8fe2079add21913641f3c34e491a08dedb23a577ff95a7252fe892b668e13f4c6ba85352c059f3759a1a984277565fa4b2d23a8263dd79c1eb499efed1" },
                { "oc", "a1e18aef7f74f28bc213c468bccb82c020b6c232914d19d120ee03d2a3158c389ae4bc83b974759acb4719ed2d2428ec9734e3b2062353d3f6939b7ed0820795" },
                { "pa-IN", "a729993537fcc88630f645c84fc8deff9ab03762d55e58c85cd6f6b1501972faddf5d01989b3d114f9d57ba1e80a6273eb64a174822fb3ece37dd5c169f9969f" },
                { "pl", "dd893640cc82253737d6d69bfc140a48813154d47abed4cda244de7f3e1edeb4785d059ecb15029afc4e572b1a66613a1388566507c0bae70f49227bc5dc3a57" },
                { "pt-BR", "647584526f3a5d400f2d6cd043ad897adc4343e156e5948b861f002dcef9ff2e8bce569c7c39f489c392c1dd4ca2ea4abb599da8ffd21444b111eac09d2cb9d3" },
                { "pt-PT", "7d258dd9523f45ba9f3dd1df9d0b5c3cd36bc03b47689890d272d624ddd6cecbdc4ec3412b8a4946fd489b49aea9dab759d4061bec4542dc459880cec8993cce" },
                { "rm", "c6d632876eb4f18be5883f77e431663504c8e7303be29f543c222940aba3dd7092fe09e85f3ffa6579dd39ec1c100c89dcb824da3af1a191be9e329d0be094aa" },
                { "ro", "f29599382aa949150b0c18234e262cd1ba5e0b4e9c2c6f1d55d60497e99c13704e29ac6b55f775261e44a6621435ddd230cfa9974c26b7687fad9164d5611a5f" },
                { "ru", "cc51a0352326dc68816638613d6e100c43b714d74545c77fb96bc58c887709a2d7147db729efcfd9064fa8d4b62b00f7aaf8d9120b13987a568497e746499381" },
                { "sat", "59cdded1a1eab31258c1ddc0c54df5a5cc8bff4ab16de530f9a2a14150a9665ebaa57ba88c28696d25c2618308f63e65a88a3aae05461c9f2b7de9850ada4a8d" },
                { "sc", "d7bdd380dc95c1cc058113167677f071e2bd1597a1def8baf94c12aa4b6b46d923b8ddf217a9a96b1381b70c848cdd5174ae3eee5d8995414710d3a1e261b90b" },
                { "sco", "3f89fd6a3c34daaa3094ea2c3a440e8309ec31cf3eb26bbf2a882828fbe0b24d178cb7f8f675a24465d7aec5a31438797a5a00c0eaab22c2ef01734fea99c606" },
                { "si", "2d3d610859435f6c1ea2aea081cafd7da29bc2c77b4fe38faa4e746e2344e3bb8a398d2be3f8428ffa2003f8d9ee282b59be2a7501e0e04506f36a8b0806411d" },
                { "sk", "4d4d4ee959f90bc02b3000e159adc27789e5777a179ebba03275256cdbe4294956312ddab5f867257bc548add2895af70a0c6938ba0d91cc8df8cd135c693f87" },
                { "skr", "3524d3438fd328b2039811e10f0e1d910f61a2b572dd4ceee27faa0e0a924ebe4b81eb57539fa1d6a974175065deb4a8056e3b104dbccbeb2c68f3126ee15e63" },
                { "sl", "7bc754069ee648fa60ecf7a85d79df565a0cc3f57171973289f7ff3a0889be8b36b08ab93fc1c8a99401bc5be8e4a5f34f525fd3775981981a855178165b19db" },
                { "son", "b4321e1102f3be2e9e201174991d8999f13ef716dd83b8cde74927d7c31ff46f5784a67074096ed2dcc497ae3d186ea97be910ece87b847db5c0abacbf809c0e" },
                { "sq", "f2e875f0b1e70716bd8fb6c4b4c79cdf4aa902bd20d1645812ebc62056ed194d6f4da1a73bb00b7b9cd43fdc75a38aac7d70a5ec14b03d5b98cb0110f366e320" },
                { "sr", "68e788bc3cd3f1e96c06e9d3743e23987a6d497fa6ca3a835f88a570e53853adac605125e62797a7502ec89d94f7c33e8d79627e060eb7f77bb2de2492d39abf" },
                { "sv-SE", "446535649100d7e5e5e5936d274b18a490776bbb7a248f070deb9fa02f9f722a854c420f222789b259e84cf2e2d8f3e010f14ab431beaa34915c1f5fc38d5b9b" },
                { "szl", "4dc160a5e2949a7e5c01c40a235eeb423d54ed1c1f9b39c09b1d35fced56bbce0f0e250c1c6e1f0a0345fc0e9e93ca282bbab7344683eca0ec6e49d09e9bf316" },
                { "ta", "ce86ef2dc09f829e325e3d9dd4490762a599cf7134bd1f0136fa710d62190eae13f7678fdd46250138a86de4c5f8fe6931ed13bfb945b81994538d12e90781e5" },
                { "te", "ed5b2de4d3c287f74b76b75a1ccac92f52c1f5afdddd3fcf79d54a1ca0b8287532fb085f6d859a1bf88acca57b4f66837a65b62e1833a7d2207fed952db89995" },
                { "tg", "06a245ff44a267058d93296691a1cf5917bcdc0769b2af168267c18f9b420bf077dadd3140a221c83eee1a6e4d8fcaa78db4d55699df0a1d184167e8ee618fc7" },
                { "th", "1b3661fdf3e203629995f88a87f373ff88afa0c25530fe65210f4138fb888b5d7aa4c68d2ec77e649a1f30a64454fae69ccd1361b9869539c34faffcbaa40c46" },
                { "tl", "3c736ba5be2974c7eb967242b421854a5c23f46e516b4f33890d5cbb2be599f00a9481a4cfba815478e1541810b58ad1a73c9190821fe242141fc2bbe3351eb6" },
                { "tr", "182d022acdf51d45b1bdcf10c8fef9db009a9ba46ca06ecd7724c95d066a3790ebe5853111d5763d5593886a2f9dba6af9bc65698973e24aa85818a96c4f2e2d" },
                { "trs", "39ae7e4026dbcb92759a3f954575cb23eaf9ed667e299d567e6a63fbcd6bfcc30a758c418207c05b64e58342631f05d243ed15c83ae996f4e6380684b2aa3452" },
                { "uk", "0558fcc3af2794dc0cc92cd3ee0e34288bb84b9884b2dc9da33ae6d60d993c126e134e6f07fbedf44982b3c868274f2bc50a914cf4b59aec6db211a6e3564eb1" },
                { "ur", "38c518f67bcc668f706aea677432747bd20d13c394ef14c48bd99a9a4fe827ad351bcc7c0b7e6f6d1fd5bf491c65178e29829bedd8c98a61110787765deb4155" },
                { "uz", "1c781d17eda236a2cf082a66b1199f25071f975e11d9df48b587a996b51f66eff9bd560b0e0d80a833769ac47f44f7fbef60937ed7fd6c6e722409a56dc422f9" },
                { "vi", "9ec15f624e1827940522936ebae6f0b6a821abdf4726e3a79877cadaad6288cdf1d44825bd3c557bcbf271fcd3a96e30e42a237b65f94c9fab13cb871c97b1f4" },
                { "xh", "629419518d3708f7c636b8ed1e41d467c218ae14119f68dac014cb7338a9883b1d4ce9fd908ab74f58d55e0e9a19812613a9f09ac0c49c8b18a439294482729b" },
                { "zh-CN", "b6102d934d0df6dcd5d1ec806cd0aed23e982d70b2f2a6bce9efd4a67177709cdca66f08eecc81d386c4a570ddb0080aff670eda731ba8b8ee387136271463ab" },
                { "zh-TW", "84d1237671634f85ae5bf2fe7601d4a48d3ff7ff58b6ccc3232d2668a67316e765c0571fa042c73d6d7d6fd8bfb97f47ace481e18ff22cf610f0d98a6e8499dc" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/138.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "eb41aecbae09ec11ae42beb9697c2fa8700cd89fbcdc8f1ea93c4739fd124b4972f6b1bd1d1eee110a31a1cf3c71c8c4909a2aae22c422d59a8bfd96c13d00b8" },
                { "af", "4758b7c852aed006520015f3a0ee74f2398adb576301576be93fef6f5c84ffcafa3c5eea83824f82816268aa085dda6bdfc3e8c47ba47dc8b94f61b4ed0d6d0f" },
                { "an", "3b06593427c2213b794c7bd98eb2653d20f6d0f52a510cdaa886b1c4b82a27a09ccfcf5977b89722247ba4c4025ce57e820e8757426ffd383b4a5d44e5141646" },
                { "ar", "3e7529ffd2404bf46c7628e49bb869ede8c3f5b4a23676febf03e64a8a06a40785b793e994cea33e71da97ef72293fde26eec9efdbb4d12c7240d745a07ed085" },
                { "ast", "cc4c5951e036798fb16252a4d38dbebbf9cd2eeb434f7ef90db960520891b8535ce4a28c28cd6cb21bd33de041e8f750507ac4815a70c95cd1bd5ae1d7c1a4ac" },
                { "az", "3a80c0aa7c807f5ff87bb09b859a5309e9feb19394a2b25b3d1652d665dfbffd8d6778ab58aa60ba0e285a363382ea71c1f200b6b35d770544dcc37f98248e8c" },
                { "be", "984b80cac027ebf8eb7dc61498f992715146be6c63bb08de7abfbcf2eb8edc5ed045ff96e592658011d96f43c449868f2e6cf0830385f5b81ed3071d436ac708" },
                { "bg", "3f5795090efa7a1628978b48be053ad200f07ad5c54f9612edf3ef4323299359383ccf230460414e387299118f33b51212cf23f37332a2724e418029a77f6fec" },
                { "bn", "bb79e0a3430bbd806186211760e3518b2f949041631ece65bd43403611a6065e425ef7eb9e2bae1a33ce79c19bd752a31d256ea494877d41214f7557b5589fc5" },
                { "br", "63de3dac67a50256cdb81f10f815ed60115274cb19006509c29e0d528cdc81a6ca649bf2ac99be4552abec8794130423720bba9a78b777436002359790c1b380" },
                { "bs", "25e117bcf5a3e77db4a69c77fa1a243f569cbd765a65298f5bdc3087fddf7b954cbdff16bbd3638bfb0c3d21017596d343d506b66be03a85dfb96213f7066912" },
                { "ca", "bc790d8e0913e927d9f082fa6e5e4bacc5d0a34bcab5d4a6b3df3df7f6353accc040a9d0a9ac3471d29f870a67180ed36c17710a7203636e9851a2f9b9f93b93" },
                { "cak", "4c2f6aba64c3ab48a94f73c5c5aacba40b9b587420b9fe0bbff76802e09f7b00f7a75366b28b3b331c73bcf3d103206e769d48b887a8e9c22ea1e9069970506b" },
                { "cs", "08e8e5d8717a1b160e54896674bcf9c9faa729608e2bc378f3f196018fc69f5ff4527398c0810150e4151fa60952f6cb6cc90b77a29e912ea7d120d15815f534" },
                { "cy", "bae0edd05723c24c406f35955ae4975cfdf87d3fa7cd527e90150843a45b6b4d4cb07578a0a5a283323d0a3060889efd3aef9efa5ecbfc2feb7c3258f1062929" },
                { "da", "ab71c95d22e0c6e2c418acdb1cbccdae3fb52b61569a6c96702e92907b8bc15b443bb68728d86f908f6a92b59b79c8bfbf29bc1808407b307952175a64b63942" },
                { "de", "0e94a0b31c2e8726250a5708d526ee35d1aa822a97ed3bd0a8b5a58ce0fcae45907d702937d8929e37542933a1a769cfc772a5ad95390be0b9d967e3d25eebe9" },
                { "dsb", "673b27293c915fd45768919a967c2a56f5aa638ac122470266acf155eff7f080f205bdd6b5d317129b3000897de0c7afc82bbece79adde5a1806348085c24d1e" },
                { "el", "73d8692b27bffd06290e59d69ba68ca0f61f74f32060b534c148ecdbb4ffce80aaa74c618ac0c6f1ebbb4d12770c19be1f07a95a68d3872d483b9c7f325533a0" },
                { "en-CA", "a1484532dd884ca6c60692cbef2ad18d7f76eb66ff4fb3bb72a6866bcd7a44be44d63539f4d5040d63eefc4a1d2cf709a42571edbf0ad3c1544922b345f02629" },
                { "en-GB", "9b18a363c7d774b95422138fc965dbf0ca6f7349d3c2389616a199afa23f69f373bd67ae760ccf7241b59b7535470070d73dd4859fca2cdd207fcf85e178c927" },
                { "en-US", "ae4bf3cc1a83a767e644283f2163fc6b759ffe372eac3d00081d1c817785ef69d1e1be58985b2ec573f13a915abf9e269e731f1be366dc1e348c9bebc6fc9f10" },
                { "eo", "b71f01c0f110e1270b531223f610f0d98700c5864670ea022dde4ecd3c5ce16e277cd85df7327ee3ad65c59f38a37c3154d4ebf50cd55d566f82ea0316a69f88" },
                { "es-AR", "36f2c47f1c416dea829601208f0cca83a47594f0f163ac47582068c5291ecf2230319bc31836121d303fdc2304461dec48a8c556de9d4899f7a2f0041f160a56" },
                { "es-CL", "7d005643b5630e127ef2b73cf9a5b273edddee040508c37f1b570aac5683cbf70c38eb38f6a3a456b89f55a32309a3a1733416c707bf1241cf760d5fab89df23" },
                { "es-ES", "59254d5633748359444f654b8d3469fd0a8f506acf13b910230bbc2409336579aa70f21ac02efbe2a33334285292aa4b04f4e7b30f71e1d756b601c301f8202f" },
                { "es-MX", "5d869ef6103c7407be9f35b80525fc8f2eb29e62791834f9a1558350693a848560f7d540d7f01e16a2a0615cd34dab8164a5039f140877029e79924dccfa660c" },
                { "et", "1c658eb37dda4e34ae2f86ee74dc5d54a40b2a3d3be18844ad14e5c8eb9e36712cfbb859fe484e670103fa88f2a4e14edb79552517981d8ecce3b194d9533075" },
                { "eu", "dfd15fbd5a1bd251caf68c1cdc606240486b694269cf3ed86f980bfc2b2f069111bb6b7ad9284c1cc1f9a32f6f7b8286cf5f9123ba8db40bbc6622bdb8f21fa5" },
                { "fa", "08ebf13a69b7897f04e2d01e99f8a6359670899662ddfc2c5b114fc2f63ca243c1890a14d1fb9522068fd29fd02eebb903855eda18c4744dc8aaeeae856f13c0" },
                { "ff", "c86d50444d927187ec0b4192acc0031d5a736ef94f54b323ad8ca0fb2cd601011f9ddeff0784055284d5714e740588d1ea3cb3534da1aedf3de27b2c243a8578" },
                { "fi", "ed41979b40608710d346ac353481073a2b25bac53acc0f34c58f96a60839fa04924064347c788b3b50db15f670d85656ec946094d2ae06ab4a979e94f9ea5a2c" },
                { "fr", "2b81fba88d2db1d5035c881cb86c77058840ef698c3131fdc768be0e74697f34d9bc2dde107d541408af699766459922316c9c9465227e6607d47aa1c7a69244" },
                { "fur", "87e808fb7630e4a7576203df6dabc3f5554b1815ef153d03b51876664344d49259b7f7f24dc1993bd89926da7fd0902beab11e937667cac70c4b4da365681017" },
                { "fy-NL", "7ddf4063c6c20de49e3eb607252d2a618363219ee95250ac3a0a112c1e880aa1dd38a291ec031670e6e90bb0aea1e30faa40e8b01189c0101d9e991e67c0052d" },
                { "ga-IE", "228575d5f42a9b3983036b1b85ad701790b10f23cd276b7473be08a00f9635d2dabb5f4c4f1c683ff2bde35f69de1ea4d4d4421ae0a63b35169bda2738824647" },
                { "gd", "36fdd4787c721f4b6da95ec9b39f6c23416c4e1bc72e28e9e29cd479aa058836b8150d4543b89347acef908c09ae18c54bd6fc75b726f71c04609d3d769c3140" },
                { "gl", "80b3f8f738b59e75c955c62eece03ce2c455add364d5ce3324283da72cba49ba54d564d75cd3d1d66f69299a490af04b9da468ec55ea8b96d5b94d65bc607510" },
                { "gn", "3c0f332124924b14a19ea3b6222db0e2672290a8e9876f0a5b23411c34bc3d0aef40bb9170f1d535934d007c4db84694bc9e22e9a7715ea5e047726dd372383a" },
                { "gu-IN", "3872925c4f505d97225c075d97cfb3c5637e2919990d3ff77038092ca2c8bc978f72f0d672db8b1d3ca4bc89b9c208470ef79d0fe40d47506857afcfcbd102ea" },
                { "he", "c9d4c6800e78781210767f7779c13d0af636aa8e2b4cdd296607d5241da162278defdaf2bd97865dd4d5530761c4ba9fc7dfbb7dcc5728aae0f1375159c9bf7a" },
                { "hi-IN", "dd99894940b9a1875af7760936d2a41f03d4811f7092cc4ec68e3f5a49951d82eba38829f569c81f4b9bb896e9f4b45c4f3740d7e98905c8ccf457c799724a3e" },
                { "hr", "fd8732974391a713de08c0f07c99574f8e8a3dfc3015a318b6a7f364b7c91cd4a487e8818fdba537162638de46aaa8210a6268b8a5b096da43395e4bbfd6ce76" },
                { "hsb", "926c105447e9ec659f677a20a2b3a30ef17623dd5c9601f340b4d208df085f53ba09887510ce53dfc735c1ee203ef7fe52f6163f0cacb0fa81bbfbaab9fc0bce" },
                { "hu", "a58ce3406040d2d4a9ce8e3ebdb432c7155f75abb8e3f11fc60b6a2ccc8cb537150f100be347f77422bf5882077b732d424479785848df35f1b5b25fac439e43" },
                { "hy-AM", "9bd58e0909898f1465d35d9ebb081572684ddc2e94fc628cfa747e0d91e1daa213779338f98d49e1d59e0e57ac5d9c7f6f63fad255f2b455815bda8ffca384fe" },
                { "ia", "20f36bf6376b62e32da05aa2ba7abfcc2f5dc272d61a1cb2b15f00b9154f095d15ca56bb0a07aa89df338787183ce82f694f9abd0117eedee0ddc045a0ebbfc5" },
                { "id", "c180a51f493402078a423ee84a9b102c848ec4bc4a5421fb45b9bc1001cdff40492c501f92f7d4f0270d51fee5269518c555d506902e713d503413692959f3aa" },
                { "is", "4364eea3fe369e45a87aa8e1bdfc6ed19fcefadac4ef69303095874791421b80f2d5e5730f0d4d74351bba445ef47c1302bb3429594713ecdd34b06e60792e93" },
                { "it", "66654a87e333ec88396e824b15f00bcfe5564377498775aa1473a4639f202efaf031fe346ac93b06382d44e44b7f009bd20bd554b567e54ad26e7f25df77abd2" },
                { "ja", "e47853088d20ff86188b61622cf55950462b329e2eaca1c03015378264d0d2c6cf608f43819524660dbca6382239321135e5561be56f0f8026feb94edc225dda" },
                { "ka", "71d7433f5ba07af290ca8b74204e095f2afae193785b1fa6b4027a19f758fdafbfd668e6ecbf24a568d77742eaa591700b6fdf27514349706614ae076472396d" },
                { "kab", "0749f48b2ec402069e0193f09afea8ef7154df197329dfcd93922b2fa17fc97500876535c96bd9879f85ff1f96c98e94674197168a7052578d7335c61c7e31ea" },
                { "kk", "218b1ccb9cc66e0632fe40f891eacda2e9055d40d423199f43f58518b5e666e6dfca66b04f20a52f2074945094abe3917bed1aa4753e4ba0b64f9248cd0e8aea" },
                { "km", "90fd21fd46d1d3a268fa4d613d9a4101110ff2d342cc85787c27262f2f63a4e9df044db86268fd84197a2acf25405de898cfbb9c027be45e86a7053e97ded3cd" },
                { "kn", "4023f2a1a45378e3ac0a695f8744f4a8dc4fb88b10940318095a77fef259d3d9871dd972ca4d0a525c16cd26ed5f10ab6ce41992b1c8a5f8cb20769c17fa9a62" },
                { "ko", "3628a0ff5d7b30a0240f5d29f3e6c14ca4ce20790bde3bccd937cd625a3366ce77399577517dbd3cd53f7aa387ab1fd5689748124bad638a03f7c5fcc8709c8f" },
                { "lij", "94b12fd29a23fa3c118175e0dfa6be69b02f6db77dc5d3c1cd4b99d86c23489c704680003d18e14f55429ed997a2dcea3eafe8d94f0b8ead19899779bd7acbee" },
                { "lt", "59c8c54fa88c132d16d12f2f1fa04000181025b52a550feaf5e1c3de8568c56dd13b9511ecb6b8bd3ab9b3e24301095ecd4f6b70570e69b556ade1a76e19e346" },
                { "lv", "b5835f10cbe5d3a1e69e4189a2f90252a0356e4a0ddfb460f23939e52c6506ede744371850e90f12b6e3934e059e8125d46accbde6035686b1e9985f4ad8faa7" },
                { "mk", "2f93aa5db89ddc42f3741b27d3e877e87054906e9dfa11e2496231fcca493f4917125cfa0ef0a47cbaf196c9332970b23431e84bdba24a86dfdb20ed16d89d8d" },
                { "mr", "099d0b564adddd342e367def1f902a7aafbd1f4ff11be7eddea2dcfacb938bbcc8ce519503c792be8e5f0f3375d0782c9ca389d442ac8c038b38cc9a17e8a4de" },
                { "ms", "1fc2dbbc68507cf12b60482046096ccaf0e49fc91b4d47ad0010b1709fa9d5e4868e8347f3199471537c3bd0b1a1c7f1c68ce8296ba90f7aace6dfbbe2137483" },
                { "my", "21fd187fcf0efaf4ed44bab915bc99f6662daa33309acde93baf9a2f0a308c06cbc5443217a2ba70fcd494c9761b2cbe4b9035c4d500f7fc1c112140f295f42c" },
                { "nb-NO", "b1d530c9d575450669b666ac2d9aa39b37405d69eff53e5a040b32f5080c4b80ab7362034bfae15c8e93e87eb02efb728d3dd671eaa2ddf28193b03049917ca8" },
                { "ne-NP", "46bee8c32a90dcd83e3a39fdbe1f85dd065f4652e6e62d59f250b3da676fafd49eea3b3337d3cb1f5107c07fefe73c73c2bf91241aabf95e54fd7883d5d7867f" },
                { "nl", "c49ca86be58fc9b8c728aaa89b2d005226bb683106864d0c59621dadc664c888835671d3997b751f66f80f7478b196ca7c66aecd3b80ae2de85431c4e8da9e67" },
                { "nn-NO", "f7bf965cebfa1c9c7f9862b9f3820164b8d1f2de5de127aef7d843805e3096e13f088cc80b8a4da19297a8a4dd50bc32ad4920cdcf4d57f9f7468bd7730714de" },
                { "oc", "b04537517c09bdca540757ca19b0ad0a3747bbce75257f5754965a0e1dbb87705c9ebfd002eca27483db346531de3a413eba5388f064af2b7255bfca58557539" },
                { "pa-IN", "9b6d2024b13584982a86373fba34a0c9ac597c49a6fadcba4e97fd12a5e8b096cc07737941111ed7c1753daa49a0bf00f92c24bb2b910e63294991ced822d84d" },
                { "pl", "edf106ff48642dd0e9da505f2eda475df38bf82959d14733437019477fc48e72754dbded97dab691a47817f3263a92ceb6c4b0a34422b493a193a86f89fcdf89" },
                { "pt-BR", "5a59e755d409f5f4a3d72f282ae851ac4486e41fa5fb4078d9aa373e033ec020cad73c5bb424c7826ed8ac8e86b7192ac0e34c4f326f586259c1cc03c30cb4d2" },
                { "pt-PT", "9b552fb8d39a848eb8ecac9adc7fa3c2ba560b2bebe38d78145e3fad468f6301d694196c233587fc489b56d53b8654a3b29c1e9683670e8808cc154325bc8729" },
                { "rm", "bdfb31aa85f8744ca5592daad99ec0f679a56b80b02e9c57b11c4999a7dd9fadbf35e182b5b695e564f51ee7d42dde6df1e79ff4c7e4b24ee9f536bfdae93d54" },
                { "ro", "cad5373130a78a1f54ec576f08f44ee2941b11a179e55773a9dbb0b756939dcbc853e5dabf8f7b7dbe81bf3f20ec607a22adb0045b10bf0b8848e900cbb0d5f0" },
                { "ru", "42739e4a73f7f7e47f49e85bf5f08080323b8649c9734d1dd36f3aa9c7f6597faea046515b084932017ef39ba8b0209e5574682e38d202bbcccaaeed8c40fb63" },
                { "sat", "114971c46139b27ef744f0b12d8db9fae576b197ee5512a073824d0a532654a58511f0ab057d847a801840e7dbb6cff51fb7e154734793506498d442717edd93" },
                { "sc", "33ed332dbb4c3216796f0aa2d59b0b3b2848efff9de4a59d79b1e190f15308ca44c304808f2915c07b640a9210b98ca4e52b620ae6998e1db2786994058b12c4" },
                { "sco", "173f168bfaec4ebea037ab853a218dc3afedd833576ede2dac2ed1b431f90faa42b0c037b1f5094b7f02681ba71eac8db03560dc059f5d9805ad6d8ea56151b4" },
                { "si", "5aa3433ac971d5c128c69a220fabc558d680656a0c4048af17258590a5e2ea177fc4dde6aaacb7a124b003f71011b7f159b12851a27ce71343024c484e5ad498" },
                { "sk", "3338506c4f9efec468b3b00c52906074f65bca8d48b9e98968c4020939bb9503ddcaa7ac7176a267f79ce841b54408f83327043cfe91f5bb93ec7a046b756851" },
                { "skr", "17af6509601a03c249da4d6c652566ea058715fd8b4f3ef3bbba2c7335747a42d0234f45a16f37ae860e7c772fa84f76a0f9eb07faa2bdbba6ba4a76601b8655" },
                { "sl", "cce091c838b105d3de8c68c2506bc64d302c9815d0a0fe0c05ccd01363a2ff70d7c200ca37b94292ad9e2564810c95843599451bc062a3775cf71feeb14ea9c8" },
                { "son", "109aceca0a707044da1920d53d3df82154f33b59d4d877e8133aa999d93806be1c9a920224c495c3a319593fc11ffe7f261fa7fb6fc2ae30088adac8ff89bf6b" },
                { "sq", "4684918ddf5f478357dacead5a5fd3a36f3f66e09934829a19573753ba1e3c12532f794f3c798ec2631a0e08b0e6a3f63e126ac61ae05025e8f574f1d502af29" },
                { "sr", "1d3d81a39287599daedd5416540a67bf3ec686a9efd7c337cdc4bfa89f13779a91a6f2708ce6ab18d0835c56535849a776b6fa9f554ba3cbaf63d6f68c421e2b" },
                { "sv-SE", "222fe0314e4d4ad4937b9830eae3f3faad7952fde1682d3d4e2273ab68ff9aee6fb5fc338791f2b4b18113256c2179d9dc6ff50721dfefe338719c781f5fce11" },
                { "szl", "63f117985ff5cc9304a7b0234fab5685156a4ca679f11a26cf85c4062450751ae79e73e2e5d1f429252020b72cd237dc4d1eaab2040af449a40d32ab8281f37f" },
                { "ta", "eb4e332e5123401ae4d29cbc2d65dfda4dba214379cbaab0ed9a0dab715206714710b04dceff01a8f52694c28964a53e2db555efae9e4f8c1b20d2abad940fd6" },
                { "te", "c0d1d47bfa9e723364ce07e2ae12c1fbddde95064cfb9e0a4411b79fe1ac63cf19abfc2fdfd504b4a44b7d1979dc1c902ac01e61dbafbaef9b2329ad04a03ca8" },
                { "tg", "e4f823e609cba79a5f17338f7c082262a04251d76f7c2dd59ec34a9b908810878917cbe8fb4e9f1881dbd8169798f3639ef8792efba41a7a6956a999e2285203" },
                { "th", "1da774ad8da1e03067380be2f008b2934e335e325ce5e39c9fd4b9f33eb4b2eb8b7158050381ad681666667971383931b10800b67c289b5b6dec9abbb62991a0" },
                { "tl", "9842c61a8c9e1b3c966ed2444e4be99574135ea13cbebdcd99f419929d7f1c12073bd5d819e3c50b214b5444f09b2116b12481ec9f86dbfb3c97e96daf279326" },
                { "tr", "ba1e9b67e696dd1bbc52ed13e7ae781d71c6fc2e90043ec56efdd8d4f44bd5621780cafb0af148aa67175803d6248cb7abe9a3cff538da5aa2b48a22eec45faa" },
                { "trs", "13b8af9b7ec4612cc6caa18bcdde09bffa4362cc942b800689db48ed9d3406a7097013067fcb03626aa1693df2791158167e04090e38a7196c0d7974ee8f897f" },
                { "uk", "5e3a1ca55783dfa19d661a1a31e4c0c6376162213fc5bf6dc2f4d4bb9d390d0219e76f57794085a69cf3dbcdc64e04bfcdd3d0da45747a52a9c09a48b9a162ac" },
                { "ur", "285e3b64d12cee798e28ffcfd136983b8706b68720fa52ffa4987c69f4541414818b24f18f2dce455780a4bda40ef1dd6a69a505da572b96b29bb7be5ce7b9e9" },
                { "uz", "3c21ffe7a32a4d07eaba1102fb790a5fe395993bf034998dc362d8aad3378b852224cde3df55bb656ff1c2c1116430fdd6917aca03918f9288423e3f5983bf36" },
                { "vi", "b279a33f24fba459bb3d0abb3d9515848500564a86f2e56e2638078237696ffdc90dd20a4f569c195761124ef8ba47e8b032f38cffc643c4ced74642f4615baa" },
                { "xh", "12876f8248b428882f070d2b31bafb0c4c9477ba6e91846f67bd2e8da262c1d203a895cc7b958b015bb17442711e2da5daf3525ee35bbc2f21435ac162f1ad04" },
                { "zh-CN", "50c6796c3629cefc6c369d3992dcc262d9d369cc5b70ef7fb64e6e62520bb25d98d1e7b0b440d208de61e28ff57f7572804ca8e041a5a2eb4d7da81903728733" },
                { "zh-TW", "ffcff17db230e1236db9f48df329048cab53b2d4b1cce9e65e0257c75bb1414ed016d183c28ea5dd9d44274926ff822f622fc4bc0e428f81ab41bbf3941cca28" }
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
