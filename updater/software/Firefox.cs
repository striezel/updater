﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
            // https://ftp.mozilla.org/pub/firefox/releases/138.0.4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "f794a5e18a375c79f83dd3e2699e04162356367f7ed01d5a4afd8b774e19b42937cef051fbd8843e9df23ef7d1a3c099509810e0c32b273e88059ed9a85b7f8e" },
                { "af", "fb15564c898aae9a434fdd4546d2d7572461e6e76c35c53b2041163d0164fd37baea26d99c037c62b96f9e11587b13c6d516236a9f9776e239232103b8d31894" },
                { "an", "7bbab29515e8accde41c4765791d7ba218e3665106e7ec473ed56540c400a98f1108d456b2514ede2532ebb80d533e984ea9ff57d5e875f5e21bec650c253382" },
                { "ar", "756b2e48a4a3c1b968aa6c3cde011c89a51c7476fdc479c8b462f31a502b78f8668b52b959368c75d1c5ba4cd9c83f605d79e0b19f1d3ba798e47fead6e0fe3c" },
                { "ast", "a90c44767ccd710751a4f739875ce5bd0623570755d78b83792a3666aa3a45b4c56596352f002ed3f5ba3bfbb8ea8a5ba57822d4137d3f2180a0986d2a321396" },
                { "az", "30940a5197b3190fedcfc8a56418a4fd0473f1472ce0ee4dfac8a035973e65b6c9e2e00e3d8be69df43152f644e84ab05264e3fbd99256b269c816fea4cf6f2e" },
                { "be", "2035409810fdfa2e73f28639a4df3687be2c3a6475dc307c568af448b0e5805f5d6ca79372c8bae00eaa2f9ec4b1c3781ff40229c3870ad129de66ae5a11c84d" },
                { "bg", "045a3cc0ab46958678dd30c9a312f2ce80150bf516938a0a79a4df71a209c7bda92b1fd6d6a84f2753825c7bc7e4e166e23918b026cd80e8ab29f3b9884a4885" },
                { "bn", "37f256881fcbc34d2b962dae2afca9996c67155d7cb51e142db9ef0086c2a209339e63c007564b2a9929fd5e3c90abfdf4abb17b20c696627d82e0e0a2d87293" },
                { "br", "0379f145af1b43cb3c42ca729ee1062110cfb0a8685e6477301706f0ed7c51ed5e1b31322c5505173a16579c0ef07f268ec14cc2ef51bfae07a479fe60e8ebf3" },
                { "bs", "9eb77064fe09bd34b89104b915a048e16da8b0088f4671556706804cc31009a97e05dc125922f5bc950cc037ac6d1bab6dfcbf883778fad2ff7159af072aa8af" },
                { "ca", "245c26bd686b0068deedecafd38ea560680f85422b280d758f9a2811c1073de67e81f550f129189793a6459eb57565b954780ae9f6d4a5c993b6c708cd9d27d5" },
                { "cak", "8520f5eb6c04403d8693d13fa7ec30d4de35f2a787782038a16dd4e5e6959451ff29fcd1013827d40b84dc33edd292e2a16c06b8a37da7baaaaca413eed383db" },
                { "cs", "496ad7f55c4b7430754511d6f019e17ff6435ee974482c7732c531f8f286acb4646559f85c90d88b76f26f5f6f67de8480c9fe7870792ac747096f492454c15c" },
                { "cy", "6a3213c13bb28f652196732b5fd39def205c4fa77b5429c4bd068ef81498b5d33e5f44d4aeeee6ef7c70971ba0b08266110fd3d3241020c63d2dade1a0fad0ad" },
                { "da", "c17c68f26a1872fc22527b7b582d7aeaacdd43a22d8b9026da6a195e8eb6a397c8430f37c6ee3a45de16fb1d3d2852e2ffeb4f3f912f79685d4a6a9398cb2b50" },
                { "de", "78c15b53915984ac5e987ea2193d21eda46882adf61e246035b5dfcff7f2b807bb22396eb4482d70a9c23189807f4e67ded6a440357918ebcb17884aa42d970a" },
                { "dsb", "15a6aebd5cad7f3abb9cc3bad85fbb43a1cc3f40923862f6116000438c678c5425ac0142a30f02fcbd34917611e7a4b18c399fcb8c5e1513c489a072641ddc4f" },
                { "el", "d524e1da81f5d26c096ef5520c46fe89ad5b05a993c27ec4494a9c3996473f50d7f4bc4b3845850a924f1cbc4def4f63e75abbe2d5103bcc99945c1e5985bb6f" },
                { "en-CA", "8e8fd2e059642baa181d8b466fcab9f731d1a8c88dfafd1e940e0ea7b238ca61d99177dd398c3acddad6742e29a0c29d3b5af34bde1c7b36e5d78b738a4b07c7" },
                { "en-GB", "b69938f2c1e21f6963e45b1717305c033430b06425395569750259dbf3099830f7264eea79840369b92c671cdae6c3e54bc6ac94b5a047aaf0f3198808fbf244" },
                { "en-US", "e08298f63ec9c8777d20134cb5fa5ddfbe46d7ea209d3908236eb10d77493c1c46a994b878aa1e0f09177c22f01047bb0c83194f2b001a804bba97773a69127f" },
                { "eo", "054ef76b610d8d32c979ebc8aeb1911b6905a0c71f93df71a9f32dc63b183f2e58c46973a036b78aed630dd5bc776ed25177d4b92a924d4e2f303b5aa846ca2c" },
                { "es-AR", "fce969e3d4d1a8261de6c1a0c2835fa48207cb7a84f2fe5914846363db752ab61d3023d108e41795d53c8421467f4de617c4693868b3741d327ea3c86e4ffcd7" },
                { "es-CL", "4180cdccc18a260b23c6a4cfb11b41abc9cf64a1c94cac0576162aec17b06fc49a05a8b8aa91877f37d37e7f1fa480e781aa4b45347f013de941d68be3a64060" },
                { "es-ES", "d3591ace2ac85d729414b77cb7a302cdd775e6d3f445d4e5c462067223d7cfe429ca41a48e5385d8451a505b820119c5bbe61d23f0b92c77f3d05d8cd6562090" },
                { "es-MX", "a549cc6ae312b2bc14ee896d04c6a68e293e775fe285512a1ec871ead4df9cd4b5e068738fa9a8b8003877aa290ab4c90940d2dde59a44a64e270db00f0d3757" },
                { "et", "a7cc95b656e9e09308a72603a480f24a2d3a47ae9f3d8a218e142be01f2d48e0ef1d288803f13827dd277c281d4e28768f0b73e09d7d6f7e305729aa3b52a28e" },
                { "eu", "0a0e3eaa6221585610e1de4e5502b78cb54f5d45843832764d27f570689e0dd94a0aa41dd04acdb4125535aba88b14ee297ad88bdcb6cbf148ccfc3b96585ed2" },
                { "fa", "50fcd665fa7022bcd8747c18f8e01336519733ac02beccd8984b8e62bf70896e53d782e97bd8e6b99aad76a779ec89851353930c60e2e1d61a848d3927c04f2d" },
                { "ff", "27df36e91f028e56855b6ca54fe3f5c4ba4debc2265f76bafb5f056a70895734b0beb386f86b3a48c2e1bb2c3fc8dc34dd670bfd016413c2cf33458d4250980d" },
                { "fi", "5b0bfabc73ed3b8c7bbf13665b4851fa92a413ce32147bca66e60c5fd110fb04f6c18870367ca9a93eb8184b41b12928cc28169ca199772c8297c3f8e343da0c" },
                { "fr", "3dd02861cce8b51b014f320ba211acdf771f52283752b1373810c027738f261070c4256b92c60a351e5139b8554083f981fb2e119596fc57b52b7eb673a3bd95" },
                { "fur", "ac2cdf2bc9a5f635baf627ba2dd2a87b154f8c88171e387c0f88ef69ec1bf1e7fa9b5180fbce035bbbbd8e4c7ddbecf541d1c02b6eb053fecffb944e7068a98e" },
                { "fy-NL", "e735a8f3ab254ce83a8dbf1f5b54b00d472bde6148b30a0a6b8470caefe2a7479918550cf9165bd810ee63808f6bcf4a5d32040cfd252009ba1dd434d80b2504" },
                { "ga-IE", "09960aeb957611cfc1a2ae8faa3a7748ba9346ef7ad38c2136521d1392ae5f8b815331c42dc8ddb3e357c4be578f4250d54817b22d60ebeba63532cb552b050c" },
                { "gd", "2f6990f82f0a33fc25297544ed605c6afc4a177d26274285c9f6c39712b47b88faad39db716a7f8fd414566da92013e96a4b45ad9df84234718d19a4a6e9caaf" },
                { "gl", "072ecbaded6799ec483023b5a2668750e02becd5daa0a46e9928a4c7727e77dd78de10df7a4da45a69a14ef479f2c0d8a80fbdda208343e58a0e8c9926fb7ce2" },
                { "gn", "a7ecca259b72ab9c91d33ee6f982557c95ada542fed00b45a4bab614bd9460d1611c2f1f81c6e9aabddf8b5143a651fb7f60b54d557fcbafb6d4277568ac500c" },
                { "gu-IN", "d244c0fe353aa7deca89ca7eb4465f2b912b7b008b9221fdf52cf2488d6f06631a4f6b94f02e3e9db575d14637333d640e42e36704788e21a16cd02cd6d2cb21" },
                { "he", "d777fba73524bbc9c6c294af3d4d8f26ab1662e31368b305eb1fbf8a895dc5a05e9651a4688d0ac78c6f76d7d9105dce074a4f5bb4067503594695dc3a3350be" },
                { "hi-IN", "a188edf4c286527660fd12223b02bd7dfaebeda68e082c24a571f265325540e72b02e51ce4604d43fa8f629bf206eb70a47887e7c3eb5146510ee9560dca8344" },
                { "hr", "2901dec0c5e92b5f90639259a55baff8a86606dd5ed99114bc05176f6937716ffcf0a1e7acadac9ebac7f07299911f3a355bd2e4926144c9d131e4deb03c9092" },
                { "hsb", "0fe08d0a951287d5cf1f1336bae511125ac2e948409d237f810110acb013c547808a9680e99d7e3134a480ec2d810850b0937e5f322a7f268087cbb05d6196a2" },
                { "hu", "3b180e81ce87dbe6e88a0ab9f26b8e1e5cce8dcf352953134a60bc4c9dfdfc2e9c367b96b709dadeb887753858d6f96bd6f09df1f2caf73948b553f6cf41cfec" },
                { "hy-AM", "353737424015fbc1ef95d9760227e36375dc6dc78af896151f9b0f474236f0543e033dcd30e41fbf8930be4757b61973983d36aa66ac5d9a91b21b5a84227885" },
                { "ia", "731f42729bde403219c9d9c848a9befdee2d32b7df010edb2663662a022b8d9fd4746bfd50ef66aece6db182f36bc5299a40be534313bf4adf7bbda62971ac6a" },
                { "id", "48746b58aa5a71c81c9d72f689b7d8a3b2698dee5b6ef3e456c9482607df0b6637c84c5fbdf9bc44d2128dd03dcbdb409c77a310caef9749f37775c6e1ee5b94" },
                { "is", "dacf39d3027b6eadd3799f6f4098a9a3b1e994384f9b6224d0beb3d8e8cf272c17659dacd9cd0cece5a41ccb7c10ade42b674316b7e7aa1487a9624d8b394610" },
                { "it", "9dd0678646666841adbacb6724e4fe2cd2842da5274ad3f1a2758716d0d313a391f6bfff97c2c7a2a6c0135fc74c507f6661ac34a4b0dbef81ff338f937ccde3" },
                { "ja", "5541a1509fbdf31f94c01e2bbf9e7dbca92817e19f63b0914989373880e10df388f36c4c7f870b1426ed6712a05b6d4979ca88f7e7226593e44866fe31422d47" },
                { "ka", "b552b96770069afe4aee9fe017d5812f8fea4f9432d88adf5c90ea37a91c2b4b94e9f3bbdb3763661148a23496cd959bab7e62b83bb45250f415217f964da74a" },
                { "kab", "d0644611f3e1fd396b79bafa86829172b9cfff6f8a38f6b5643a124506860f7a27e3c1b65ad49df98a2da910a803ccb3ca1f5f29b6b0cbd1c3c8493e74069bb3" },
                { "kk", "6161e1f0cf868488c3eee8fb2a11bb2e0279ac96a8dfbec74e461b6ed252c6106df5423066f0314adb055b7ecae7e4c7b51326eaea3ba235fc05e71f5e615dcd" },
                { "km", "fe2aa8e6b83b90c06f9c593b36e88aca43b0faa6d5d289037c7a9b7a85af3e237f0b4b7efb6baedb80602ff9844230cc9446e55b287f56a822882e338e54717b" },
                { "kn", "86d2c1aeb27e34324808ced91a1eb8bc268d83bf4cf64fd6b2208b8071bde6c33b4fcb91cff204322805bf787de1b7124325257feae6388e62c916d6ebc00a8f" },
                { "ko", "f9d6ca5b2749528ce3b88b32abfa50e1266b262735fe6afee6d769aa735af38328246dd855c3bef42b25d994f9cdcff67f7faf1abffd19769e437c427bb881ad" },
                { "lij", "3abe5b3a952c41a187ed2da911a9a9169cbea2b98a1a0ba60e7d24f3658501064ef7013dd7854f29c43438de3596958a2334467e73d024f0858ef9e7e57c331f" },
                { "lt", "174a2fb0349ee23982e935f8d47d49ede27206eaf54043a3eeb383a4be873cbda11dfe11f050ed31091c1c6f223c0bc2cd7461af05308b3f87f476645fd6750f" },
                { "lv", "6e5e4300278f26a69015e49dbdd98efb5ecba9f268b37004cfecf610ae6a1f46a380a6b0c5e280d5cf2d7cd915716a62d4b988889c57eb409fed3a76dff62fe1" },
                { "mk", "32263a8eca8f84aa35991c7d5f2229ec73062fef2db9842c532de4c78d25aa5627c89001afdf1158c6973d1936938b7b18ce6e7f42ec2412637c8df554130823" },
                { "mr", "733707c0d9f9cc44bf49aabce5a18d1d3cc5f502d2106841a3ff4ef85aca71da2d3792a34f5990251e8dff6230d63f160a44cfbd07d31301576c872aff4d1cf1" },
                { "ms", "31f46a376072871d53f6d330214bcb26fd92f716cbdc95a6e267ab2ab74ff6fb030eeb33284a31395711a54c6dedd7d592fbc11f81358e905a8979f75e07f63f" },
                { "my", "d674bed5991e55064214feb9190bf6afd7ba6df8a19e908ceb719b54d82d71a8fa7888b02dcd17638f628e8249660cded2da573330f6c9ff23f71bb69e06f421" },
                { "nb-NO", "8403ce905710c0814bd3e0ac80370e47f2d9b772e39d45a4d33e89545acf94a6219563d1bdc46d0f40bf87a47475a78f9492ccc430496aed0c4e71964994b3f4" },
                { "ne-NP", "e06b66c5a95558c5763fe6592fec93e487c88bda2428a31d8490efb14eb33b57d8ad68f6a12381a7874000d395f287d11cbce814870851eb54e1b86b978a0681" },
                { "nl", "72b18ddfe498b33fe6080dabb09df757f1c0541341c32a640826dd34a6342166dea4b0616deb14894e8ee1c791d261cd9ae4d29dad50698ddcfe7ad398cc2a40" },
                { "nn-NO", "f75afdb499e8bcd6209eaeaf20962033d1e7078b14d53b71941caa085c6a36dcf8e32861591ff904a2f9d58dbecc54edf92210d18a8ad709fb52a625f9559bdb" },
                { "oc", "b4b3c8302aa4c599f06fabd0b1b39be341e8134a0a0df36cf402f1c4358b789cf5c63ed2b338007d93b11e47a8ff079ddc0f74d50cda0c699fd826f6b8eb08be" },
                { "pa-IN", "aec8577bf8091638ec8961d5404471299cbd6794b6c341e8b752fd6c2fcb9f2cff50f9f6a08e33cd648268835d84d76a2f920f68dd60639b7c795d577c50f309" },
                { "pl", "a850495c37b9cdd760737db6dab145a703f63df20453ca9d2c02be8da630f437e5ef1a1bf166622f028ef92c8b51856272c99efbf2f09ab89473d37bd0a94f52" },
                { "pt-BR", "fdc1865fd179d2b6a9151de4a9a1377dafb66962cc6d82df96c9ee6bc67e21339c316bff81d76cfd7f1833e0bd90cb2437dee9b43b035513ec08f5e7b24eea4e" },
                { "pt-PT", "cbd01a500f28f729414c67fe8c7d2a368d680601eee4c145f14970d552d4a330f2c800b99ac03fe1387be4dbace51219ae20fc3fee656e82eed9445224a69de1" },
                { "rm", "01eb050366cb936dc7d191ca336d9eb628397242961f4c256961e285c7c889205409e712b0101d7ef778e5a5cd5f348195c815f9032d7f14bbe6909b4080e26b" },
                { "ro", "8439f3a7ba97ca69f2c971dec3af5b233ba95844a07b6da9bc208715bf56e5382a357d20dd88438d417176c98ddc5c730cce7286321b87e87d90d3324ff00c7d" },
                { "ru", "ca497d8023a894cbd2cabdb4d0eaaf1fb35fd0797d98900a16f9175d1015af1171632ebff85b60d5f1eaf7145c91a962aef914f22af846ee3f88a2a2b3ee01ca" },
                { "sat", "3200b67dd3ea2e5e1f46d5f08bc3f09be61af34b52079ea6828c25cb0d17dfcd86319b3687ce8f405a5e2449cf7642326136d882137f19efabbf6099ee557358" },
                { "sc", "d9eca11be3dbf1440e41216ab231f7f9149040e5046bf67b0180773e1243ab807aa720fc9c7a241b2232fe279d8dfb856937153f01194dbfc943b6109ea9c5c8" },
                { "sco", "2270ef2ee88adb2b29178221e0d0dab11d4843ba3587d7721b1ad6323544bf8b2e0cce635d80105e5b176de57e3e912ee8ffd5fc3b171a61cabd479262ced001" },
                { "si", "7bc7a07e118d7a2e020fe5fc510dd992f4d170ae508598ab2f053c1c25eb74f19313000eb272f31f606c0ecc6dc292fedd501e126e3f1a5155c3f303d250f731" },
                { "sk", "a9dfdbff8646c1225466ab36f99137c568bd89e999f39a5723941fb5490fe862eef6db3e77808bd78ef3839db285380da457f12f4f558f8b209329780c640bee" },
                { "skr", "430509d57968214979e095da2d5afc93bb40a1fc0308ae38d94c9231fa56fc08c899f72aaef4b548999c2814b0903ceb247472c22c25cbcea61fceada5aba075" },
                { "sl", "3aa05d46eb1f61a008a1c98f25e0d473206f0acad7265d466796314e2fb126b886256f95c2a1df674798f985f9fb83df7580bd525749b86c0fa0f7f06bebfc7f" },
                { "son", "9c57714752b96fc9391e7acab3d1f8d385c36dbeda8bf6a18b6b041816530ab2f7d450868d0593ae3a6abccdd7eb257c7a13292667d54dd49ff90921efca15a1" },
                { "sq", "44e5c14913cfda034478a82314952cc68a9a40b1466a54b5d9a0a79e84c5d883cc120e2506bf4f819491da651bec79edfda74365edb56f46447b85b5e8da09e8" },
                { "sr", "64463f0203462a70b65eb38f294c09f7a2de2795cbe346d7c86230cfbd644f8d38f2cb3ec14bfda33b942cd5922248f0855b4f28dbea9d63189333563c18547a" },
                { "sv-SE", "d57d6d343b497f5f90c1627e9f48b193ea662d0a1b066f78b3463123c07952ae34dd584d9b124b9b36122f3de5e67e65eefdacf65b2f5def639ad2c48d6a240f" },
                { "szl", "68c3ca015b4d821ff9849fbec78a25b95ed9817837eb22ef93b73005ced6c2cf54db50853c594dea340d6b7da3787df4652f54bb40ac9b1d98087dbe3765a852" },
                { "ta", "61c6ba8c2560f1e7b6bb1ae56a6f16b18880c1bc96fab256c8f1f2b86f87ce003d0ed85098ea973071dcebc36935dadeb29731911809e72f4edc95506e8ce75d" },
                { "te", "880059e730e6a886254bda94f95ec3ddeb8a1901199fecdc605030e7415ec488f3295c7aea749547870529c64b1988a2ebb4986a25381ddddeba8a8bce65803b" },
                { "tg", "1b4537c19d6ee0de22bf5ab4c5909a6834ac7da62ee51173f65d78266bf1c30cc119ed4ca94065e28b1a853837cbcadea0f9c0e039297c5afa3d232f276efa28" },
                { "th", "e850f6f713f9cf22ed1c38845dcbea592e13647cdd607485729130e810d7d036d8a06e16fb1b8abf537f08a096aa6081ad1779a0fcbbdb37d0898690f19580f1" },
                { "tl", "ee4f5ea12c686c5556f1fe62a4d8f37eb8f70d68ec9dceafdeece2380e51c9671012df280468dbfad802c4125d4bfdcb088fe853dc7c857f275a8a977ac78c74" },
                { "tr", "939b706cad2bb1b1d199a201c27fdb59e6562c131ab74df8c183f779a2fc51c3a23bf96317829ba300ce8a2a103e2ee0ef8fc74c6d934a7be52f73690730e1dc" },
                { "trs", "90be4d370f53a00315ef8ceb0b7a6836253403094013d7590aee704f3271113e87ceb59c1686aff6ff92a19253a7e30d891750912ebb152064209304fdd1c9f3" },
                { "uk", "20fd9569eb7ebb675d5c307abce3ce578cf9d7ebd97039005f23bcc08d0402d8c3d2b26c0e4136d3ac0a5ef123159cabf389aac83437064691a2e9223d307850" },
                { "ur", "39040fdf144607d0bd3e4af1690cfc4dc4e32bff6fa584433349056b64ea23deabbe447dd399f79cf6f5fceeb31e6dc35fc86c54e0d9889b75013d843ec49168" },
                { "uz", "a2fcaf821a6b34d9b3f87166183cbad0e3d75d8b8e61f973f26a271615373a8fb88c2811a1a9340e1b7a8a648feef992c36a0b15fac1a2ea319dbaf056d3fb5f" },
                { "vi", "8d25e34d7389f452e34b9feb7521870ec0634214a99acd5bc7a88777cb0b4ee801ac65785d85577387ed2a05bd5dc43822a83ec6f3a388ea3981f786952bf81d" },
                { "xh", "4f0483832cbbc6fd1ab8c8d0c9822eb55eee8e505de06d94aab446a8b501111e130f9131b99dd1083b91b9928c3080fb39ad9b564bec7ddd29e4879e98c1349c" },
                { "zh-CN", "fd30b36719962ab0eebf9f3a5a1f28a54b12f35db817d26ed3804ce98dff24513b8196d36f99bec05ff4136abe3ff440018013ca7595783c09b8ae7b77607580" },
                { "zh-TW", "330b9d0ee13c91ecc9274352d197aa12379be33e7478c36c5afa87d6412fb8e54423c95faaa3b2692a3100b3d58c61c7f9168ce30cd762982474b460caea75e7" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/138.0.4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "88763625db98ec7e2ebaf199113de2f62f7c1056b65f91146455baeb5482cc6a59b5064ae8802d5d6a1d30f39fb3283386251ef4e6d9c9fad685ed8d43f7f187" },
                { "af", "de9b568663574e577e8b0f1299635fccd1def2491d29439abeca3c97ca701b043180cbe025eb8ce3d7670c54c8651babe4c7f31ce8cbc1473cb8a918d39fe6fe" },
                { "an", "7926d04449106b33d4894dcdf3fab05189b9ce9cedd68ce5656db087f74e20e2aa077175623fd09a1eaa781bc698a27dcad1619e4a8ffd60418b4e00098629ff" },
                { "ar", "a80168fc54109bab08c4894fa53c94f9d1b282f7b36ea0c45418f9a0d36839f5d529d8fdc6f980077a7811ed52d08b237d1c5c23d9d1389640fc7aed601b5930" },
                { "ast", "438adffa08f3c73e68ae8e03a3f2612611a451d37f6f973ab83916f06e89fc377772c4dbbfb76b89ac921141602378546dd086d1e5264c829d4515742f713c27" },
                { "az", "fa64059da82a232377f52ae35caad249655b4ae573dfec99f41b2efbf2a50dc9ada93bd2df693dd2bff1d8711f986bae7f8a7c621e0dc38798294389b29d1db9" },
                { "be", "b1ee91c301de7ccf0ffa1bbcc847d1148731fabc71e95048cf4d51e0cb644c0082ac769ae7d88c011a02a7fc6bf608c5ab075b9ace132517fc4d4945b7641ba8" },
                { "bg", "ea83c6ec9ba65e7abe31b5d5f7fef23b0f98339ee22bfed2b873e5c6f2e9f1ac560139a7c2ef122ab7c63dc3dba0a0da32ade85e2b14656159aacc55507fce9e" },
                { "bn", "22e2487dfa7981f16ea51fc2d4796a8058237096fd37ff17a806dd5e85169c4ebe5c23b0f8c4cc26fd356f7b5ae64f2c950aa055c1e2e7ac5ee14926acbb21be" },
                { "br", "6b56fa31d3a267aaafd98a7d349623ea22e853fb92247f275d943d9fd9e0be660400a765429dd1623a0d27d73aa4dd159b2f89c992d9f3a26f5376a09f43ff54" },
                { "bs", "8c661ff79fd544815c58933ba82f128e73bacf13813fbd5c71fbc73cb80a609f8626fab732aa03e11cf59a37e228f493f8f18ffa2cbe51b0377266960e41065e" },
                { "ca", "487a70b472ff6e67d25ed78088bd189a67bf1ca265704bd50cf523dd4f6082c9580c179b870efc64e8e661e9209826468aebf917c08bfc65e2da44de443dd302" },
                { "cak", "0b49c831621af618d5b0379b6718049f7b092a5a229efcc96e92f7d005585092e162c48bbe44742013a7a221abe9d2492eae8c840240a6ef52d1d41290d4284c" },
                { "cs", "76eeffb1b5ad2e3db70cd28031997366e4cb3421d431d56e90d092f0c65db8c941711df43aae1cebcbd851b72d191c9e0319e23d0c374de0fe1af621c6af1599" },
                { "cy", "de3ec7dae1534417b8555e91e10ac2c4cd0750ce4a324fd1c6b580fb6bb5a49ba6d46ac0f884e8a1da5ee9d3a5196b61894611b48d17c0e82551bf1b57aa4d23" },
                { "da", "768e6baeca985a68023f60a2b21cf6e889af69346dea9203f33087027a09f93a8339dfc6e0476db0ce52cfc9aafd79498584de8a6de6d905982757e3501da40b" },
                { "de", "0dc5271d969d501d79ed048d9a2177407d3ddd107472e694d1ececca2146cffeaa279578561aaaf3c459fa7553611f65741cbccda8f80411bd55e7aeb446f7ab" },
                { "dsb", "ac69b8fcc499352e089bf553f6efb724a401ebaf3b300b4e36e3ce3d018c2ce50288d9550f9d8b67a9d6ab62970d8877281828932e72abbd784298b3b69fd625" },
                { "el", "0099342bf77cf988f0d1318c22e97b8edc9d9f159c01c333410e95584a2ace0eb838b7e5daeaf88ddb817a6854cf2e271ebb859440377ac1e696b2e47626bf36" },
                { "en-CA", "31f50bd628b8e36560593efd0d875cc141a62ba13368a7b76c7ca5bb2f4835a3410dc5169609f5ed90c39726f86660c4f0feba8262d11b7a96a7edbcb37ed1ee" },
                { "en-GB", "2d1d930b5bbba3cee8af83b9259f73a816e8ecd23305f33bc35d8efe30f6d31b1a402874e429c91d32f02eddcb82d94fe98c5b166264343eb0af93cd4fd28147" },
                { "en-US", "4fdc0965467f0fbac031195dc7292663ed1a3fb08dbaf733a17d0c2a2ef4eb9e540e6516bc7aee439840a3e220708d84670177945d598cd9ac1aa79c41c061e0" },
                { "eo", "a474a224a91a54d3ab18d1c5088636a99bb07dc3d8709cd970a7785bd309d3aef1b82b05d409f4b535f08b41d1caf1502540bbcb7c275cec7861b47ff7dafce4" },
                { "es-AR", "56bbf4950ecc2259946d37c13525a811741e8eefc28faa4918b89b68097672ebefb6b59fc18ed7b368afe8ef0e9839239b724b33ee05abfdd730829d1a649414" },
                { "es-CL", "f332c8c0cdb0c94f6a75d5db0df772831b0dc99cfc93ff002c382f9af4c14e15299ab0c0d9e950d29b1b106c621ec41d7ed97e140fce732437fd56a6bb941c72" },
                { "es-ES", "b85e21c60207c0b86e915eb7dfe3222925bbd43ef53066c2d9a82b385d971d0c9056cb1fddaaa9ae56798ce25a0355c0cb49bfe8ce2649d4eca34e38de3ef87d" },
                { "es-MX", "07c04cb7d8f0742efb87fb2860fb9645cbcb2b2a8780a3bdcc9376f4e3479e182a1f1667ac0ee6bbb2225435f86e51b5ecf98145bbfbb9ca50fb0f8d3e759c56" },
                { "et", "96a538bf9eb80c2ea4ca4c3280980f1529739efccc696b595c2c561284cc8bd263004de9ba63b7428e46604e6028ce7d4982b7b61892df8f88d02ec3371d192b" },
                { "eu", "6f3842fe5561dd14deff542eaaee0e0545b391de11d41ab725e76372237fd5d0e35306e439a5033bc93e0d3266f8884323c4b99853483e127fb4ac9aa1a86533" },
                { "fa", "df3f830306fe4549f9fda0d7b1a6176f6f3e9201ac46ba357c2c6a9099f786860c4f598d237c3d1d4240c2563dc66dd979aa49d6a199a769c13ada7e55387b95" },
                { "ff", "164dd5c0d4dc9f1188a0d16748c64e51adbc51a05465a55d55d6dda95f33b22cc2c9e0064e002b3130743c60e5d3f1e2f7cdb746d5ee18e90fbf460cd6e28913" },
                { "fi", "9aba5a142e900006af4f45d82edbc17447a1a53b5f9b93fe06e57aa9623bf05ea722681b4b0a06d8f78937d5ec205d9d783dde8c5492d56abb5b8b1d263a23bb" },
                { "fr", "5a1bc65b66295bf1bd9eb89fc756b2ff2a03bac85d79209aad266154196281f5a800a82f6b682219bba9fea1a7ca5ffe9ad5f5fed11e58b056c3fe24442033c1" },
                { "fur", "b1e91a9c64268130f9dc7eff43af02d3e6c91cffb76ba9028ee3a329c08883f8d8e5f63fe7185dc8b9c0ac0546b88718a58a5a91a9db82d292b3e65f9d6f7bd2" },
                { "fy-NL", "3f896f601085d41b21bbd596ef2228438a212bcd979ffe7c44c4b287f6cac16557dc78837b9557bb2a9c2846d8edc77942c5b416b6bf2874b187fd5310f1449a" },
                { "ga-IE", "08abde1238c022f9ece9932e578f7795ec887f60dd778145fe9eccdd5ad5ad7203b489228c3425032ac0b4960d4b13dae9a2ac2f5e5de1cf04c4bdaaabd0dd85" },
                { "gd", "e34299653ab40a89e63fe67c4947ab559294a149c86f83ce07a78345ce6017da7cb76f89e11b38f868e896654c24c315c2dc8cf8b299594021def7673eb422c7" },
                { "gl", "0cb73e5b8a05b785cfdcda86a46b9013429f39f2958a46e864d89f36c3c12b25fb37cbe86cb400e25c6153420c3ba4fbedbfbae40dc364158d05c662ab892d4d" },
                { "gn", "d6e7f6889d3474f6b1c8f17fd8b26eaf50d27b239895207ada4fe4adf24df43cb1d03bf5ee43f5b0f9e821eba5320f1fdb4576ec3414085c86493af35a589a2b" },
                { "gu-IN", "d7dcc6345a204e038d42c0cabd91f3286f47f8d33922484a9762b6f4fd26b838d07c22eaf7fd581a1369fbb78bdfcea6130e7d8b6d24f2c4f27ed1dd6da8b164" },
                { "he", "debbb83cfc5bc1ac294191bf1e3b4a1dd9cc571b29bb6dd611acfbb6943711a5ce9309ff3bb9d7d44caa9d79bf16a6be606a814afc8ccdbbc5f26f88053613fa" },
                { "hi-IN", "55e2241705a9b263321041845fff9480fc44642896d2d304a5b8021b6636b95d8056dae157884bb92c2f12715160bb0c184ad6331baaf82de121c93ff8ab5d15" },
                { "hr", "f06cf2f41f78bb5c31ed5465850a59e7c4a0369a72baeefcd37dead7c0b6c431447cd7fbde4cfd33ec4b9916c352b5fefb4e2c22a10bacbe02c3771b099bb4d6" },
                { "hsb", "c705ab7b755af8a1ad434443a92c5afd9e130914caf37e369bd34cfecfbe5fbf1d892d67e420aed709afe982035c1506d2c15beea66d7c42ac2d47a231928628" },
                { "hu", "a666f94f0ab323b0315134fc29234334a7d58938d6dd99e70453e3fd48d8d09750ed33b365386a5790927031083d58417d8fdee673fccfdd992adc7c1f10cdfe" },
                { "hy-AM", "42793ad28cb5f9cdc9921035eb79a87bd4e80d2bc6156427bc7f49f0a14fe622da35f5e4a47b245c0ce79f3e019aaa3b525899e7ce02499beb99a6afb2ce19e9" },
                { "ia", "bebda88f52494831a165f88a9ca4b6e35e785c1c53c9f841ad84a9c625cbd5a370135c1f7fd2362c00cf9a53dde122df2132fec04ee156c2e690b4b8b7fba954" },
                { "id", "860a79a053220e2bd2fa9d902cc14f30f5357105f11cd4b03c9467b620a72eb17c8a09ec03c0cd2f68d4a4ae4c27cdaf3e439eec5cdf1627b191e52780a87f07" },
                { "is", "923343304f986447b391633c7bb8f8d744562a42363d522f1e3a2d511efc5352a2b65c1f1ee643ad00d78ca0ea07ed5fe2303ae93f7bc375ab3a9c721629c7ec" },
                { "it", "9953d28507c6df6c19a42cc29e01ee05133a0194e7dbb402b8aa0ea8c32f837003799cfc2054fc404fbd7e78e75528d3edfcc32a7fcf24116490fe575145096d" },
                { "ja", "290b81bd0f9150f0261c7745cef4049e4c8da841dd7bfbd17b990e9ab23b91ade53374fc9f2e75a794aa87fffe6628ea310403a2bc4606d1d0581aac27a51832" },
                { "ka", "bfb973c8d0896ae5f0271c8c0d844257fbe094a42757c39cd3385509bb99a2a496c7b8650d9833fd9ae7d7a068c44cd5eeb62d0137f86b71becb5272ca9c2923" },
                { "kab", "0e97dd7909f0a00a6e6220a0ff0c6d9e156464daaae638888d2978bbcb46232f7782533a6564dc6590a1bf1efc43cab59fa0bfa7773f4dcc59e9d4205d6cb443" },
                { "kk", "3727b24f15f00765ad401722b2ec5de7ddfe858409ba912c2647121ca11ca1effb555b7c0712cc5fe0ea5f03dc133f6886c672bbc5b2d9d94dc2067f61e803e9" },
                { "km", "e50c2dec007b03619f097d4cb095ca79f1194990917f8d817777205fd770d8e7fc5425655156606fd9617e954b3f999386463fbb9c5a0ad482af58bdb68b3b7a" },
                { "kn", "43e0e2af9aa8a1aeaf0c8268432a7cec2e2e63fc6cadac20eb8c2fe08485a554d1811886b0c105b91f600f5ff5fedfc36eccb5aa718fbb4e6451cab48990eb3b" },
                { "ko", "efa3ab8b277815b3ffcfca4d50b7c910839fce4de1b9973af9655bd533a8f00bc8c46b119ff5bc33a6b9d1bf54570774c38a4624e82406f5a1b40f04f34956a3" },
                { "lij", "2732bb54c74634c5ff61d941df0b94bd27eb8b29c26ef27c91cc4a37386e6f2916239e0a630c1f50420f14f7bc3edc2b2dfce4904f66d71f6fc66c1627957254" },
                { "lt", "147e639b6996d503f32f039b75054f29c7bb4b67915270afe45798d7d43910e3f5b759574ca11aa79c29504656e2204d61b2d2c6859e62ba64fe6883621ffb30" },
                { "lv", "a286f8058f14df451f754af6412c9bb540cbb4fb7d938124533d3eaade6182e0840ca3379987b9fe7e3a30323135d6eee89a47f420f97437ba13ae821b999fb5" },
                { "mk", "f371597dce20b7804acb12bb198d814cf319539b2c6fc7944bab467a7cf7c6dd61490fbaed3f8929798b5d6b37ff12fbc8d27fef5091eec33089dbc0d017e99c" },
                { "mr", "8396852b7d6275eef58242a1037db79b9427da8d8bb309d9bca020da9bed0b8f74b20749c8c74037b72a16b840e3df88c1fcd41d813c1a6b81a85372af94a3e9" },
                { "ms", "375486250c86f9561bb4498cb4d6d5f874d72148d46ad78a835adf33362555b662c069ff4a313bc018c4fcd5cbc8e7a977f0de4c4cff78babaca6a96ba28b39f" },
                { "my", "8e861d87fe4bd190918048c88d7cea9aa75a145669e3aace61e75fcf35c6d4e9509f294367e0961aaa083f550d9d5c3577b65051a5ab80fe6abbb90d7b5b9f05" },
                { "nb-NO", "145e17084ab459ca39f6d804858a6873ffb6a6faa09dbe47a6e3853e2e69149fa62d4ca2cf51ddb380126eef7b4b41a1deb60025edd646476d82dc36ef13fd92" },
                { "ne-NP", "56db2665a2b34f2b69b1afcb8d193cf97ede3ea466efb66e3957c1e454a8511214a1bcf024cbbbd43826de055fd7796aecf7457e9e126c65e5c5cd81762eec99" },
                { "nl", "acdf4ab0afc301cea856ab40f715d0269d6ec24a712a7ebe32e1e17d367210e96c69b4fd943f72202033ad34941f76adc70b5499e8715a13bd40b8e98c21a9c3" },
                { "nn-NO", "5d17a36fc8bfc44925516430da76749118341a7442272acffd7d5ce763530791d25ec449b95e6ceb8e6222b35a920e6206751a92bd73299179a10534174b2866" },
                { "oc", "ff4caa861ed9a23191d8f60b71cf2cd3894b26b94a148e23a61ce87537625d7390370cae8e114934af10dcc00309ef5192b6484bb943155dff6f480ed76d0a77" },
                { "pa-IN", "158f47ced11cb59057e30dc14955403e977a123ace0390ebef9db56314d2fc9d91c176ffe4d79a97c82c2c87890010bee1f88eb4a4f813f7a6e061add46c4fb3" },
                { "pl", "26e17d02c3c63bbe2a5f846acfcc44830a810e80d2640977ace3b8fb8ab5d08c7da85f0e21d92eca195ddca1bd0360d94f26b1d2686eaa7478013c6e073f93a8" },
                { "pt-BR", "e82ad8a665b270e05992724ec60841ac502b19b80420c3872f1d4d1271d576fd8ff88b403edb6545bf56434eb21dc9889ba3569f60bc5390bce874cb69b9de6a" },
                { "pt-PT", "ca8a2f8124fc549c3093a0a92bdce8aefcdee9a3aa57abfa415f63acc92f9a743cd7c1eaee5fe1aa3bf58654620e91845157225284ddde2f82c39036254e99b5" },
                { "rm", "03a2565accbd3acd89983d1a00f257444a89d2784afca752c11cdd94168e86a01e3321d2809734239db67c4fe47c8fd4e78000c16a71c5bcf0a26c56b4af482b" },
                { "ro", "4476c170efb6ec0264dbedefc5fe6685df025daa7c4498fc55d25ca954a613f8bdf28a0ff40a0c6c2a11efcd89bb7dc01ab3ac882dcd281824b195c4fd9aaf89" },
                { "ru", "97a1c8e4ee9c2996c89b328872649b6d24af3b1fbb9809b1bff19ff3909ee04aa9a49ce9b000eeebfad8ee4be50ec29a4ff42b13d7c24f46848644d8f6acd97f" },
                { "sat", "922107e9c0b81eda373f6be8eb89470653b63fb8833baaeb0efc8f3c989789d3677cd36b405e2f44ff18b404d00dd4e3fe34ec276833913aaf873cf0986ab652" },
                { "sc", "725943ae276492e39c0aa65532bef0da33b9bcd5962783bd8c84da09081b8eacbd90487585cc2220be02d5c867b9bdacfcffbdfe711ce631c83c3204ad011e0b" },
                { "sco", "ec066acf32024fe64f01baa2875b850232811225d605f90ca1aefa75be17cdc584da99038bf8e6504658ea377c82126c4492a9e4aa9050b07c423f666376b225" },
                { "si", "fd22a3e51b6865ec9c79d335b84564c8bdd57c7be4aa6a52f1f2ede771d4040fa95a336524d90eedab5b199b82819e51cf9d07808544afc192e29d99e640ebce" },
                { "sk", "21ebbc4dc0626224c9c9fe2c0384ec712444efa67cf4453aaa6257a6accceac7e9c3723a5160c1ba3a5c39df2220462bdcb1a6598d0e5047c2e3ebc9c92b17c9" },
                { "skr", "d3ac342e8b5bb55af8e22ca7b0436e9477d4327aa7989fed9eaea0d82c36c1e57185ff93a3d6c72c1b9a9338935c6f40a8a2f0c43bcd00ee3bd2c2863916bac2" },
                { "sl", "8c93371890d672e0d2dce8fc2cc4419945adf7886f83089c5543ca6303a063b434abf931f06e1031ac81da93a2ca045d5e50a2e4571bc64874e6c781969f0c04" },
                { "son", "c46e005792a15cb5edaee5047d4f5365f596154f21cd7113caf506c29fa8da1fe5d9e7a98e5bd451c9abcc80db5fe0b6516d2a7c442b905d6b648cbf2a1d7ccc" },
                { "sq", "e5f815d6432b2448e78af83196d51de2eb2e2d0bad0e366478f996c09badd4301fb1dc8ad7b9d9309c34bb818c5be1d310f13289c1a1c4b6ad4247d84536e46c" },
                { "sr", "bcb4e4cccf46fd9a89e00c667c28e829b05c572b5c71f521dbc3b4f9f11585f796b3939a1cfb46cecfed32d418a82df5f6ea60f09e396dce999892842b0aa398" },
                { "sv-SE", "bf534762b920523a6d58cfa2427d15af4447bfb5d84614213b5a04b9cb420f0f3c396f561af29b276d71b162d04d406c5b62901ca22b05cc56d95b20e3296590" },
                { "szl", "8433fe068a6b67d0176d92bf24ee88a048ef40cceaf7b7471f44e2c884ae147b5c9490dee0b50d098dce25eff699455858ffcc2de79a582f0ee7576665807b39" },
                { "ta", "95935e76265a2969906dce3c47f8ca924fce670cb0d2b9a0ed23f6e67df5b778f7be3507af805c703d036954fce473e3a0a30a05bc3393e94a572c7f43fcea3a" },
                { "te", "462b2e6136898872e371aac14c293b842b56a3f554d89b593e85bb31cb9f36569c4fbd27f721a802409f4e78493e0a8208010a861f37134b84753a94755567e0" },
                { "tg", "b393b877cd100b05965c4b3444bb4772b4aa7908a2a733d3797af240104adfa8e2593bb329c3b697dc7f3c0e8ce7ab702d8ddb531ee16e621e7d5a331363a70f" },
                { "th", "b6b9419458bf0bddd7fb9d9c24680e5631aab0dd6dd650a71ebe9d099ec155f0e611cd708fdec1a4a8df002089d6acb72f6977ea41ed90bf3ea38112eee8ef62" },
                { "tl", "7f175b8e0f0d3a14bbe7972681738b37a6765cbdfd7f063af8aaa71b79a5cabd5ec0d2e8d5ac43dba350a0462bc1573f5471c08531b73b18ce814a12afa529b4" },
                { "tr", "8c46825202755bc8a1798ca3ba251c234573d925b474aba0af00d4bd7b4f095f956210f0c3ff2fa5a242b42eb051e5ea63f4f9561b29bde783b20552b1267ad6" },
                { "trs", "bdf8bb73e1f70faf287c0616fd31ab7f27226a5af735df1e2a5fef4f69f127b40b198b7cb1d08d26e97e92a7aa9e6ea216bbcc603c7198cda04dd6eb94e73b68" },
                { "uk", "4515669b4fe76eb70fd8c9d9c7cdc74a8958e01c0a195de724a1cdedb429a84783e0c314f437b9d2acd640eeceae0dc4eb87df0b8d47fcb6e7094e86500faf6c" },
                { "ur", "8fb006acd61aa4a91889116167ba076659fe775f4c4cfce07323af4095e5fbce0f0d6617c6d5b1843bf0c894c966b6855c862f947158094d25de929b1a0a9914" },
                { "uz", "3580a881d4645d50d14665f618cf4594188b3ec65556c4cd21103252cd5a5527078c475c76d3f4772f9c7c688f8961218a9ac778db2e69f6a0eef9b6ec445665" },
                { "vi", "e920d36ca6565618659f1607a55590ce2c19d191d391cb59de3f1a543f6beafb91aaf1227296111a0e38c899d6230fd5e94ea8008970ca936deb4537700ef41d" },
                { "xh", "cc1aa72955a6ad9e172d56ac49cab913f99aaccd6875bb76ab6234a67833b493398186ca46e6299d4c680514bfba74486c0864975244b3050a31237362d5eda2" },
                { "zh-CN", "5dac04135490a8a68719296bd52aa7c321a95c6c6f4496e5b8e2e9a79062ac6228358d4c7e7a6d2bb2b9b8772ab37c494def082e7a2544815b6bbb8369f2c029" },
                { "zh-TW", "8157596e266f22201f1a59e31ebc86360fd36dc8bd818a31e06ff972222cee0e904c46b556c1e8c14dc28189131ca042bee354d2c8e14f6d01c5c2304215eee7" }
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
            const string knownVersion = "138.0.4";
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
