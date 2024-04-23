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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


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
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/125.0.2/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "5e848d05d1f3323118cda583601fd48e4e364ad10bd7000ef3755f57a4983be509ab4af744f9024cb7d8d4c7201df1385e8481e18e762afd121457c270ab95f9" },
                { "af", "183a66b1c94064465ef45dc3400daedc7548e11aa34fc46d562abbe50fbac1c30a1a26b9ba9a9fe28a9a5f4dcbb0231681f129377bf074fb214c0d98f4f1753f" },
                { "an", "5aff581cb0b5123d3365c741fc934fbc5ede72e1259be53670f7499c783fbc2048ac8752b30a5a336039f584904743bf00801ec0df0731a9da66345cc779de45" },
                { "ar", "035725ac953b742e78f66374eea0c211fec2cfb37d2ad9724f65aaa86809a1be419136b513ba87fbdabff4e98971af9bfe3d847f567911ea3eb74ae7a03721d6" },
                { "ast", "2e736b01109b2416e987787aeef072b0f034bdcb38e27844ec77ef8595d032d32641e28a88defab9b3da576399ca83ee4edc8c78750da05f5a060833e727b2e6" },
                { "az", "1947fa02c32e44420c74b1b22cf8bebc9b77d911dc84efbf9b0541f91b1d871f537ee4074a4d421b269eabcf405afbaecaa13399662ee57be3ede7aedcc2b23f" },
                { "be", "9792a321c65f97e896ae7e8eb7ce550b960b93529dacd9aea0a7c12a49366102558edc1f564fbe02f1468d7cbb68cc8801cece519b04ab850ced1874672f8cb4" },
                { "bg", "c459719e23964c334a6358ec02ab8e1fc513636070842dfb1e313cec30d14d2b19bcc4946405b9a6a412b7fbf3989bdc31a7f6c93e4e2ff5d437ca26571a61be" },
                { "bn", "a2ca850b71f9910d68b456f3950ea46f4ef7d71600000b537c04cb06daffe2a83cce65f9f99120b8525ffec9cbba444618251acc04b501f53899e5de17db69fa" },
                { "br", "956461b7f9994427cc299a5edc2c518ab27b74f5cd6ac6b8763c874fc42211b383231069133a249291e3374654a3330ef05f4b859604c8b5b6b1b30843de2a6c" },
                { "bs", "4c20a5bfaef1ba4bc190bf5b030afbb2b2fa06be8e8281ab54d6a4e590993ac470b9ce3c2a7963421a31c123586585f7c9ec0885091fdaed2d88f9b32d98c957" },
                { "ca", "dc47a079276782a27908aecc3585069e13a0286a9d3e6239dd74a1af9371ccc2bb53029fd9f23d135fc772ca437d608d19649c31d06662a0909cd09ecc61882e" },
                { "cak", "8150a3e7bfcbcb338c4df6bf03317be2786c6a1e0c1789dfa06395faa62672cb98e9d5b34ea2e99df4b1bbaa81eed93176214253aa2a2acbd894296b06fff8d2" },
                { "cs", "f16ee4be951fc77e054e6f6bfedea3e81b20d15d2fbe693a95ff97f6e0f2f3b95669e91e6cf6fc9a8d9f16b713f19f647cbcb03e351505f62becd146324f7e51" },
                { "cy", "e3108d166cf0370cfd9074e4338ac346d088eabf7f554d5b22d952fe57b1140f6cb1a09c94c72008d223f12e6e4b56871c08655171382fa5656bc6e6a5ccb2b6" },
                { "da", "49bb5aa59ab65749dc510114d178236322f6cb07a12f891a99c30f84dfdd56e02988629ecc34d5ac54d9f9be5ea08b87f0a497d1095ac31fe715927bc1c1fe75" },
                { "de", "e983a2eee589f8d79211ede2c752c50c33654dcb2852e973319f6c94dcad2970a177ce9d7e0cf8e1deb95bde7980ee001b5d710b02252447b75aa2583a29be6d" },
                { "dsb", "562818ac03bb12bfd2cc36e6f7c993fb64821bf0d574f55d9f72716b4002d2c5ff11fdf5712264d426f4853ad283484b2b6c1ccb04e662677dde9530789cb4e8" },
                { "el", "b4f532c48a45f89eb21ddde637e35626dfbb27adaaccb971e818e2b029a2b067dfe88c8aae43108743060a0e9e1a0cc78cd1bc874ec668949805abfea95019ea" },
                { "en-CA", "bb369a9ef6673ce385771ce05e420185fe826a2cdb3cbbdcb148a9e6eb1880279ebd454f43ed7be73eff1a30e490126e786764d95ce1b73494a5b40015b5c074" },
                { "en-GB", "dfbefdebfbce53b9fe1f490a7d5b472f3abc4e3aa7b20ffbe9342e37bd911fc2e01beba5fc29c51b7b1e745ce095701a4f32ad117198d3a4b46092cf1e455c7d" },
                { "en-US", "1a6e651bafcd05ca40bc8ef224aa81b632a6ae8df07d829b929479951e82da2f64ca6f80fe726fac9c80208904fc377b43f31437ce62cbc3796c604f6e8a8484" },
                { "eo", "e79aea864c3fa70886a7deac190b811e5fe77bda9552aa2a08da759980737f7d59914a62eed02a71e7f4d7f21211c4c912ebb25165eb0fa77a5f4adcdd688b58" },
                { "es-AR", "9bfe5cf9d3258e158838aa7a4aef4711aee65956afcc2d405932aa5c8b1635e154d2bd7551aa199634cc2f43be981b2211581fbe5a6adf68c871158c7ca0b2dc" },
                { "es-CL", "985738da81af33fff568be7173263448990763bee8cd9b562eb7ce369e4d192af92d90e57e9f320e744750fefa490071de753e8bb48c75587fdd0cb0a76e3abc" },
                { "es-ES", "0785163e1353679333745286107abb94f35143f337fc5bc67dd226ce03987a96df7476d9522bbede3a8e960b7380c827473f78f4f1f599b2b1c19170fcb24c4c" },
                { "es-MX", "3f0de3424fe4de72b410f5235a5d3d3f5cdafe745a5e958c4907a5f7c33b19c04996005de5049e8adb212a555b24b92824625312557ae600666730091721ebed" },
                { "et", "ce3afd5408489e75eb5e21ca5bab61ced632564b7435922e2626a9f8778cb66d67b434a6aa0cabda94fe9bf4245b3e45c8c52174fa56cd744a3163cbf0cbaedb" },
                { "eu", "0e23e3bf860a157025b052bebb10e027e347b3937061d7414596f7096f895ae8f64f53feb6fc6675553757753193314ce867dc8592e6c1e6923852c69065bd8a" },
                { "fa", "6f6dab5c68d311a4d74b22cc0a8f7740a68ebc5d46c0fac55a8fe9081497e1fbcd4e9984e2b310534233a3e4a5fed73209a6bcf4fcf9f660ebbfd4a8593553fa" },
                { "ff", "6b3a90ac29c1cc704186906d33d02f8e0366708b936de08cbe9b293083a2992b6e982cec73df7cc1f91bb1b0e71f4cc55f269b89a5f79ac827c5d682c902b347" },
                { "fi", "54d822b0dc15ac36517b8e20131a5c326bbddeed3dc84c9da076e6a051a38cb3f36536b36ecb2c27b3a2a298f96d33d2990461d5f3374c393fc710fa908aa147" },
                { "fr", "e843798ec4948e3cf6e8d3dbb4811cad01bfe1f0eb8be8f332358482538d284d852995d85dca62fa2cd120e8e85ca1e2eea88a21fbd8b3903bec6207692ab5cb" },
                { "fur", "312a35cba47056bd8cdf7eb4cd8b8898d4fd77e9760bab318653d35fe180edb59585986a2586e4e9d99b216be38d708ce88d3f71aedd06040532777926a33cdf" },
                { "fy-NL", "5eec8060f7ea129a4636a7fe5ed3b696ad0779178fe236f20369b6930f4afc9671c44435f365cea20fac97c76d91db0e78173f196dd5c0eacc4d4b86c5101b4c" },
                { "ga-IE", "4faef13c7ae422b7cf46fdc74a2d3fa6a6dbe0cdcd8636324b5809baa4cdae24752dfd3ada4c2429b479b22cfc6322ffb2749cdb9a2ce9ad2b168537e99d378a" },
                { "gd", "9abb0e75b2d0b1e4c06a2096273ec890839895eadb021f1e7c040ad5afa44993e76483a46b773fc5c659f4d867b4a74947653e26692a6defcafae5f94a615fa2" },
                { "gl", "e003f57c6d77d77b83f4928bfd1227a7b35720ce3fa0ee23d6c965c0e545a37fb33e6859718bc4bf82593089fee3fb7b65cfa9459325994deb8e26844598eadf" },
                { "gn", "d3ed4d424b27333da81ec57e9baac541967873836d454b87b941e04e6bf2f48d34edc8a5f2559d3b53d905b21627663e39e44101e597c290cbc9e708544ec5d9" },
                { "gu-IN", "3e9dd7850d23fb146f86ba028ee17b9cf0371c76f0a3f8519104b0810acd49e6f8cc6403209ec93bed7cf409305a966a138172329826b58ce1129f74cfe77e93" },
                { "he", "1ff9c86290b2c500e66b60808fd5139e549671c25084e9c1232f7f8f35a48e979d5bd15a9c25ee594f91ab0fc689af3c43d026950e5a8b4f7847c4e3a29ffc0b" },
                { "hi-IN", "6c56ccc149e0c04effb4aa2e6a95fa0e542806f356cb8aa5ae6640512d204982b62c1f1ea24f82131e63027b60669903cc84529f144fceba91da5616a8c0c207" },
                { "hr", "67e31becc6ddc2571579c4472834ef2334192581192a54b01a6eb32ed85638b4e3f10ec2e4dd878a730d94479f043343fa913e0d9acd8268e5b309d89c327ab6" },
                { "hsb", "acd9becc0e441f95b0417158a61c28aff4fe44614f5397e3b0514da37ac4445a12a557103b407b96e5f9640bcfb80c986651cbb64d97c83d9e010798cab5f1ef" },
                { "hu", "f0513fcf088f7ffc83ad196b4164d1df34787ca08254dc7be1380f757588a78aded29bdbf5b901579f5a1b9d498650a6696f76af096bbed779be758dd48cee5c" },
                { "hy-AM", "9dc650d185ca478455f2ed3127a151cc65bae100cc4275fcf9275323653d45e20e2c72b6945983f33017bb9a29798b5b8fa2f8bef808eac03f67c83a9fc85599" },
                { "ia", "5235c3f5a5e0392d043fa6ac0311cca2c6dc2d3c4ec526116d90a169a3e5c3bf0eb2b561a21cf5b99917d0e52de52cd5e8e44932cddb3e95c198864188dd2be0" },
                { "id", "058bb55ee06c4b49ec3377af850d6362057e1ed7a1d639db3d251851ffb91914e8ecf99c8e1c06d814c63e03b82522e755c6553ca3fc5f67d6be99b3d85abaee" },
                { "is", "559905fa6fffa67efefba78538c833604f326580a048dcc7e8fc3c1daf846e106d4f966805105bcbf6760bd1ff6b4c8223b0225233bc10c817660f192bacaa0a" },
                { "it", "1b87b8764a6d9a00315d4b729a8013feda7ab12503bd15d4d61e9c70358a167dc6f397d0ebb0766b0390ab242b243cc17f8e9e9456615d2d787c0527b82ec5b6" },
                { "ja", "1cce900c38f55389cb30851de4248ecbd602a44af4dfbdae773a0f6d116118f7735858def48f41f8d6151f471fe20e8917ff1e07a2399b37b7c0e01b7e53ae93" },
                { "ka", "5e2e176206c86b6396a7af8e90dda73be16a575bab62ecf26b04fcdb27c2b758b9480df1f247faebefb9201955dbdcda168e0c343e1efdc7ad85b5007bc76fec" },
                { "kab", "7c64fb7d78be133a4cb9dea5be3c1f7059a7fb9d736bc147b20c17621929cc59c6109c162c5679ca338cbc53c03bc9d00b3aec191cee2549a2b4e28327aef678" },
                { "kk", "030a2d7d10f02f9215b78ea69348eb692f9f883f983f5b4f37c77b07ebfe045f0d55328e4684247cf3c449be2e73f0a9a32ad0f442a7da95c315aeb7e7007ff5" },
                { "km", "c0a0040424c69a7aa9ceedfd3638f7f7b79543ecffe3b3d122e3204a64af9fbcec934c9e4bea88321964db4fdf02c365586c2b4ef0fed99499cf0d936a33e77e" },
                { "kn", "6e648f13f52056a6ab57bdd1d39310f9c57ebab9f1717d5e85d20a0f734d7a90e4c916593fbed6e91373a29f79cecb04cf6ae556dabb4e65eb57aeb3e7607abb" },
                { "ko", "eeb9c0d0deb21c14f5b7b6de2112ed5b6846348dd2711764fbf65b2369739c3a602f5a4e65d85932705518d9f555cea0c1c764f7689c9e1704a09b5faf3e16d7" },
                { "lij", "5bebfa3fdfbc0e1c0fb7cb0635ba47d54ea06a94361d120257fc011047a7dbb80e9d7b715aeffad9769867b9ae09f159ceaf84719b58789d027b9c5b035302d2" },
                { "lt", "325650a225655ccc5ebf92ef09d30a7dbd1299e3215f8a9180a425b1474921a3d711a179a59b5d22667f794e1bb6e43495065b2ab703d8c16affe3d6f0da4259" },
                { "lv", "9a322a2b4260e1c49acd3b597334118991b63dffd0d3a682fdba744d9eb1d88ec33d15b727dbb9f457fcc68ca53ea71afdc904cba08738a8ee2aa50e3f696457" },
                { "mk", "ad1a3794c9210c72f2ed33fdbb4692c85236f5d596c9849c0aeb04fc6c75777f86ca0d358cd9ce6053c243377918fa7b187eeb59d8e3a36b7ac14e00d692cd13" },
                { "mr", "26a8c3f1bdc21336a7349297208a46a003a2be341736148b66df2b569cb4422fd5e86d56b8362c3322985055a9385e85cecfe606e2b9ac669b91038363d78778" },
                { "ms", "d0c040724dd74fba7d883d86bf7ffbd5611f453f148b921d207a2844b80c7f76d9147f6cd6d92586815aad35ea03d8a566034cb518b7e9ed800ab64506ff685a" },
                { "my", "806b6473755e683e860235273af57dab60e2f1918009635dcb65b1d9bcb2fde3c3e6b040eeaf41b4b0078a42b96369615124004b3be5a25e14d4fdf55a2cf4b6" },
                { "nb-NO", "a0ca971f5cbbae6306264ed53dbd342c6f4560a369733ef49eca3fa14c2dac8ba1823c2796878e0b800d40e955efd96b420a27266161b527be714686c038c796" },
                { "ne-NP", "7824278e6cc37266aab5fe83a0c88ed6fd76139b036db8b5a92af8c0e5ac3b5d5bd2ab8a34c4b7d9bb76cea2b8f9f146bb98754e8ec886e78100eae116c7108c" },
                { "nl", "5496e2683ccbc6798adf5541187631ab01124cb09d1f63218d23fdcf0a6dd89292ed7a55bada3126d0d5e12d15b4d40185c6b8882f32e893bd58cb6299d3caf0" },
                { "nn-NO", "772674cb7c674544e0eb5cc5d7987e70159e1673abd938237682c722a11b878f50aaa80697c22501ec6f9682147245518a296f5f5a57891a1d95d4bf0989c95d" },
                { "oc", "46af8591d22a8e67cc11614e145860fd5cf84c4bd7f7815ad67d17fc8b60d207ae47cc36809ae532a3756ea91f7ef5c9ce7c5c8e8d8b56efc4b5baccafbc455d" },
                { "pa-IN", "b0d91fd1122c8abb04ca4c4018d886dd648ee0b43abdc3cba349892addb42b8bf34cdb011f7f655dbd3e7eeab1849c7c4ba2e28028ac168db62750d6b0d44218" },
                { "pl", "cb3e55738b179ac4d003f8f47ea6006703531083a799936180d69186e0c445c7047f4c8db6003006b155f894dcacaf128cb3386321c3fe8fca1b977fb8bb2201" },
                { "pt-BR", "586a7c8fd75f2646396fb9540d570d200495bf35e2e8e948276cd5432860a9c9d05c86125f1fff7c4acdb240bc2cef492570e408d29277456475a04773c14609" },
                { "pt-PT", "d9c88582630b81640199c481513dd3ededa84cdbb1a1c12ec0b1e07392e7c0469747c54110f9b8a098868c28f31a19b390b57ec18d09f7e0d686c650156c13bc" },
                { "rm", "7a6e2a6b5da9900ccf941de9e079475c4141c93fe2031242c3e7939de57881a1c0f31f543a539c2d6f0f779be604ed90e19518ceed0d6d5e432d26b11d4703d9" },
                { "ro", "03309a7c1611b054a658050ab8ac0073a8117ba88277aebee1c200863dfeed8f7338703a5729d83d90b57f06c133029f312d3bc39a7fba8437036e1b7f9aadc5" },
                { "ru", "93a37fe74a1a568657ffbcf9a8aaac9c8ddb7fa50e924f1d772c4e9f7a3cd8f2b715f13bad39af7e0861f9632ac0e8fb76f601d569485b5d8c99ee56d282b4bb" },
                { "sat", "c80b36df0ac36e22628f72a2b04d08e7373c8f3f2c9133dd85abd068d438106cfeb729059c7eb162e88601fcadc7cfaa0f68c9dba93a7c7f66047baff82b8a47" },
                { "sc", "9fe308d45d6308d78896a7edf940ef3984a8a00259563dd48257763e85cc454ee7e21ef99f2dca39076e3d01cb79b6b066b3d577fe25016dea4ecef319b65655" },
                { "sco", "e7ab669ebef5fb1242056be620712dcd4b0ba65dcc20ce31c09be47fefdd1f268578de24ade39067a0b647736a78eeab331217152768fa3b020f4736a2e54599" },
                { "si", "2938b0a8eea3bddfc1b8b5fe8b37143c6db2d5be0cf53a8cfd7a69b1f6aca87458ad1106122bfe28aa707901adce66a2917c0e18be8bc88bb8ed432b4dd45093" },
                { "sk", "aa5deb43f2c4784d92fb509ab2cbc7aacd05648504ee426dbd2baad86047ed5b404335f909f8cbbd84574b60981046be8b1c45c46a69bee875985e6f01dfd4c9" },
                { "sl", "f0352fa7c81606069c01ba4d04335748b2eabe74fb5a9ef099682d50e5a7cec01dbf3259d391539f9124e3b925fe1192995d8d708148479a7b465623df0c091f" },
                { "son", "486745fb83a3c8e53fa95655f88771f5981fbf685c56959d34ed92132614beaeae000e10d464da0e8e727b5acf1d64e313a35fb14c447130ad798f40efd211f6" },
                { "sq", "7dd4f96d86d1a9b855657861090c6e8466eae889f20c1009ec998cd48d02ea490254301805f07ac9d4109e30bfe1f1618542bde2c014db7613ade1297752184a" },
                { "sr", "bd70ee2211798ca4c9578cc18dc42c09d0624d4cc74044f70c77dc684cfc9d90e1a1508b740d8e8226b5c0ebaf3fb10f879ea6255ede65fc0e2e1113cbdd61f8" },
                { "sv-SE", "03c8a33f6d424e9c97d0d05eb5ea39f9f02c39078d9080c7c10dae8a79453657f15e9da6fa3244f06b2c4a18629207d285ed3c4345e3db9bac8a45d038f9b3d5" },
                { "szl", "c235f99f1e6024e065e1140aa0f232750a9c0b2f94e7c42d231f1b886333a54be777fd062996c5170bee2b260f51f32d333abdd097c9644316e4de1d45cf76e8" },
                { "ta", "4686ad3607172b97342fb673482ce6a16f98b4a3ed243c94eace8e9a9139eca4b48be6323555715312cbcb0222d4466599f0809a4eb753138a6045efd8957130" },
                { "te", "588143ce9db9bd84a96889a0a6807ff5110b94ef31165d0284e57ba3e66ed53998ad6225872d3b0475bd419f889cdd8dbfca20cbf7c8c33d72b172e67ac59080" },
                { "tg", "d5cc37da324d906a1cd03f41d191115c28dfa47a686259e27056dcdcf21adb031e0bbfe6fa7f0268cce7c72a379eb40a8d29105736e1c63c7c28871b3752e0f5" },
                { "th", "ea38dca7ce01d6bef804df6564d4d87d836a9b2bd356b63063ab2e83e11edd06a23992bfd313e0506d4c14025775637cdf3bed450f295ec01f4107aadf44935a" },
                { "tl", "f39220b4c67da2f5216a83b253c07fc90443da13e5fda4c32daeb4b2c65465b456c748077e503ddabd024200456fdc7fc33017a40816324029e82a125bbb6ce6" },
                { "tr", "c8072f3be0e10cf3e0932440026328eb50a959edd467389414341b774f01b9f5d305fe25e38805b475852a3ff61b19af019c7569bc555ff2ee922d62aa099c3b" },
                { "trs", "fe60660cdf5216d5e11bd9b64050c3adbd8a9eeeeda1fca4aea70399a9e9a9ea1a5854ecb8b6f47a766d282c1560ee54ce73496495a9886e4ce84fa3b6599557" },
                { "uk", "4d32f1b95e00390ed957534f778087273d8d18a25204a1b048b92a7ef0b9eb3487750027dbdf88ab62668d3c022663375bd7ba2c65bd212323c621d0b6966740" },
                { "ur", "79f2d64debce4ce4e64e8fc5f42f8c188aa991b585b8b16c3d87d821503e8c6448334390bb8da3f0c10b15b463d4e3bd056f0b0d146a319e5fbdcc75cf557df5" },
                { "uz", "52c311bb4fa5eeb93f3f7f5f378a83566124e7cd5f4c240ff94335df1242803c3ca136b9641d654dec01cebdcc6225ed2a9a6e1293d2330931cc5634578e5323" },
                { "vi", "742ac37f08833833bef7a96cec51189d592663a0821ea07aab480846678e6c29c4c6f2919b56930da2a04d9da24490754923fc432243ec199a55eb386da1cb56" },
                { "xh", "5311cbd5620fc93aaa9b84828459c2393423185c7a5f856b0e71aa334cbecc9ad9ce615ba81a43f699948565a3daec9aa54540e61e98f338f41771cf2b76d750" },
                { "zh-CN", "42c39ed0a0e29427b13b68b6d34d258ab3f3181106fb40bc1406119e63c347d053c390e1d7c62b7355a87d6dc9161d06219040549250d51c12345218c693f11e" },
                { "zh-TW", "b3af7b9c2940576452df57ce0611631e3a489bb0d66d5cc6d989036ecf49d3c340744fff42bcb097deea74f2fd2a5a1a3b256077e105a4a09ec1003b4d6b989e" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/125.0.2/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "a155039865ba8ca4e6d801900651cb5ab290e959c2d71ed155ec08a02ea3ca59b76cd400ce083c122d9882d969c63942762f33e1dd0b68369aed3933779d3141" },
                { "af", "0940c57d1632ddcad5410c017dfcf0ac265653e59f1f908ac8e68761c66fb0dbb72a8fb1a6690162be983f59446b15742a8e8110c9486ef6f08857973ab3db4e" },
                { "an", "4402d20f43eb985a72251a433caafeb9392b1e466404ebecb8aa4cd0a33c04b1e47a507e59bbada2c84df8fbad27184b92bb33f658df7438bfe8cccf54c98aa4" },
                { "ar", "ccf81956963d88fde217a607cea67d4eda094992963fab77fe66747aeaece87791193433916875ea39976aa944fb21dd5f83ff2829af9ec25edb69c80baa24e9" },
                { "ast", "a4e2977e9e2b5a829f53b103eeb66105004c1d4ceb478e11652f9a2134d21cbb30d234df238522225bc400bfe760ff2d6b84a822a01d98a567559470f80360d9" },
                { "az", "5afc9b1f61f32b3efd6b25f35c10a1781c4df75558135bcfe249220733c031305c521c83925e5e3f9134d005d4639ee00d37955dfcf7c9c52c92c1eb6242668b" },
                { "be", "84293c67f7a80eae5304433e0c863f59ee78e919505c28fa1ab200d334514bd7bf880fde3bd0a30b65b4cd1f351a936f16555b316886c9e873413d7acad962a1" },
                { "bg", "218a0952ae39526a91e9e3a8246cbadb632d31df17401a38d15061002b842e9fce243f8e6867ec88b8e31334b32e534deed6b3da7beb7b14c4a127aac391a776" },
                { "bn", "c2a49fe917d2dce6ca869af242c9521670dc803c79bbb8940589501d96e8a829c655135d4c660cb70f70028f99bf3cd6094e0799ba7fba4ed14cfa691b0d1f83" },
                { "br", "151495c15df9db02729e47f8e8b8c7b2997e7653db49e921a60ee36cd3964beca585f23f10d1fe53a17f7e3831f86de42b1fa3f4d93b2380112dfc4346d222a7" },
                { "bs", "281080e3d862e9d1cf428bafd914996043491e62b034d85b622cb3e0a98c13bcd28e9953f51b458e4f463acd2b1f2db9cd0e3dc5eba01217f2fc9a828689d902" },
                { "ca", "6b503b159cd8dd94be6336492df28c98a62cb871cdbaca1026537984766025845617e35d35ed6c738927c36209483b9d940d60cd5c8a1229329c2e59d02a914b" },
                { "cak", "b4f952ae0ec026a7037e7d9d6c358314b8675dfa1a486ec4b23bf856f3c7f818739090c9a5d66c63089179b9b20528c5457959221461f38b10a92759a60ffc22" },
                { "cs", "8252a08de92c961ef80446a3357d8cbebe1e9236fd5ff9797a642442a92f7b4c57e09bfecdb1fff7035a1b8e8d7f0a62cdacb8521d3138bcb08b067ffc968f3a" },
                { "cy", "bda8d028482e9021b0930ad8f81a587eeba9045482dfd8303cc69e45d1641bd11631dfc791420ccdd96c37a8f7140bc9b62746d4e3092a35c6a9778c1ff39c29" },
                { "da", "5a4e74da8cbb20feed32d33cc14763f053584ec356e7cd9a4491d459fb130e67ecbdc3e9ba501efe56d577ba856aedd17278809514c4ba05d81c3b2cef212f4c" },
                { "de", "1f89943dd5678a08ef818198c9b7178ef7955c622af1fe62b98c055ecd785579e622cee460bcea8184ab057070efc2dbd98fa25f430f54959bd1e9e9be7bc044" },
                { "dsb", "b58eb04f1dab96d46f174436e6fff4948f1327fb383fc7e147dac113eed019b1485e647d0e04b614a5dab78593a435f01fcf1b75c9749d68901259656ed63849" },
                { "el", "a129e5386059f17202e513e3854d01b63c1f61dc2e31527d8c7d29c7e657b307395d66dec226d2f08868f9172b9e6469f065f913494b9f7b5729ae1f893ed8fb" },
                { "en-CA", "e5b4da871e56bda9122f16e1df9425ede36140622b39f72d1af96b22495875913b0d92542c6d706a6d8562151dd64ee8d7ad1dc863458560ef1a4be02b0f1979" },
                { "en-GB", "3036a68dc751d629ee2235174f509d32a91c5ecc12f3392c42f42a713b957755abd99877535d76f420b2b2beefce2c6c318ba4965ca00e38ebc1baccfefda16d" },
                { "en-US", "b525c28f4254aaa3d68e6779a17a332934f68fdc9fe5c2e3d116c7dece1e36e22f29cd1c92f9df5129a5c03e15e0f55dd2e9ce36e0db12f4c89641222ac4d7fb" },
                { "eo", "59435405e98ee7135a96b87a9c006caa13d7e98495c7d610a6cbf0b044c3e46904d6fd6ee89e9f0af839f99748a72ef1118ae526aa0dd970acf14fee10a70bac" },
                { "es-AR", "496c646ced26c8639556556a4f61ba2b7d75fc052ecb34e28c091d9a17dbc741e6fc7ed46d753b0ee1b6738a64757ab503c99b2c06a1dac86eb1b92cf5f3504b" },
                { "es-CL", "6cd2669d4625c4058eb445fe89cc30802b25dea94e62086b630aec7d557067b90bcfb4a11cd5984b0d1d4b0bd78198f55a88346500302137420dc811f24dd80f" },
                { "es-ES", "585941144ab4c87b38323096ec5fe1a459bfd5522cf87a4a314bf368de9a36c5bf4f7d9783cd78601daeed11df109b8e1dea2d5f6732fac855ccc512b7374a7b" },
                { "es-MX", "357e39260fe757c5d865e81203f1f9e5b14be077b728665f543d04135ebf2261c1048e9f443f1f554070cc6c78f807d5f1f6da0a3c0e28cb01ffa00fbf9e6d7e" },
                { "et", "6083bec902bfe7568fa9ce9af8265a13c639c6be5a8b16bad52e65df914af9b0a50c2458e5685b440d9a0db778a1ead9334b15363b9d45bb49ecef20d1cd1830" },
                { "eu", "b50593df3d9e67ce57a53b86a209616ea807271048df7bab7da23586c9a7311827a35c476cabf911085835c5d776c6c5184137fad2e98139414c54284c87ffdd" },
                { "fa", "3d87c0b9cfccd93dacc4bf2fc236803f2284aa8793f6683a9f794ac83613a686fd4760908b377517d591bf628e2e4156c89ecda4673ebfcc2154c48c9e4d20a0" },
                { "ff", "1cd2a70c128559557dcaec54abacdccca62e0638199ce12351dd0b1a3827738b071ad23ca93de4445e1450e01c24e1f65653064c6f54bfddb452929a240b54f6" },
                { "fi", "e98faf6203bb8fb2501afaba90f35c30ae02f14ea2d7122569e50da05d3ef21a912ca244838680f34551574154ca6256c0568bfd5f7431227160d52715cc6651" },
                { "fr", "d8175d76a464a20b5c68763abe691e925c06b1784bfef5f0fb0e89b71b2843e15a03a172f00d31ae836237b05a264afada8af58ac87ae316197eb0406510a78c" },
                { "fur", "bd250bf549ad4a8550e026e1f8e28626d90dd8ce2976e9e156552d6b2cbd9ab5680b1e9fc3c852616cae48fabfe101b504c6c9f5804d59be0780b8701742e0e9" },
                { "fy-NL", "88f988b9d5c56fe3f72c1c784c5047db6f4a8064753a508650d18908e16628217eb034d6bcfc473621262a6f87e604b59bf53ea0c1ef34156cbab7040290d7de" },
                { "ga-IE", "425d97deb1612fae50fe13a95649b494f3f1279ed70f2b2937cd58bc328927573c12c36c756fd63b016dc273f2a5aeacf37b5e8f435cb6e5c46f4061acf5c09e" },
                { "gd", "c1b0d60b3cfd4b64e6225d38731d4a8d77dacc184e1017c805e5a55c7aa3223ba05dfd3c2b797f4fd216061399ce98a63bc2d9827ed7231b46027aaa36ad90f3" },
                { "gl", "e1a8049f6d2cc3a9bc7326a3672e17766fac7b66a31efe904ad66ca0080795239e1325976d68efdce78cffeb369167184d3b1276d1f73d1fd27bdf508349b95b" },
                { "gn", "a2e1963b5cb043ad8ea3a6ee30722ca7a8bb32083df13c1ceab606e094398dfc52bd453c255a2166e5fe2bd6578c0b4e47a8c32fd12b30d709cf9b58ab13a655" },
                { "gu-IN", "891fa3aaeae034c5f3a779af0794c29c2be3e0706fe07c35c9c9e668dcb7659d3cfbef9a6d49cdfe1a6350055007e77585f029e97ea63214b4117737e35c01d0" },
                { "he", "e254d8bacf53c50bbffd6b7146ad6fa689d0803dcdb3f96fb463ba8a50531ad18a9508cfc8dc51a0daa2b04072689fdbb994d1ffb0be42010ddb92e02d47ac35" },
                { "hi-IN", "37bc41f2fda36941e710ad58178a9087d2efbbc55e28f08cbeb7148f643dde9b7a5388fd2d8efb6a5d634ba3884afb70fb6d2734d387a77711783f7e26190e53" },
                { "hr", "5ba50e46583cd09b0857768de2d9fc3a54eee69e92cdd7b65facf0cba6922cfeb391cf5f6cb06460a9762ff5b88a4aac6f627ab521f3136eb359098a8398da6a" },
                { "hsb", "9a75d962a19270d237c48dae0d6b4a4d9ca4875aa9f6e15f4352ecc27f0da9464327d08660344ac698a990c410e3d1dbd2e0a5d7a01eafeb0fdd4ddf2bf562a3" },
                { "hu", "182c3870ab536f50d5acd84127d3f3afaf2ec857a2f973530f5ee5f33345be3e983c70f5c75c2a9a987d05333759f7cd46c4f0902a2a609ab462b592e2f5c67e" },
                { "hy-AM", "fc69e631ab369afb9b42b4818e60372fb14c87ea46e9312054d9b150da7889211a63a9fa80225eae101d1a28c645c51bd75eeb7e0c7fa579adcfcb4fbb32f63a" },
                { "ia", "87085f55904d6151ae439765dc25522f91ea9ebbf9023af5825efb3d6bf5cc3a13fc3c205545a86994af3ed24488f87b9c7dda708cae98039dfa6b41d14cedbe" },
                { "id", "efa3700b3f7a574347dd33d8020efbb1d2ce2da84f2c68c7a82549096963f3ecfa9dcbce810cd7db05c13738ed2bd045c7358ea5cb5af93aa267f7ba2d562400" },
                { "is", "8129295138c84855591da2a58462904e9f419d0320d1d014a1652e15b83e292cb930013055a4105f2d88a78fff1baa37c50fa7bec23fca5e9eb0a7f5d499826c" },
                { "it", "05e0236db5ca4f2e00e92251a27af4949d124f887e9c4197e10b30041c5274d6983ae54c31ccd0904ac425ae4a3c57987f17a4124f48aa39634289cc5da3bb72" },
                { "ja", "888fb69221772e34022a10ccd647fc6a0d06a233555aa1fa7c90e16123f986cd3bd70f46d3c202e8fd061a134193ff17e7cb40a6df3a758fadeb5beac8f37026" },
                { "ka", "ceb97f7262f10e69ab6743e74a4e6a2bdd2f19ef96e51f937f74a9b8ed169eca5af8b1e1ecfb8e593efddcd63f22a7cc1cdc21609da336c779202c02c1fb0ce7" },
                { "kab", "4fa2c88939aed89e8529082f2e8308b7970bd0aa3b609513d02ccbe9f461a957c9fb44456f68ee83ade2a70f67f61be3c1fa1b2e767e728698e3ff05652da901" },
                { "kk", "7dfa005fab0b48a57818bb4c689b4e74bf1c47957a1539e444634fe94901d62e9b25492675ec4e15e84e16466a84f15a2bdaa163a2021d5a219a7f85113519c4" },
                { "km", "c5f94bebc91c82503601e29b650d1a1e0ac22a6f1d0896680b71140d18fd111b02b108b6b4403f09225d2d9f4313f331c461c4e84348c95dd7cb8c25c4fc4066" },
                { "kn", "0d1c1bcab3e92ceb2b41c5480e1b1d06e97062c0048cb300e62d430840aa2299c38f2d07e8a4ecd51f06b6c85b8f46e78e93a37fe1027904e22bf9387f0a5b74" },
                { "ko", "c1123d43aef7c1e408a0c0773dd77f90eab57922ca738d76510ef6c8f4fca18e92bf4f0377d70039919e20a24c188ac55925ab12f9d6784f0e1c487778315a7c" },
                { "lij", "4939ba44ae3fe3e7441131211ef77078e2f02752b196789a2cfcbd254f52d6a7b5a92b7b8751ccbf2ff75ec91a2bac62eed0dd6fbff52afc8202e2831bb465b9" },
                { "lt", "d0825ae700510945e5a9b64521da2549517a4cdef643091a63eadae3d86479b621d49b8b53cd6a829c2d40170eda60e2a78b5740a53fc15cd0d49bd2010a41b0" },
                { "lv", "32125f465c1e3770894d9543a7db6177731b30fed71d170ad0df0239e65d210353e57909fbe9343988f062d905b34dba0a1ac19f27da58d769817b1871dfd505" },
                { "mk", "317e5bf3792c2852261d024b09b283a8ffb73d00ed57a6d4b41cd727ffa92ff38bb36f48d311132341fe29416a3666378b0cf9e598fc7c01536728917dc13c3a" },
                { "mr", "71151077f7a3169da57cdc5cdbf2b4ac9a0e38985efeaa8717dd7cd5b321fa0b169d66592e710380249864afe6970a0979b3241b1d94188219069d0cc4c9b372" },
                { "ms", "4cf9c58d58be2dc9e4334ce4ea1141080aa720707f5fc4df6a6e39432cef5761f82cc39ddb122d51401800bb93de8fa09c3006d316659c8e94c0d77eec15590e" },
                { "my", "8fddf184dddbf50a737eb82b25f0bf22ff08b48b3d9d89d8f7bda51ff422c4cd58c674bf1bc23e6bc21fe94add0dee078998513358d02a91fc5c324ad58e50d5" },
                { "nb-NO", "e3a252bbfb924df5b9e26d523d3751d406be60213452d5cad5837ad54d4c0c21223e76169e84e46504274ba7ee66c62405480c20a074d3897038ed848bffbcb5" },
                { "ne-NP", "f4dae42816427137e4789d043504af3a0b2a9203d7bb6860965bd17f5b3e23820758a2cc079b05fe3f1c7d7e58258dc8a8e9b3edc06f850d2ee7c97062162d82" },
                { "nl", "7115ceaee5cbe91d9a119af2d793090eecbbb5e729746b4b546cdbcf1c3699c1dd2d23c8d69cbad7b8f01a851d452bb85ec411fd8fa20ca69e11db2c0fdca665" },
                { "nn-NO", "042adecb865efd849c8d4e4e63420e06474ec8d11a3221b0a43693772a8edee1f52dfc3a5bc61e8224d0125c1a713d466b4a771460d09ff547d394dd04155f05" },
                { "oc", "163428efec23895172f20dc2fa4c6e46c2b9a936365e9dff3124d3e4f54d3859382ca15a528912df698740e4eb7afcd3414cc1fb1520a78f6b7f6e4f07c27bc3" },
                { "pa-IN", "75828a57cbb7fc27b4fe65e3323adbcbab9c13108dc45ca60cf4198dad59870ee428a1213eb3c7fd1795941f78908396a894ccfbc25a6b8081c0f2ec8930722e" },
                { "pl", "d8051774f2f21a11e943be719c9c6928b7d3faca6cfdd918ffdf970ea570c4ae758b52b92aded1f36774961cc82909442d2766ca0177639c69829e6c088385ce" },
                { "pt-BR", "e9c0ed36e0cb240a856d51c373fdd8381f385c30bcc282f7a451eac57e8a687ef6f3daad337f47a424d4527a7a0ad6783ee5086962fd3de8b25b43d2ec92d6ca" },
                { "pt-PT", "6adbd76f97eb158fbd916320601588a39f8b81debf7ea0825f49000eef939627addc3aa9f886993a87fc0d7235227bb2916e2ccee03f606dfdebe7049eedd6e4" },
                { "rm", "46eea460e8b2262dba3ef038008d331439ec400173a4cbef74ad9515688caa48d929d2c08909b66ac6ebd0c877c9c4a231d473731a134f1238341e4f489d42ef" },
                { "ro", "8145c68591da5a7bcc7f582e0179cf845af7a18e1585e678d9824f32b8d724b139de209576b60da75567d106427be972006ff58eb951360373c44b92dde71084" },
                { "ru", "55c8e01ed14b97822a2f39f2d3e8f51c57e88f6fbe112328b107fc3d55747a00cc3aef15029e7198f15386a1e373691ac80245212d053225e6156b62f7190b43" },
                { "sat", "18fff452ec7e6434c458ed930ba48cc353da8780f068615f74be2a6e6fce9df1d9ffb7fd313efb4afacf2e23ea393f80850f8c0a3af0228588d6a32aaa61f4d7" },
                { "sc", "f5e7353b914b3fd5a5b63a63b4ee28bf44ee33f499a68952b345862d85e4fd814aad64067ee8482fa1ecddc9f17987ddf6ca67be1300392941b87d787dc01b17" },
                { "sco", "e367bc6d073328d47fb82745f5a95a27e6cc761c1d2587cadedb509e070efea6187aaec08800876c34a6de72af6e598ecb09b98131d30f443dffa2e89b62ab3d" },
                { "si", "9d716e772fb385c0b39ba87f59759e586e9cfedf40b64a3ab0839520a98773588f0abcc7e0c511ffe85bab0c3315d175f2314f0a1f58c9d314c5ba3d31bb56a2" },
                { "sk", "09e7a3804bf82eb2459c5041aebaa38a00c154e0156f06ee05612ce48c6f4032259b3f6aeecff1ec922d1cc6f78ee73a8122c71c21bdc88c357d1c4456287ac6" },
                { "sl", "fff96ea7e2d084c894dfeb7bad40f006b74e57950dec1c15d701ec8832c97de5e5c5f3e6650c0efb76eaaeabd61c181add6068a5182aa9986e5e23d32e0aa25c" },
                { "son", "a3ec2aca38d0b2da94ecdb6852257cc168f69d1760451bc3ff4a0a27d80f3936ef340295b1488d299531f37f4accc755e872dff8963e90ad678b9b4a0df50045" },
                { "sq", "4e967e6531faab83068d634530e1fa18e269d5aa078ac8cb4cb673a3efb6dc92714fb07ba7d4b0c78d7f4579ba21b0850af246ccd774abe6c87426fb7c2b95d0" },
                { "sr", "172ef761fe3feada7f59c954ca6503e7268dda174c64adcdf1da11e5f82d89a01845d327392a462aff24991458fdf21063baf83ef216bac3481745f7ce7e078d" },
                { "sv-SE", "1ba035c39a2b96a79442e525a0de76472acbba752fd17616a5b0758926cab2b6075389105a39d4a64f9e62f4cb5bb75697298dffc58d68625c8b9ca44dd523fc" },
                { "szl", "ad07c552f09bd6f286bc3be1eb8a248601704ffa77fb4530f2343b9cd0eb69291ca48fc58e955caa0d2df6890012c20285c211cc512406d947d367f9d9099a0a" },
                { "ta", "df6458e56724dc782bd1925885512567bd347b19b95bfcaaf75e44acad324256f6bde6eec2b52698c69aa22fb33b009c26e27c233adc0ee716a229edf8bda5db" },
                { "te", "3aab9426582f950ca10247f3bfc4b05344b44f3ab80ac96cb8479b0948c4d3414008deeea3ccfc2a1085b0b655a3f9e8ce39f239ff462efede6767952bb1da71" },
                { "tg", "fae5696b6d5883ba43527535cfe26e794dc5b1b0807fd2754853be02864a05f4cb1d5ddea16f30d84f923035b18cbfb0567e05d689acd609ec0667f0ccfd1cd5" },
                { "th", "18ba1ce50f088791a2b8e04c591ca6f2dd3e63865fb61999a97933458290c84653c0be775d4fa3cacbd67ce7c0a2b9195c96e4488e93afb5191eaa631cd5f4d5" },
                { "tl", "73e33455e7612bb1151a82de638e3ef12fbf6a54a3095100e109563ce3f7630b83350063ad229a507e3227d9877126aca4bbf530bddd7fa99ceca9c1517d0e71" },
                { "tr", "3141a70d4a7685b40b52cc1811c297b0ff6192e571d024126868f7cb44ad80366459b5dca701f4cb2bccea9aaa6b5ab5ab1339a5a3cec2517b5ce65dfa549c4a" },
                { "trs", "3640daf73b0848a780550c741891b9dcc15cec44013a78248e4d29b8c85193a2b79bd9bb00a869da43c9d850bdbd2b478d42764586b639d9ff64e28dccd12f17" },
                { "uk", "2f15270700cf2369316bdf0b2cb4f1bb412918180b195274422c4cd86a924e722b1459b245bc55be943d8c3a525ff3e513a64a3854ebd57126fbf0adeb8e0ba6" },
                { "ur", "b7e4495259b57da90391a203ef7c2af91d024174e32f896e208052258b1d15b8ea4699f101a875b8d511ee6c8abeb21edbe58a63a144bbf013fb58db9dcbd9df" },
                { "uz", "886bc2e742c007cb607dd56ddc5ff56740b3f5d48485bd494753591f67bc5bd74bdc8ec1cc131b66b11f4d8a9bbab1dcd2fe287f75d3eac4d3800c15b11d99a6" },
                { "vi", "05ae5fa15b1e7d7f27b10eedb61fc3a7ee87be49b1d84283fab104a797ed57b3a96b1a61bd20375aac5943752c757d887f75da4b5b063c5218da27bc2ea470c9" },
                { "xh", "f67b19c3405003e367807c6e942d20b3e2155a01b6307e2954133142a1737c0036b6a48dd2300a867f6924c28eb1dcb38a4fe3fb601fc311b1875ebd9dc72966" },
                { "zh-CN", "104725cade891bec5054b5fc0532e26af58d11eb0acca7be661d6262ec4ce56e218e5a781a155383d7cb7338c318c8fddd2d331de07ec9f3da218cbfe5413d7d" },
                { "zh-TW", "e908a9998e9852e8e4c06cefcb5cbb61faa1c354850f4b775dd2a3e735db08d6ee6f00d1c19a6150dd26842b5e6c0e501782b3c76f5d1deacf63d78217426565" }
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
            const string knownVersion = "125.0.2";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
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
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
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

            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
        }


        /// <summary>
        /// Determines whether or not the method searchForNewer() is implemented.
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
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
