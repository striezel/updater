/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024  Dirk Stolle

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
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Firefox Extended Support Release
    /// </summary>
    public class FirefoxESR : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxESR class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "128.3.1";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
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
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.3.1esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "1ec08e34fa9e705f64719b381de799400ed65bd081d1eb26ff47803d4d2749784515856fab7d28ff096c0ba96f7618e0ecd3d936793abed0dc6bb464165fc1d4" },
                { "af", "8e0f59036ee86cf78b1027eae6499b79fd9f1a1c8822b781f21a0f9ef0c6d97d38e496cfc9bf4e427e420bfd8038edc1cb491726eabe3082ae74d933b35ef2af" },
                { "an", "25143756a075cb701781df97aa1b1307104bc7594645f9927773cd65cf6e9bcc5ca65e691fd017d6d70033be63fb99651e723aec0d515898b65cdf3949308cda" },
                { "ar", "88b75d6c8417c8e24aef60c3fbf431aeaa55452e81257c0eacee39a0a3c59d016f875d1da4007858cd900b7cc3d6979d8d7b952ab6915fc71c7e88e55d189edf" },
                { "ast", "1c4cbda4e6e2f6424ec435fe1d533f6ba6035923c6640e46054a03ddc376ac40bb274aa19123ddc578f4ee87531f85d5354f506fb5d7cfedd759ebe6166241ce" },
                { "az", "b153fe7a639f0a06dee081dbd6dd9be55e94b6f6db138290f3f97a388f4e07b0d991b081524edd6949c6ee363750886de5b42a11e88e619587216bbc5901a42a" },
                { "be", "544245e96b2c3e09b85cf9f5649bc4b606c9b54793650f141a5c39f7e092054086a05ccb851e08324cac339bacea5ea82961bc8ba01fafb37c131cd1246d6ac2" },
                { "bg", "266262d0420cc48bac6b2e44450c9b80ee3dafa8e33c48631fc40ba7683d175858614fd9b2097ba0bd50a1a8f3ff54cb99eb5f07cf25c6cad72d64c78f6c371e" },
                { "bn", "346d5720fa9ccfa15e47562dfb4b02d994a12232ddbe3fce636e3d7a2d906f9b13288505ee4fbbc31e0b28d2cde86654c9027a020c6fb5fd53a198357f9dba6d" },
                { "br", "b330cf93dc618f3fb9df3f1da08d3d5327f633061e319c2852d08bd5f12441557d8755b56a6843fcca306828524bdaf38462008d44d0396aedcba4c7c671dc0a" },
                { "bs", "73bc881656eb2c1638b82e9241d1799ff2002aafc733990d80227f77fd6dc9fd839df4e86e2445e0dd2ec7abc8e4ba9483a019c4e6bfb8e8d2c0bedd7da5f5a2" },
                { "ca", "31f2ba24255e71fe6ba4fffbfee1fc99bf7390a6220e22888e426c192e54c06ec30430c0cb82246cf98995cf2e8d53f61669fa6eb4297c1faaf0b7f4af4f97f0" },
                { "cak", "ea5190d6957447b1765ec7b26110ed4acbec2c6f52021d4d416f8512d3990864fd5d945ae59336449a2082fea5bd718bdba799edbd8a711edc2a689ff4b6c76f" },
                { "cs", "a5ea2da2153423f6a65fb3d9e40b210c8c9429f2cdd82e29ea9252529d1cc4a5b2eaf7ae5b12393688e19215b0721ef1e6bf5d8a817f8b424685924b2ffbb77f" },
                { "cy", "fedd7a843a044ca092fb20d15ab70ce39e0b18b2b60b57ba3b0c78217d5e94efd5bb12dd39e1deea071feafe74454e20a11c14c943413396579e56f77637b950" },
                { "da", "82020239705c639b39275b50635d0326936724ab3af0d205b1bca75e6e87a03a853136b0fe7159c24f6f56b7a5059f6dd49bf7e554a14190e62224396d16bda1" },
                { "de", "e7a2260faa486a31dd9848a0bc75eac18e3eb36221df35a9640a4e2b902f6c18bf211a74b2853fafd41bb141257a4636f202094e0950ee970bda1bb787cc9520" },
                { "dsb", "15abe2b1e7c8d4b7a7d2920a9f1f7806b4e94dbfc567061f4a863d89fece01d640066a8d5ed767e179276e0855c18fa4cd102fe32cc6f6c13f3325f22fe943ea" },
                { "el", "076080e9d743d11cf1734c1bc330f643b87fd3b5d45289ac32b94412fc0de99003ddf28ece87c0d66d7549c9da7ba40b9732950038d2614c8e53f02a45e37614" },
                { "en-CA", "86693a052df2ab82fd642997bed57a53c578a4752b56af2618de3e963cd4086640bc37c341c795902dfb3b57d440d0c55f64445f7981464a61a0a8f355b149a9" },
                { "en-GB", "eff0732fe98a2d35ce672e8238bf1d8d6327d88acd2fca5baa75582e1e168b1acd150129d7d4375d823a329733defbee7255ada106c8b2a7a837acfcdebdd776" },
                { "en-US", "f595b91efd8dfc0a80211788f7ee403f43a366a8bc044e4fbde6e2030d321b3baa4ad48bd9dd457329b0036eb93ed1cd0aee838b31b6c98047138c62c4ca97c9" },
                { "eo", "8aa2819c2e06b597de4774420467db004dd61e62f0796851f22de9c41a36f6365267ca02b6e58beeba75c9274c9b083d04cc87bf7e8066a3d386703f8f029263" },
                { "es-AR", "f62d4c1914faf0a3b8769de7f4a3856b34098372e00a95bee352fef9be3a02a880fe3d384859e9bcd43ddc4015d8269152542a8b39d818bde37047af737b37fe" },
                { "es-CL", "c2365f348ceaa4c00edbeafc1bb1dcf2b3c0c4798b19d93543d409a8487211511e9fab2e7fdf69066a44bf38f0d43495adfdcc031871e1ffc100fad031ed9df6" },
                { "es-ES", "47969dcd273fe7a3d05bf2200b380c4cc5c47a6b25b2c9e140022319f537c80a07038bf78d9f4d4e0478c2becb8819d87b79ceb272d6c013763eb6e91ae9a856" },
                { "es-MX", "8cd68d4c87c8ae1325e34ed1ed7755d9dc7c6566892682fb505a17eb2e507c51823480af1831be1f2f0f4e99c8220f629fa67ef68dfcdebe220af37f3a2f5fd3" },
                { "et", "e8e25c0b119489c35c301879b1333fcdb32e3c92ec314448f7be891009d07f753fa679bf0a826d5193c24897c1d1d0c400cd586cfb7650682469ba853e9e35ac" },
                { "eu", "2b375580465067ebeabaf67fa2b6922077cab1f48417b073e95ee3423052a9e375bf1b6987b24e33d124ae172384f5f96119a69be0b994db11a71a62275cc685" },
                { "fa", "7cabf747841a12c168bf0f63c772923872e581b91d4aa12a649f52e010502be08e64c2bfce874ccfc8c06415948751d4370a64e832d7d8a50598b88d0d757e67" },
                { "ff", "cf0dc7ea8496905c8a287c5252637a0127f6285db4e88bda4d5b948017221403558e8f11f703ec9bec0ce7afe72e9d4d94e86e30be9a5eee3d55277dcb159340" },
                { "fi", "45abb12a4d45c650ceb04a8f3f91ae2e60b13b8df5532bcd4177faa2fb64ba98b9d3bd58e83046ea2ab62db5bf5f2995105628cb1bb89981b1f3d639b8afce12" },
                { "fr", "6801dd297040147032929b198b33e26505ee4c42b4cb2b72a46fec4ab6af5874eebbdb1ee167b2cd14f7d8439f7f7ec69d0404da74f946c1f243964b9da1ab91" },
                { "fur", "e7d86d3c91c023badb52186ea32bdbfd6805386b78d0500c72e5f60329a3b43e1ac1c33ca28e127ef0b80b04300019a98878b8b9a334cc7ab0751bdcd448987f" },
                { "fy-NL", "3edf71162468ce323503f382341e74704c94a7ff1f148c2d936e491d77d290f687e8c316532a1e98045d241be01514191e91227ba57420eb4cd6f3cafd48d019" },
                { "ga-IE", "1baa13e222358a928d05346ca8ec2fd8a51ac83635195d3959b94eb663b28845882dc0c5c25e27d508ab0a845c4269930c09e3bed96fbed0cdb0e3334a6f3f1a" },
                { "gd", "aac8b42c98bf0a3e76e37ca1785a897ea128ac88d4a8b8d4c949d6b917cf874169936dcf7531a002f3d4bf805cd458d865625d3c6f11221b7ef028f71624dafe" },
                { "gl", "caeccd1711d86c536f97d9da9611b2f9d0f0ff1772164ff0fab76b313160d5499d28d7e69256ce4e5b5d8855de6e69562427395243a39e3823bf468feec149f1" },
                { "gn", "be7ed03b30f15ef11da34b5464939347d7cbe9dc93235b7fa82e1db0d7e123c4a96a483fdf73bf96e90ede43f4e25c8b86e83d9b91a20b40fdd35543b79ac68a" },
                { "gu-IN", "b2c827871942de66d700469fd32c16fb9ca560c52d137f07ce8c1d0bfadcb0641af923cb3f923bca01cd4816c58387b3f5fac8a6f124650e93790026d6b2d8a5" },
                { "he", "3ed0ed8b3f295854919e27625f8f40644c513d8a89db18558dc4f05da627100946daced03c6c98889d4e97f6e71b4e28688db7ae7b8d9d266baeef899779ff01" },
                { "hi-IN", "fbaf5d247f554c1876c2d6302ed6c31288f98b1477d6bac9de949d6ff91146031f529d832b595264412d5ac37e8bd6c3f0001421a1c43b7645aee2f18225eaf5" },
                { "hr", "18a621afca132317b137e4f8af03d0e5c4a98625e7be18808d4846da25c52eb4d0f936fcb4d4dc970704c062f2c5b74a146a9ccff2e0ce094f9bddb256491790" },
                { "hsb", "d270be0e05b3a75f9b412fc1e2f3e6f77ae43240b74ca96237ce32016eaf67e9ede89e2326728c3ff57fe3a5a8a7a2dab316f3474f52fcd160620197b24a8441" },
                { "hu", "0105735aff1d23112d25a2a82a67591ee4c220e21a8bfb3937da59e42d6b4fb9d5d7a8934652cfa64e711985941a1e197397e9f1ce5a9aab9201b938ebcdfbc5" },
                { "hy-AM", "c4e1d3b24f4667208e9c90f16e456284cad00858c6d5e0eca9002ff1a8f49efd546129d357024f6897038e6afd41d249d4982822c0b39c63b62870638a2f5a2b" },
                { "ia", "d1f84254b40a17f209efb2f2d6194c7cfbe0723ac150f411fb8b6b37ddaed1eb5943a744f595d783424496363797d7bc6147cbec8393f4ed71234a0a90b0f6ae" },
                { "id", "ecd513e7e6513dd7f6ceb4dd713d7af61b13affb210e3bfbfcfcf45286aca2b7e3744b5fd6b632672225938c61b9fc3389882a81d7b7012e49366c664338159d" },
                { "is", "985012966c22c0a2f9983041cd8b40e97ef2a683949c92d599abc86447116ae9a0da44a06b393045d13c766de2551b2b55a5a1c04272c9fc9c456194f65ee5bd" },
                { "it", "5cc88ba1991c2a0bb462d81ce3f10ed3a3b0c12dc603a48a9b9bfe27b63f1c7ae2c5487706495fb4bcad912008edb2ec47fdd1534d609db7d4b44130f05b7280" },
                { "ja", "0880836202637fd1ec1ceb1fbc3ecb58d60af07497e443232ec8ba0f782e3b34d707d6f9ad646151fb5e56d8d7b1184d51778dd539ac55d84f2fe8928e9081f7" },
                { "ka", "51ecb405a0b87820d6e9cf9d474ce37cb151b418f82a703f8f4ae4b2063ef4ccc87c5f57511392f81237dc3ef0e1f7abceaf8a5e04b43fc2f843d3a66596ec84" },
                { "kab", "6a855ff1b836b6560e79ee6b7b165fa4c80787f6f5cfaf5ee469e6bfd77f0816394aa0b045dd832477c1df9dba42e42b3b41efe3236d396cf8df472c8448725a" },
                { "kk", "e3d9d22c274799dabf20e7a68c42fc8bdb7a701b3a2ebd8a3aad351dd6486730ac8c2ceb1e469a94f25a4f39b529a6091f1865343ac9782592564939eeee2ed7" },
                { "km", "345cf1cd899eec1ae0b0a68fc7fa245e6dba8d45095693075b222a6aa7d75d9ea35e42a22e8e10049dd777ade4f3752ff7672e25691a917494d95a5842e35f21" },
                { "kn", "0b742a454d3df2574252e32ecb0fcdff6913c83bd2809f89f1e108633f806d3aa0ea64818857832e75af3c3a7daa3354401b714fbab273992b1e98c1cae0e6a3" },
                { "ko", "f952bd7238008331f3ed88d91b457836eb223d8bd7938a5e34dc836da7220bdf2124e40165f3529ffc9a9528e0df09fe81752c531b992b4a078288eb20ce006e" },
                { "lij", "5e14094a7f0a4d29c9b4a031602c2fc70d4bd545ebbba5c3bed7c4dd855f54d02c6a34f1c483745c85c1c2c197326eafd79ba396ed88dea51f1d63ee4ca600b9" },
                { "lt", "d3c64cf7ad0be7f2f43a4f45a5dba0243b5120198843a6596eb9fc217daec39ed4939af3a135c2343ace707575abe1fd544a3dff5b9e9f61f4fcfc050be0f7a2" },
                { "lv", "7c023dab268a4efe39250473c4bb3f4c108dd1b2afc71d51c4e4d40ac2f54a61ad5bb3216256258cd12872556abef840ee055be816f552e570b62a61712aa5e8" },
                { "mk", "ca9d9572b16ef951284a42dce7cb5aff86a419361389c622f1912294b4ff111bd4b4de90c27be3b851ccb3ca8170486b095cf9ad067df13d9ca62757ee2d305d" },
                { "mr", "acdab491f8e00b3cc83878059d1d33642298f7e35a329f433d8898993885dbd21e49f4a1b13c90877f215eefa2a4e45e48f723312c44b3ade5fd96785f77a043" },
                { "ms", "17092db298eb78d85a82c3295471e381bb395e4d35fd4e8fca3c3b6a620fbd7485326bec8c131c697dce9b19d1e7745186684e83a31a77f17375fb7ccabb113d" },
                { "my", "ec42cc8f4b875479bb4043436483ea3174cc82d6d05886256d776a7fd45844702758d31ebfa869c5991200832eb9ea22e610082bd47a2c4ffa79acb6ae9893dd" },
                { "nb-NO", "2ebe30f9dfab9ae63dc80b0bf7b2e2ace0351b0da7f5f4d3c43c6a0ebba37932848e679c3020577acaa1df86f4c229e4b5b887a216f90a928fc77ff489a6d88f" },
                { "ne-NP", "760043e94b72954e5cb8959928af0db985053b8ba3055c7ad7f46c1cbb0790f7b92be4b9d9291cf2d9c3131882ba21ccbd5250557a4c0bc56059af12c6671705" },
                { "nl", "8579d069281a6b11cc53af42dca28ee1ef8447453f3618dd54257a560b124ced3fad0d1f1531072754a50c9998f3e8947e9ce57ac62c179f9bfa2cadaedc0235" },
                { "nn-NO", "686d6367aa11f985948f53f5b630f92e309f9bf2ca70b631032017eecb6d5708b813d5fa102f1772a8b7b755035912e8627465dc7be5222b8f5bc60deaa0842c" },
                { "oc", "f928a973f0b6b3c696f6af5444c67b8c2ee7e6acdefdc290d0ddc75d551a4338ca2763afae9919c743a9759ec694d014fd6cbe7f092620aeebb03f50a2c57edf" },
                { "pa-IN", "437fb5d766036f657328c14aee06ed0c5f23793fa2497389e0aef74d9ded8c31b3c7046699561372afaf360def082f69981dd58708e06ad5cf043ea36e084afb" },
                { "pl", "73b427771b53c0a7f2c7e56ac471f469bf529a91321e7edea2f904eed2cfc45731e8aa25977edb019a67fb530ff48c02ffc84d83a13a37b7bacfa9476d17eb60" },
                { "pt-BR", "af33464d6dfae7667f3b3a2d9c96e31ad5301292d8edb2cffee87a36ba8b823b8828b028342359c02afcb03aa6c7bcf62bfe2c50eda3ac737d13aeea32f36f05" },
                { "pt-PT", "0906038de222652f726dea5b99b98ed1cd6ca7d1a508f4d1dc4f58cedbe39149c704b8fa903030c7e661193d40b625b5b6aae53d23a42c85d34f0dd5b8bbce75" },
                { "rm", "5054343535ca81f1bf3e561c72d4750f21ae9c11e152367e6e2c2843c392c55d5ae6e96500c7cf5e8b93d33b7be43f68b7dacfa259c2a6073c7fb7dbcd634f43" },
                { "ro", "c48fbf160663a651410a6a61bacb8f390073e7339bf87557d3b893c3a44190ec66650aeb06b21c5c432713e5f622a1fafb32157c656d23c77c1137a95514e0f3" },
                { "ru", "4f4bd6209848f168181f023dceeff41e22886a6e43514df0e1c8a8ce0269ccfa34c3c80689f9a2eaf592de1fee6fc07050c2bce25608b1be2b30fbd36c278f1c" },
                { "sat", "dc2e97ccbb8ee07280ff17421b719f56e7156b2c54429495c1151bb9ff1ced38b04742cb13c0191ec8de0e5e61903ea94f03e05df7d901a0b521117dc7af92f1" },
                { "sc", "310b226ce5dcdd7b7256f70d99e513349e8fdc58b10f359bc13b0a12a094f2d90a2582c2d35f211d0065564e9f4b6fdf0aa53705abc6e742b4065a612ab939d2" },
                { "sco", "5905058cf78bae801579b6bcd8cc8b3a77febb2f30103181aadfc2fea3d7a611e0504d79cbfe590a4bf7d0d5af4d409966f027609fd238a2ec0d49262215ba0d" },
                { "si", "b2e07df3f703501d04df1519c6dcaaa12008b76ce7f04d17625fe59f0f4d8610b86c87cd3258d6769a1ffe7de6d2459fa6566e5df8dadc49a770c4dd9430a503" },
                { "sk", "f077ec2cd4d78fc7fc9f6d1174a62c93e9a3a8fc9139714adf6e7d127ec7f1f235806acb165187ad0b7ce14c7440c14b2b43c48126b0e896416b4e12f5ffb2b0" },
                { "skr", "7b6cd737c8f0ea7d8af9cce4bcd06e8f2f9703f70e5e42a19b066d6f7d6a5aa5ffd2d128ae1d988362a2f39ebf66c8c8d244689eae07ae5494c3ba6f538a1efd" },
                { "sl", "d98030eaa498c9a7d5ba6ac66e80110d0eebaaecbf91317b6c2f0964b9bfa8e0586c890864a4b83dc41990d3fa32385480f372aa1e6f4457da688c08de59fbb9" },
                { "son", "d6ace5baf83bf4c68b75221adc521e07a92c14e7dc1cf715a30910be581e193b406b0e569cffc80430eb730d774718c3decca04b0313eb8cc1baff557d5a22e9" },
                { "sq", "fb789007822b3eb8231259da2d9a3a2d92271d778b332f7deb47589bfc560e88eb827f21e77e3db1c0c97d8008e00dfe7e944f1205704d5e99ae8b5566a2900e" },
                { "sr", "3df63a7f077957f8e432511009602f9e10f9462c6059e749bc91a8203de1321e6213bed8568cca1e8e410587d4d5f38eb6a896f6b10e211a76ba939bba5ef099" },
                { "sv-SE", "93b03f7d86a5b34133ee5f896d7c26b3575d8f05adc7639844779811040fc4f533e8599c91a41a12f8db22fc1cf3b7c1046659ae62215317b25753c24c4a327c" },
                { "szl", "0365127e3c1f31b402b8b0949bb7028e4d7302ef713142d66901a69f097f7e0411efdaee35fa8e98bfd627d0ac0e3ef4b662a56e655abc4262c7b6105c8adfaf" },
                { "ta", "c0633b7a9346256e0651843063151940fb7946215369fa19f4d8eb4b61ceb08733834af9983e33c305cc594395bbc7ea429464bd28fd0cddd4ada2747d58b26c" },
                { "te", "65a0851a95aa1be08f8f6f1312e677bb048d19e148d6b6e14e412a788585fc1ed14db604c8a922c969f886c6b6e2942d71a7e95f5f615d36504275629eb011c1" },
                { "tg", "b869278a864109efcdada0439e46bef6fc97310dd0f5fd352a598064e560dbd6f6a0c2e2d98d8ed0cb3251dc5fd7b61ef087fb0cd65d87121b9c990e2a383cf8" },
                { "th", "a8f5b225b8f453965077dfd0096e9c4eb487966eda4cefd6de3aa1cc7bac950c783f271a4db784082dd99f469c5d70a1026ca6f27280e54ea078377de1721871" },
                { "tl", "27e2b13f3ffc74b486ccf90260c30b3153ebc0f5fc6cd2b9ab43a7fd10b8bc18724fe474e9ab823e4ac9d7c92d903b4f178aa83dd21acc92bc6ab03871576d24" },
                { "tr", "70ea9751214fc535ddc7c1fa8e29a780be39b9932e49678fe5439bafcadbb905f76a17725f73427f5ee77b1a34757643f3b6cf22114835e2a2a62420085ebe17" },
                { "trs", "ead093d6ac478ce1ecfcc678ce3342cf4124550d307e0fcd86061068250e5732a1ef9a7d5090c99188495cc6d1ac923b3f2ca1c002fab31fc35fb1cb9462c122" },
                { "uk", "bda1715a3a5fbea9415b3d797f2f6ca2626d7e18b37ab877d746384e66b3b7fc617eb9ccb90dae43c0f86d4b19565e60ae4eee71e3c8e9604f116077dfa11cc6" },
                { "ur", "c25fad7af7a5477233ececfd945d26010070b558ab688c0ba522b03a7d72b0a4ae55642fda65bc7969781cb20458d78f9b407d4166b538fbc49ec57337b8f65b" },
                { "uz", "0f4689e858908188beab54785461036b1e4fb94758dac78f09361bd343cd5958b0ddb1cc18304296732932d2a37f252525e616ce451b90ae22c001c76d33e097" },
                { "vi", "409e2d91b0f30de9601b2ca6a0727f4273698f18aca9755d3e039ebd53b4f16b337ab7367eb4fb9a747362aa3b0eced11c37d4bf2364e976ab5f3e7b3b35cbd3" },
                { "xh", "82a387863d26f613378451fd67ff044e6e02f45364729dc6fd1dc4512bbd0561d42f53d0a8bb12efca313d8d81901291875d4c7df8734d21599212b7f8f7f85f" },
                { "zh-CN", "48341cac1a233a5f56030ddb53d57723ec905508e8737e034905086a9ac9d50bba76c832a34db0380d3d0040dc187a9b3345fc75f5837adbf6aa516a43fba10c" },
                { "zh-TW", "46bfd62e0f3a1e98c7c2d5b4b57add2ac310060cb2dfe119639ffca999f6d355cf9dff0a811ac6f8a3e9ea09be5f13a35311fd2020ce6aff6b96efd2ec793a2f" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.3.1esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "89062e9dfa3a3c544ee350fa670424657b97aab20e8649c0fd8fcdc50f8d378723423b5ddd31ea785d5d96fde7fa92f448f92d6f4da7b1a91f1febb112b58712" },
                { "af", "c36aa455873fc27ed8e63944fde2127343c9a2f26531c1b9936b24a218d1b7b759586c013c1eda196e5ec7b374e4240cb2b016229cbd75c49929084306c09b67" },
                { "an", "35c666ff3de4f6bfcae605a13177f3b46cd41b74b5354fe5c00da8f3cb2296c62cd92192595eb9c2348fa054f53d7f1cc35f729981db8a3e95ad21026eb1b16d" },
                { "ar", "08e933cd6be5c27c1e104575b4816ec074843e552e359a28d8870a8bd7bc0b2afd3bf4b53368dd54099539150f2353598e322b8c851eaf4409007c6532e25e28" },
                { "ast", "16be1b869e4612220f94a63479b01f6f4f5661e2fa3a0de18695812f0428e00aa5a0da9ce6abf5b1bab74cae6363d7aefe05b753f482c06f9167c74b51921d63" },
                { "az", "4f2a41126fd7eb4dd81be16e96cc94362bcf9f6131d54d8ec353dfc656ee3e28f3e82c54a99d881cb59b7ba465e0aecffa7f9605005eb04e6cb167253eb9f074" },
                { "be", "140821298c841e64148c62be74af4ecf02ba76520e981121abe54ad38e7dbf55a40761e23df06019f135ce4911afd45f66cc157f04e3276b4af5e2e6dc04f613" },
                { "bg", "21519dd36f1dd90bf6a7f8ca31721ba7077faec21c2383de16cd8e158b855a7227b5d6c9a531c8738c668ab7b4324496ddef09db9d101ca7d26ad6a0891387c8" },
                { "bn", "c26eebc09777988187e7040f1734d70b9eb52f7276c4c68505d528050d96c8c52bee75ddcd34aa20822ddc86f186aa7f76639058bf896ac6425d708d0d19e138" },
                { "br", "225da2b59b3f183b3e4ece406761e02efc3b1d3c357bff316de78f6533066575ab787fa0a5e9be34e65cff4de5925c03f036440372550f4856571f541c1afb02" },
                { "bs", "3a5243976361961d4b69a8cb88c13b151602ff0808a52c0cc746d8496d642c63ae523040bfdf180ac90d4180dc9fe92197f552a3b82213b7e716e4da652baa48" },
                { "ca", "3ed892c4c80ae9a86bc7c7196047b3b9c6a0da68a5c247fd783cace57b4f11943df1022fa105afc7657f1d64f4f583a608ce655874de0552cd19c6376fd234e2" },
                { "cak", "0697f44e6deca908642f896092d215e1a84404fb1a2c9a39c8a474d1e65f98c85d4494005d50aa04fa72da594ff4910f498b5a0826d07bc9571e16ec8f566bb5" },
                { "cs", "314efa251bc025004707c1b8ba7f25ab4cccfa794ca6974bd1c2a5624543b17fcc072b0cf7f48c832bf886ecbe5c58279bee77d98df56f2d217add5f4a879cf3" },
                { "cy", "8c84c73232a8cc0cd93eb1708b46d0a2c971ab7d0de0ab0b226afd339dcd64d5929f371aab36f20cb4dfa82b8309302a7c89e1f543d9eb878d4712ff21568cd7" },
                { "da", "3bf587bd3fc151168e1bea6f7418548af643838a4be61c72f5d0854faeb0267d20e23768f621719bd764caf1bf620699050881b8284e6b1441ed4be3ccf254d0" },
                { "de", "8b020e1c19575cfa324fdd1b850b878a13666decb7504e2686f6fe995ba4ad9a6f22aecf1bf951089870d9ae335aa8f1ccd4b62eb53ea23e221cfccb93aad353" },
                { "dsb", "4a3f92f372c3ed1a162555c8cd3f27ca18a4d62136553db33332b50c6d99609ddbf51deeb7a513675e215b801ffbac19b400379bdbf78aa11b9f7696ab7abc2d" },
                { "el", "58ac243853da39a2b192a6ddabc6cf5a2e2493ccb3bb28bb85f2ccb58f11ab92ed0de8efd63b71fb1d2a38ae40cc0bf0b001186cc8134b39dd318445f660d613" },
                { "en-CA", "c1a2244f77613121d3cde6151429ff971d79cd243ba380d166358ebd25bd469f0b82ad5c803fe5d50248befa281614eb0c0e92a4441a1e0bd9243f4831f733c7" },
                { "en-GB", "20956b97c7d28c53a87893d3bc9567d2cec3a6ec3d366260c45b23e3eb7aadcf39aeb3ff2da2a86e390988b3c83756ddb1b7fbd1535b19cbfa23ddb32fcb6aec" },
                { "en-US", "84ee9471f71b88878bcfda02eca9815e67c2cce0256c8e4a25a0e571d89966aab54ef2b0d1dc75723f8371ae837458651d2a587d59d9db3346256d7284d6844d" },
                { "eo", "24f183597f5fc93575704129edd28cb528e62d579f1afaaa56c6315128644be6774f9a58e3adf965724bb07ee5643a2d1fa97f0caa2a3006e277aa9ac798a6e3" },
                { "es-AR", "939b7b14bcd29bafe088dd8042527349aea2246cb6eb92de45086adfeb7e1718b3033aa2c4853e3809ca0a79f6d3a7ac5dc123898924990aad63e2bdedbe4df8" },
                { "es-CL", "733bef98e2bdcf2021e91972bd9d8f9cf313a3235ffeda03e317e24cbba4f29bf26085a6aaf51f355b4a01ab318f8ced450836e25a51e44b0836e0d4ac1dc66d" },
                { "es-ES", "a80a5aa1b50f7ffcdb1241f1d53c89adecfbb1d0ca4eca94e86f0882bcb4903b14ef185966e0e83b765741f82fd521e9fd3dc4a93837fb4797a039254367fcf4" },
                { "es-MX", "8da2816658662b00efd68820023329e26807c3108ced69c197e884817e57d5bd737d76b4b5b3f691631566a1b95352a9b16ea97750e86a0fbb3cb62f48857d9c" },
                { "et", "a6716959c26b8bee445e8a60c8c900bf9187ad306fa2ce2414b6e1bc183825b06c334a751c0f65f96904e158e566c738f3f27f488d1e7d604de5471e95188db8" },
                { "eu", "fe3ff9d561fe9b7d3aec75e4b1cf7e536474d71894bddc55d6c680b53ede534b30cbd3dfde188eed54be260e42df10d30c2039aaaea8ac19676f51e54193d349" },
                { "fa", "e4ad8263c9bd205aae2f700125b14e691cf7e574876399ad064a679ef884ac83fef7477fadc44fd18395ba0e02939445915f5b3daac7c9e10670c7a08d4decd8" },
                { "ff", "37db6c0d8cae8d442f6bf2291964fbe2885f7a7a29bbd35716cb7338060b75943b7a4b6179b9a3c163aaff863de2523495c3d473fac1b49248e7c62ab6817f48" },
                { "fi", "56d8f66b54f7700202ee9ced1b6b8efbec69fa5d8a55deafab14ffb1b87b8626b147ba0e06870951892bffd7cf216cc7c95ef3a15c6a8ab571391462f50b578b" },
                { "fr", "f753f97a73df41d886cc48ca049dec911e4e958a6c55ad8293645ca1eadf9813b367a3f4727a735bea3606197fe4d8de8761fa89aec938ef4b62343658fdbebd" },
                { "fur", "747033bafed06e17db14b93ff926f82b2498c37100d62796d397ca63ddac5caa9c3bd006cd4fa1a20cd699d73bb53f52212e00132e6294ea5f7df9783153967d" },
                { "fy-NL", "95bf22998f580301f0f66a53d0895c3a9640e6f8b3640c3b043a484c81f0623caf818ff1dfdaca572e37e11331572d5b43918a7ae749d61ee7ccc0f24f0c5608" },
                { "ga-IE", "2463d653eabb35fdab9b3e4fbe67a34b7a324d15d5445f85853fcf4ac5bc56ffa10696b53be497fea28948b4333f6de26410dce53acd0bfc5ff4aa4b0c2cc597" },
                { "gd", "ab950442212e0a9d70ffc31f8c902cafb70806e2e835e127b6753dcb3496636634192c9a77e812be94745dccf801c527f8ec5206584fcf15f01cd03fca920410" },
                { "gl", "1797cf56f73369e8c639e85b8276ace1229b347b2771ae7d204378a45c76a7cd03795d4af9a8935bbcc64285e4d072a8c4f307df918347bbae3b63681b8d6653" },
                { "gn", "f3c3da82b750c6368871a6335bdd86df054f207a2bbf2fc0938b11a8cce6b816dcb9e30d4d67bac0271fceb11c7399e662f758a2a3afe7cec014d7fb77753f0b" },
                { "gu-IN", "d73b716010867188a21c0d06a3ff2762ac9aa706d60b4f6206f986ab9db06f5b0cbd2023f58a38b1e56aa67b74a151c1061205bd5593f331d46ff4e2536beddf" },
                { "he", "9a774e3f90fbc8c8ca4237dccadf9cabf1f7a6e18239439aac78611dff1b500cc67a6ff9010772e7ee3c02b2b59d47cd7f43a1cfceb325345dde4351978bf270" },
                { "hi-IN", "1d1e0cac527514c9800d7e1fd5de20c74ce3e3d4a9ce80cd756ca184337483e060eee09a9d5d3bf566d7e83029b564f88b4b6ebe46610de3169397061dc0ae86" },
                { "hr", "d7c38152c91ca06d10dd953b36d423314b37f5bf5caddb2e9c5dc6cf834a0625be8b4fdb3b15860ebe0ca43ed76d6189e0e07bc77a9898d514915e9ffb5eca6e" },
                { "hsb", "c6cfca48cfea696b11b7e1ca173ea0ecfe70ab37fdbce0598a8e68e8fa270601cf888abb82872699d58758856e09b5a46b81a68805a672e12f158cd7a7aa4354" },
                { "hu", "9b749bd49515d1985276c7364b55a615c7150f0bccb7b7027fc90379ce479887fde69badf6fb5e08b4749482df56b574c3a486b984c2be430bb782c75e079c6e" },
                { "hy-AM", "2a4353764819e32f3715f92167eddbc3137030e3a27538fef0a6eb3bbddb7b8aeb1e9d845ab244f5b74c29f47e2641e7c7fff1c61c9664773714f94ea95c833e" },
                { "ia", "9ce346c819ae01cf8a635ee7ede6d7acfe9755863121d0bedc53fe21ce0610015bacf33a77e6f634b123bb4389eefd2b5a729a60abcf17a40ee3d6e5880f4284" },
                { "id", "6d6f0f5e708300b859c649063d20e4d536af4b96320a329127dc8835bb536d0accce59572662c27b2b1fc5f7dfaefa596be6e12bdddd1afbf80c3caec101b3ca" },
                { "is", "e57ea2a18aae53d72d5f76e7e93db60f2add4eb0d389fc7ffb7ff2f55a17a6515d38c55072b0dc56a717c578f49cb5e7aa8ca21691e0fa07a51c198e002a16ea" },
                { "it", "a1d0f7c2e9d066872e17c87586a3baf22a53016be90093dd6ef0b255c1a1b1f2492637dc911404765fd858ef8c67e9b096209458f54b9deb57cc5b9fc031d2e1" },
                { "ja", "d41834aa0bd6c11c233c193ffdc35643d6e4ed5b6510b578a2b9e63255629c8073b7aa2b06e870651e074ef2d0bee8d379c0080020ff1ed80c44050e1ceba11f" },
                { "ka", "238e7eec85257f754a8389cdc0dc6b352aed1b88aebaac1d1d9fdc18220ff94642ab5a937bea1fb2e446bf874039f1eb75ff740cdaf24e04a461032dc39bf42c" },
                { "kab", "f02e644358638afff073e669b925ab8503122463dde3e849922f9cc5238c38ba140025c825d7ebed683d104776522595e9be6f85ae99192bd0687bde3efc7ccf" },
                { "kk", "6279a22ac0294c70449d82e852261fadb557f3ab6a44bd6fa7ec0e46a31e0bc803c3ac0e012f0f56c95e3068de72b2427187c6038fb7a7c9813592b32d267542" },
                { "km", "9b6006825bd8d7c03266cf51a4c3013894d6eea37bc0cc155a983f10f37cd1822e2448a8412140361d8c46c993f162bfe037dbf444ac04a08ec162f4fc4ed19f" },
                { "kn", "9021a3c6bae533c6a296195325eed8b8d6539984186606d3e6d6ee119bb16f5bb8e45c6c5336d21fdc98cfa2dffb71dd7d01de2aca8fe42b69d955e54db8a11b" },
                { "ko", "029bdf5f84d14aeb7ab1f00a1875672bea03ba38ffd464982330cc1352aca4eaecab77e997f1c608d77fd31c1d8e97eb4808016c52d161ab8884792c1ceef233" },
                { "lij", "29d8ef9af510a64843cf0c885069390e071bec0dd30353255149786fac78dfeff96f3cd3e95b6e3d71ad4d3f4138a9887ba36fb0803726b49942741f989b2065" },
                { "lt", "6811c89ae330f2a368b065b5b5d7169f47babab48b3f42cc8f21b8d83abd11168de498d0a95e152e02827c7c9faf5e5290d91d7d9d6d73abecb25c5d36d1431c" },
                { "lv", "ca444f31e37c4c36e4e241cc6ef04cac21c92efdbd24cb9e7530676e4e9e24f2e0ea872808b36ba96e018ef26c49eb6c608f67e9f569fd09b94b3adab56811f7" },
                { "mk", "1319a18adf09b0aef8156a72fe3c6f8a17396ab363dbe07426dbd11f0acf06d1ddf0b41dbb438792a0a2a7cfdb3483da84d409fa23fa1f6eac917fe947a5d24a" },
                { "mr", "4770b00eea23818070be5ed8a9d54ff4ed33fda81ccb6069e639e16e20b819c3fd0b8494ef55c655e2240f9b3c42bd495bda0b203b43e96aec85562d53fc0633" },
                { "ms", "820a6152d6989aafe7590f4fe68e381c83cc69cf7f1824f3c41c56860eefa438e4e38a9a9cf321f9fcc6cfeaa79a09dd103d8cbf27d2327890f3e6fc7958820f" },
                { "my", "4973f822722fd60129cef8b955250e0391e424c0d2d39a94f763908b214088e48e70e3ef4d2110545907351b9f73c368d18ac5ba2df4a8ade222b33a2ae9ed90" },
                { "nb-NO", "dd3f95f02d5ddb4a9568866d314aef4cbf77e9434b801bde444d6014d91fe24d080bafb91ae7a3b7566a034d1d760cda5cc5ef30ed97dab9dce3ade61cc87630" },
                { "ne-NP", "911fbcb17ff3385374beb09a8fecbfcaf958e6bba21131d597b7395d5db320cad62c4643858ff770681a7d1d4a5b08e950dc0455128b411e465b3b15db1eabff" },
                { "nl", "801895b1020e9b47f11560d89ff15244ec4d3294f9b0744d570ef2d14f4d48c0d52be8b8ce9dc77d33662dc3edac42d992526ea94bdb10b815cb4af813124690" },
                { "nn-NO", "504fc89113ef8bd340bee80799784349da733ad502c4db360086831c889c8f89dab37fcb9d5f18abb9fc03bfc565d16e57143ec4c437998c6ff5edcf6baeb6ce" },
                { "oc", "81b685186b3a58c26eb8a76c20b1ceb54042c94fd232958f9f4c50dd58c2903e706ac682fd7063991007a64bce8637fb685d93263dae7bfba343927e600e38e3" },
                { "pa-IN", "76aeae79f138ccc73bb1071c4ac9cd4647ef9ab747fb2a87debab65c1289befd950bb3a6be911d85c04c5a11da9f9671bd8b2acf7387387c3ab2a6c3c22cee4f" },
                { "pl", "cad4ad612654a9c3c3db4b1f2758a299ec78bad1349f3a53678f35f261a75ec15700044c59a0567c95ed1f0f8af893763579b940d5759c6920969fe377197aa0" },
                { "pt-BR", "b339ed151331656f75193f8d23e19711a3f0a1cfa777497ba07833c70c777af928c85e17ac9583f4524dbe18ddfe555d0f0d6b956bd6d8f6e118073813193b80" },
                { "pt-PT", "e8ae1a6c3cafab7bb2006d4f072277d1e22195e4dcd69f7359db49896bf3bb7e7f7f99cfedf09246a3a8cae6d953e5227ae366743ca94de67dd1e51ffa64ccc3" },
                { "rm", "704e72cf2fb100b2ef4586e35f4faafa76199c76a0b892867ea6df5d67af8ffe0052029a6364a051c281acb4718d38d9a93d57031d78d3284af9d1f2d6681597" },
                { "ro", "ad4a492934e3b0d6fa76ac7e0c9e531e4b0a4b3f07b3d61de17334a4fefaa44223569e2720b2f6c8c53f7808caec7af9c04ae5e0e3d4e90481866f6eccbd77b0" },
                { "ru", "6c1172a42f6104773c584342f643a3dcca20da80ed54246841001b4b9f9870566a6659f701b49fb2276fe66eeb547fe2dd3b563af1d651b5b7b59d86dde94403" },
                { "sat", "e677b5c9471ced048c0960c7bee979f1757fd9a5cb1cb6a1fc4dd690a604aa698f70c0897af68dc3c9ff82c0d3687ee74bb6ce2465c04b52bb4f7b7a2da9a392" },
                { "sc", "dc24314d83401136a406c330a4e037a945a5affafae463f9ed2260fb1b9a1fdbb73e1d04b7d801e24e8d5d22c2dc004f45dd0fbe347c887db20db5f695fc88ff" },
                { "sco", "ea12a1fdee7c363acb0a5c4658853a411b2a9b88d8f16642c94b335625c8a4002943e1b95962083038f57175ec1c838bf21f81d9be408619f41438702d3c1214" },
                { "si", "292ca7a8a29ce9effdbd9f1ad7cf9d619a4567504ca4bc44d115d9d91d438fadc121a36f5c3e7a4ae500025d063390cd9035313fcbb3f6c23c68370d17def3a3" },
                { "sk", "3c23137a6aa4bd44a9b5ddb4f6ba81b903e2050df33bff8268c08a5007735eb54f77bb928ad256e320bdcf6fa256314440fdd01625c6408511051c1745c38a1e" },
                { "skr", "3c8c67df8bcb17229d4721c95f08242f8ea8ede8822c7d84a90f1c9d8ece7ef068d15b02a511559ba0c5325d7635bb827f54f7aec922e491a5988bedb1a6bba1" },
                { "sl", "256184b34682945170431b875a70af6fb7e2f8630f4ac501322cf8164a357419a258c4e412e69496978322d180c857a0f9699ab6c2e0ba003d89f1387eb6f0f1" },
                { "son", "e0414a7f3760ce83e8981da7bec107d2c12f1a7481d46d603deace3e6690594ac14eb314a267682ba44b23740a5887b642b47f53efb8b571af90296195a0d793" },
                { "sq", "69e93f4eed083ef113c5230d2efd7f87ddf6047a4dfb6107babb8bd3494cf9e85bb3b0665a793d36a1ba5c6463f0965da5b1472ef0a74abfafe6190619c5475c" },
                { "sr", "a0f23519b0bec14028786b7ea243fc51ef7d0c35007f1325e710c84e7e54678460c55fc3329cd59899a8b5393dd1bf6a4c8cd9182d7eb32945fde3dcae8b1978" },
                { "sv-SE", "7d182f370dbbf8b2898411365608fd0a107894625d0dd5d5a37d8957dddf88d8cef9c1c7cdb9ec9a471a2cb08a1f90b1a19dc476731fcd576d371b0aa5a8e3fe" },
                { "szl", "95b5f5427f7425446e098ec58ddb7dbbcb9ba05a516788641083dbd12befd76d2e436c367669f96b4e3e7f04a9732fdaff880825d1ca18398226c0630963f680" },
                { "ta", "ace98bd42eb7e246bf763dd8939236dcb73a517709aa5e886df93475b31daf1a699a136389943a54df9ca0a7a3add44f7147b4ba671e68781a67f12c619004da" },
                { "te", "56029cc53eb2d613763a92e98016be443fb1d5054b8c900254c2c9bd3c84424c01dc8a9883259b97502cbc538b851f7609c8c60b7d54532184f0496e7189927f" },
                { "tg", "d791c877cea0684e3489c8793167623eb8e756d6c1419ab1bec9e7734f03709836abc462ac08820704dbdff67a5cbf35f631b75ef13574a3f0b1b54737dec5e7" },
                { "th", "92f4d9ed6292eb49c5465d252f29bf76064bdcdb122c6f6f2f00c90af09f8866d97a0789ac6d447b1e9114674575d77e87c36d8541896a3428deb9514ac7e864" },
                { "tl", "5829e4ac3ad298941409444eb56fe770f77c02b9832ec344b939377f9ffdaf0beb49c1baff070b37f175be9ab4274e41a64ceb8a98f2a934fdbfd2013f1420dc" },
                { "tr", "d2d691963d8e3e804ea620c26919bb073d263aadf4d24249596096569e3c72232a2b635bc4f5398a902e1cb8a31dd43c3a2acf4506de18395b9c5f67ddf97e1d" },
                { "trs", "651b8635cc1d88b21fc92f4717b891d528ac01276ec20f0f9111153d25db595a62debfe22ad8fec5a611316154535b46606c593bd177022580a77fd18170b5c8" },
                { "uk", "8ed605254da7814a28ca511d95d72248bb122e18e72eb84dfad92ba0da2132840aea84562bc3825f8a37a953ededb8e8f643a166a8618beed75a561b60ee4677" },
                { "ur", "8bb2c9f9b25c65c1c168de54337e4569d4eb0c69d8d2a41020213165358f5370ad60c1b2f6d89f70a30c69b916a769d6e5ac53fab857d729847d9290f790b544" },
                { "uz", "25983181702fb94de12615822b7b40b3fc51a315b1aaf1851394582076403a3a98b740a66d8df3aa8aacd0308258edc8cf01c6271807b8d6cfd075dcca43d0bd" },
                { "vi", "b3e6300f576c6d92589d401e7f4ffb4c2cce04133f24119e5dc498d0a3d1c8f8611d9cde47e9a78456529a0ffb5d04e53096a0ade0389d5e056a6ee26d87211a" },
                { "xh", "1a76acd9e90adb3a7f16fcbb8eaaf77baaa66670af506c02aa16f6fa530206105692690f2b9f887b46650ba18c18e3e98c7b7c4536cc8a22bd5f3ee5d4158ac0" },
                { "zh-CN", "e9f8a522b9c9cc8aa10e3f8d0c725bfdd7f51e2fcd1ad03991f6917fb4e85071aae719b9a2143262b24e5c24d9f33887c9f343f96e8382f3218b580a65da6b5a" },
                { "zh-TW", "c858450e1f5e8d0f98d3d8490c3877199e67ee1994cfef0c9200343597d12edb9ef694759f67cba5215c2c8e5c1d93382e11935d717368c44dfc04e652e2395c" }
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
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
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
            return new string[] { "firefox-esr", "firefox-esr-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
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
                client = null;
                response = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                Triple current = new(matchVersion.Value);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }
                return matchVersion.Value;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox ESR version: " + ex.Message);
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
             * https://ftp.mozilla.org/pub/firefox/releases/45.7.0esr/SHA512SUMS
             * Common lines look like
             * "a59849ff...6761  win32/en-GB/Firefox Setup 45.7.0esr.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "esr/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            // Firefox ESR can be updated, even while it is running, so there
            // is no need to list firefox.exe here.
            return new List<string>();
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
            logger.Info("Searching for newer version of Firefox ESR (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
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
