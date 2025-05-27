/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
        private const string knownVersion = "128.11.0";


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
            if (!d32.TryGetValue(languageCode, out checksum32Bit) || !d64.TryGetValue(languageCode, out checksum64Bit))
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
            // https://ftp.mozilla.org/pub/firefox/releases/128.11.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "509667646b7b86d6dc2e67f0b89f84e3135b59611b6349376c7c6dfdc59687af2cb42ac27bccd0bb94283a02b3d7f2700b6f805cb2849c318a82899bb952256f" },
                { "af", "1616a2e16e4d9607551838d49df80c08b6bfa5a85c826d1ae12d840623ec9f72d28965f782f26c532825b076540b93b72c0b5efa62cbd9c474d0cb70bcbd6ccb" },
                { "an", "92597229515d1aaecfd2608bdc995f7f3d54d65a7aa365e708c6d3f835c11cd61b788444e9692959e95a0726d25396bd557c95d665f640d497f274a7b21741d1" },
                { "ar", "16770634a63f6f9c29cf8c5cfa9a2b17e7410253a7df40bc8e9cce23a967ca45617480cd35b36bbd39246e2b7c127c219c74e28c7ad22ff6039db154e6375ba4" },
                { "ast", "c83bf753a1eefe298d07a8ecff2d849784612d850286f8c645c4b3606291112e8ebee35a649ad88319056a478881baf408c5dd3bcbd1a14518d793583659ab33" },
                { "az", "8894709a94735a031e38e166b3798f618b417f371da2d5c364895bf1fb855f4f1d00d0022bbb427653ccee53a2a9d61cd07b3bc46ae0939b104b0eff7066c4fd" },
                { "be", "778345576b71af3878feaaddc08c8c6ef184e512557266c0414a35188c5f9a09c40eaee1f9373ecc8ac8a1f6faeb8ca2002a758ec06c213dfa884260b74d6f49" },
                { "bg", "ba8ae0a1e12354a480d0d6d3966aeef475fbf595141364e68e4f4b1039534b5a2b79ec777ea6a235bfc800b3e98f10b982204ff4a1ee45836866aba89b3a9c68" },
                { "bn", "074a52ae2b7dc3eb15b1f5cfc0866868541f3924d8111648c8452bdd75119795dcd20190c791ce3059271dbffd332f4da41f137219d85891a216526fa2144fe0" },
                { "br", "86a634da5d7cc0018bf45aab5bf7829c20da86488704387493615b1bfc29f53071888c0435a14c845e1a7815503bbe4e2fdcacf74b756b3b0e2e4452ce5ae51f" },
                { "bs", "d1bd160eb7d57157d5833dc06ceb6f9d7127eb8fdc9e0294735a9ed6b1d627d934cc31561453f79a5dfbb9e7536b0c4c657d47592286697b369843a2d8af616a" },
                { "ca", "21b48553563d25dbe81d82d7be3b8f395a28499e93654dd862e094a323c5ecbdc549acaf8669d5715013925e1026d7aa978018eb08c7f6d0fd523e17989c183a" },
                { "cak", "7543f906e8b01d1e32cdd7a3104da1bd55c636a88bca80e2e6f8b4c7cae2a8476f7e83bc4eafb2cb0958614a3a8968a96d6f291c0ed1a532294fdc69b7d8f5c4" },
                { "cs", "e955903b2d7221cd6cce5934ee9cf58652ec018129e260cad03d4062c5fa42b54bd57812507f57fa1513caa02d77f71618e4dae9ffff887ac83d1fd2acebbb51" },
                { "cy", "387e6a0f2f5b858811e19fd8737ee9ee080043921893501b6d936b57c18641a24383586c1b9e14f0997e8506c5318acfc3751819caabb9c473feee87bebd319d" },
                { "da", "c04eaa053192220fdd6a49520c565417ead3e2a445e74d73a811563e6f4136de9b60dec117673ad46aa785dd5540529606b83ed8e490de17a5a1bdb4e22aa28f" },
                { "de", "200adf6ab9b9456b26b1d51e7dd86e8c58c3d7ea38f9e0d0f48bc3f486557d8bbfde355999cbc99b436ac74e3508a7c22f82a43329a16148cbe4a2e70c6d6237" },
                { "dsb", "11466bd645f7e35e70f466d6a07867881fe33315fd8d35cb25bbdfc02b906c15600106c5ba25906f16aed4543d771ce9e4bcd5cadefebecd89a05d6327b6d467" },
                { "el", "1a862c4595ddd91d0c1eb9ed11569716b1a668edcde0cec354e8a7e22baf032a96a2c5729f12551032069194bf4ee360f0709988d5c07fd6a28f1456367d7c0c" },
                { "en-CA", "1422dca37d0a9e4266e47fe81f88283975a0f08a8c628a3eeb04496f724b600906c4d915d2c17b1b3ab2c05cccbfd73cdd4cad4aaa527d0b67434b6b623c908d" },
                { "en-GB", "819d0cf335e7a59b82f3b5c8a66124f3d4de4b553ff20239d96e4eaeea26a777312da1e197382d20fb5c8f66c41209242fcd81cd9140b187eade79475e579288" },
                { "en-US", "9b02b9e8633cfbea060c38e014562d94f536ba81b6e095e1f143eb438bbac6e6d215966a8ba5aee2c4cb5af2cf751608d7307bca0371f6f9747692b6748b09bd" },
                { "eo", "2e647c91346c6a7c5f3e90967f2336302ec22496912f861014745304e7f57701225f4fb48387e8dc630a6e1c4150132ef27aec57210958ccab7959f58a1b7856" },
                { "es-AR", "4197447ea64a2ecaccfef9e65c17f014f1305b5ae26f77b6db19657da6dd79bea2682e2560d5e2e978ad83fece3d5a6996809ab1dbfb75113b74671dd946d71e" },
                { "es-CL", "21ec5aeb52b47090209a3173e75149853b3910c9b4eb59bdc9c93f5bc3b99a8f3b00f53b413a536cd82e798c5d2a29fafdb4a81ef43a079a279a18ac74a0305d" },
                { "es-ES", "c8ed8bd55e8e9e0eeb236c14377f8afab919cda57129b0f7507a0131b34904d7c2d1fe4cc8bd92c13b80dfd06af510136089b8f1b97fad3603a2208984091649" },
                { "es-MX", "13561e2bb4a144a30dd7be8f5c1959602cd5edd4868ce437516c895629311d4a63bbab6b441afefa995a64040f775ecafd243d61e44cfb8a0b3adf0633f62707" },
                { "et", "7099aceb4014b80fb00bb6f08a2610590aaa41e34b3ebc2e87961e3a01d38ec12bb5bd999cee6323c8c4e32cb8007d060884ae42a53d80d6aecdcf8ba809dc0e" },
                { "eu", "c3d514719429a5e50ba2f7600fbf3a16e6e2df920ff3f52bb48473f9cee65521caf5400a4a82e326b75c39662e7b29ee3a40c65e815c77c1babef380439c4133" },
                { "fa", "1a80ef95b2f37a17fb1d1cafd102e7746d6a0e0dc277bf60b8cf8ea8b68922cedc06b04015691d570e924cad079d951e002eecd015270b34de230c8341be5c57" },
                { "ff", "f52a6cc35f932cad9909b793a844d76b71c300afd0c17f8e2c0287ad51245483c375562f0a87550c7f5a6e2b478fd007ba1eb9498ea7e70aa199dd1aa79c795b" },
                { "fi", "9a00cecb05acf15ccec37f70af458c8066e113c7a03c18480b1f98002da49d43498e426546385e6f6f2eb0eec3d98e3a655a8f7dfd03de18f2c6da05fdc1c785" },
                { "fr", "f10fd68ab15879a16a6f9d061556c4ad6c67ef1ed348362a0a2a9a86111c3691661bc2fe1eed53b7b53dba32e8841c4172634a4021c6d78ba34ed908180d2fef" },
                { "fur", "ccb50bc290b826265336e5dfbd86fc007c301a41dff877f31805b5dd3a71ea699a605bee1dc78fb5c544e60ad082cb07864d3ac2a7bf84e23bd8d8542e5a4f3d" },
                { "fy-NL", "0b645e4188af2c723199fbfbd391fb2a7939eb2bd851a4afcbb6ff6c1f10794426e0dacb1c22905bb4b009e869cab5d84cf875dfa0aa8db654a147c907813c35" },
                { "ga-IE", "89acdf9b61d8b1158f79dd608b23ce14b5b38a3548e4414cdc590883b6cabdb5f40ce6d23cd8091a2a17c117ea14f9459b5dc7bf94ccc4096833ce4687d0c8df" },
                { "gd", "422dd1482e7a616caf96685bf17ba45a6560600d02a745862addf4fb3c9e7ed280309693c47c94add475cf6343457857f19f364c8f400da98fd9b5d145dd7d8d" },
                { "gl", "3d7133ded390717a6200153effc98ea3b371088ea09b71bfb5a796243f781ab0c6f66ebc6240367c68c73302d9bd9a650b7215bfb19913ebe3ec4e524d45f86a" },
                { "gn", "32ad450f8563b5d8ed1b3e4bb73c911252a8168fb84a45a90cfcac68fc3137cc41c91d462aedc51f6f343beab33a0fa0343c0f82db1333eff2a02fb3c4a35e1a" },
                { "gu-IN", "378f06dee04549a91d9f127af7c9db5e199fc94d906e2aef1359ac5142c6cc783bed750065bcd7cf459cd6f19c458971edd5df13309e72419d3e9665d3016393" },
                { "he", "f4fb2f6e940f46ec5d93b96257ad343362d04a7627be36759b7af6a76e7fcb0ffb48807bd293f469fd79b9b6dd5ac74b20ef47e2f84793193c0e1b0a90937712" },
                { "hi-IN", "918a2f07e5650eedfc405a3b43f98082a51e7beaca62861e6d9c70b856d6f4c38daa72638f623d1d38d96d982cf03c6b31fdd2156c35fc09cabbb8a43bb75f86" },
                { "hr", "8120ebac6dcbee61ad79a2ac24aadc9f954e3febeb1c8ba96c1207f5dcd638222df10031db1dbc1779f804f0f39c234944aa4a636e501218f8540adb63643706" },
                { "hsb", "5f8f05587e33652938bf8e7edca295fe496ea6f719e66f0f820879e28084458fd74d4b5b1e94744a0f386ca2409c56a93000b0a5bcc3e4c3fea8f9d60f2d21d6" },
                { "hu", "59955787d6f00c634485caafc60359928110fa6d3b30fbee1add10b75ddbd287842b70616066bc92010093ef76e318212caba10f4a2ecf40b1f803f8875abe4c" },
                { "hy-AM", "aaf499a19e6527f8283413d78e80315d9a84ff6f4465f39d68055b27599794c67e55fdfe9bdce3b8508170cc43a64c95660300d507dcaf7c8f373a11b09a893f" },
                { "ia", "1eecf5cfe56c2e56fd4a71a1b00b034b78c0c1509f5a87d58308ef219afae83498ea0bcbd8420a94d4e41bb45e8a1ce27e91e4c9751a3a981245c41f7a1ef698" },
                { "id", "c0932dd4efe868c0d258744ec6bbb8dcefe3099efc624ed01627fc172a339a5f6ef9f17b38d0e7392a0a82b0dfeed6785b89b023ce76ba94b3d37df25fbaf786" },
                { "is", "2bb4662942889ef06dc9c3a33ff0297aa7ee0fb0bd8f91079eb44d05dbe08b8336858c856ff1fc8c12a3da5e01d5272dd580233184b5622df345ef358200e05d" },
                { "it", "b3cec4168ce8a94072691c0ca50260321dd7d3b5d180bc2fd7dc02afaa956ddd4ed2cdd2281e426a9692ebff2ca688f148d98263485c4799db0e266fc84fab90" },
                { "ja", "eb06fd917e94d3b4ad1cca31bd9ba7832e872483bf0e6d9ccb3258a2f75407b87dfef9f37ce6c08609c646ae0671c08f741e2b31f3b1e59a49526d4d657079ef" },
                { "ka", "3486f33c1077f0a0a8dca145e868c25b03e94adcf48cf96b11395919f7ebda02403e2e58e1c5e372faae2d3490ccbd3a8007b970a0e42e3c6eb4f5df1565eef0" },
                { "kab", "3b0882e3a4cec1e44661ae430d77fb2bb7dd9d78cba47fa5fc033b9a4d8132e26c8a883be65d51119b9bdb1818f8131fd7ccef333398348e424bfc59e84a5289" },
                { "kk", "a47132144df7ee2c14cc8453e09b5d4bb65a75ccf31ffd296392f968041e839ddcd5b079ea971836c0899d25a5b07028d2645a2cf9fd0c620148e25b8a80b521" },
                { "km", "3dd348c963968e69ccd26d7dcb1666bdea48b3b9e338c6539557f4431757128d82f15a565bc5f56d024658d8e2180bf7dc978fdd388e1b9ef1b47c7a61726c87" },
                { "kn", "dfb65a34ba3555e12d03f982c8d757de8be055d759d060b480336aec7e4e4d9938bd7b06cf924c31a6a75deaf6ac36c9ed8c82baf0008baa0a0aa758097d64d1" },
                { "ko", "cca64040eed52a136c5e62120e5d91ffcb4701dd161b0b7a5364ae29765e23e947a5f537ab64d5988d24c9af6657e4a12ce61621d3297b55dff257086bd65063" },
                { "lij", "0ec6d6a84d359dca7d7e2e3e0c2822fbe87960c52d59fd55188a0370919c18c1c18d241369f04a06aa2df2862f1916027be0908100fb5ab2da11d43f96e3b3a8" },
                { "lt", "4a55ddf53b310735e63dcfe7162874e5b0018c3a976b0e5e0243899901136a2ef2a70245cfecb10ea528915fe9709f37115b396ebb9a4a634603fcdb902862a6" },
                { "lv", "7899dd71e649f835e9071c034dd261ec2d3eaf0ca08794402e3e0d6cffd1907481891d5e9fc57369fb6cd03f31f47af551e104b2275f242d40b1caa4b14ec4b4" },
                { "mk", "4a61e8a6b3db14c3670ffa970669ffa03bfc9e03633318c529f65d5864d7359f2bde0ffed1e199c630d828fc06bbc626ef97b65c932233b035bfeed06e443f18" },
                { "mr", "9e5719c98a86b40d87ace2ca145c89b956499d0baffd687ca9e1a2add745cbcc196af1fe1156c695df314f8b826c7761e4d41985105ddf03e878f109d4262633" },
                { "ms", "80efe2e7dcfdbc38d356637dd3854d6f7c11557fb9dc60fab7c3d87d40b582a37872d8139fb08bc7d63758184a8da859aae0eac9223c0a779afaefbb7aaf7515" },
                { "my", "835d6b5d0fd84ac0261fc4fdd2b094797a8a2577bbe26f508dbf4afb2b67794aaf741bf2dfd7f9051c73909e0ff048f5f9eaf8b37c16f274492536eefea57cc6" },
                { "nb-NO", "c5807c71736127139e6fc3c71c50f62bb5a91c7205492968df280d0ca4b53d369d5df788cf0f62d90e9ff5e083a8ec8db88e6a16f0a660a0e0ad7d80e22cb390" },
                { "ne-NP", "d2420cfe4b691d89c5f3571aae9beaac19a48ccfd3329feeaf443a0ae3393a2b39a808e65eb648c58fe37448d5e8a8b98525fe456136e644a733eadbed9f27e5" },
                { "nl", "89d14c6eb002d8534607ce2d57c83968653842a4c3a0a223fde9e91f4916bdcc9b936a155fe86938ba1e915ed07a5dd3d70719865b668840c05c11fc702a3c4b" },
                { "nn-NO", "9174b354f45cd33c123189c9debf4ea7a165aa417177adafa080c1d920466d9796248cb6ce686dee28f4ab93581d7bd8c72665830f9d4cede99b92b7dc4a5ea0" },
                { "oc", "195041b52f5ee9425ce9b8cfd114ea4b6014ee6aecbb7223c7e9bb1f114442b11fa84a5501f22b0df924d08572821a375a2b5ce1301fd2d1babab635c5a6b1d3" },
                { "pa-IN", "f49d8ebbdf5dc67df740903b86a1c2dd91368af3888c348441a6a7dd24e3067201acbb932260d0410c844295f5b868d5175269f690c4e9a688d1f1144da9d6fc" },
                { "pl", "ac5723b70fecc565d6b813a47edaee0d19f49b19732a90d4c9523606d6e63cda5674d83a497824c33be8dd4a0a4fd7bc6abe8f3bc4dcd613c61319bc38fb9c8f" },
                { "pt-BR", "c96fab10df974da2e454c0609d02725099cb327f7c075204cbb1a77a0b521a7e387826d614c3f93671cd0ae4326e930bf6627256868914408bb13bcd77c486cc" },
                { "pt-PT", "a62a9b6af8e77b97a8b060712c79ba666a3141b49237f9c3f9a9d45989a827a36955115d3a8930daf5d341ab1e2c8e0fc81c5be273dbac5a21c52e81c69a571d" },
                { "rm", "567a5da63fbf9133e572757a516209af83e82797049dac7bbddcfab49a5c89bc1d0c928467040b72ddc7b16cbedf5d99a4752878610fde4e8e0e9cb1cb82a015" },
                { "ro", "66c706e328f2d260c06fcd0bb536d8151c630666cf506afe145e877e9edbb72cc5ad4ddd34c20d18bddb12f46e4d779ff36cb76ebd8f78a5317a806a1473b440" },
                { "ru", "2ba809f9322045b557daf3917d0f840beb0f0dc756e107b086daf7200184309d3846a3265199da890e96e78e8fa8f16b587a95202a7bcea36eae258cf554e8d4" },
                { "sat", "62e86f22f426d8da4b115f44d5f79a8e1067f7edc9628ba80d925a4682a30f0cc55424fc45f6f85660a8cc0430b5eaf296aef5a334af9127519bb15724021ab1" },
                { "sc", "7e68b503efad512c67188be5665f4f751fdb3ed985497813bfbfe46c737bb2fe57abedae550e8985b094072ca7323fcdfceeb36b1ae445e5d5c6d38d1f059b37" },
                { "sco", "efbbefb2aef6603d3811368543249f37a100034c6df2c6f5db0b2e65c169322b41cce6c7588f004d588ebf5eadadc5e7085c16dcf349a0db3c4ee4b1a5e4eb51" },
                { "si", "f79cdd04de00af48267cc47e1852021f94c17a92499bbe69ccb59d5a2e94365db858c06de990418d1711c0463f15035f435443a252d8bd9a60281881f97c5edb" },
                { "sk", "58b2dae21bc6a64a96c8c55530a14dedb7340737284548bc93c311ae0c9afa0ebfd8430ffc35c2fbd32d0d4fe6ff4fa5639fd292d6c825a90906a92276461590" },
                { "skr", "058b469639c0a9af56b1310c2ccd6fb6f38d344849b5cdf34e9039ddbb810901969ab29fd7d46c54d7c99f2e7f25fd1fc6f534409a71e1c88879f9e0a814190a" },
                { "sl", "6c05511d1828eaaa9a2f1f8e9ca623fdc7b598854ef411f2493650f7ada4920a312aad4c90e85e3b029b965d0ab129dc6b855c2ad2b683a437542fba1177217c" },
                { "son", "ffc283e2295e81303c3fc966e9728b7f7524cf1ea0a39be009e1808512d02a81fd640c86481465c16f79b146a35abda7e32f0a1ef203fe2e3c4aae1e8840f7d7" },
                { "sq", "0f28d035362140855d73db440a4fe8502156b81e1a38958a0e9a86ff5135e76601da6c6eb7b85c281c26121fd7e6aa95857a69e3767b72ec2618baa2cf87eea1" },
                { "sr", "cd21f34b8e0600980b9e0c7c51e9d661e9ca94f2f7082df706e8215200936d25a16e42098d57ec3ad96c54c0c84f26b7228275e1701a0e44d2598a207173d22f" },
                { "sv-SE", "3ded40c3b4342bf5cf00b39b0f8c2e119514b49fc68493e5edc2a9bcecf32ab2823ed7d4cce544d588f99a4e9ad34c4bcefe43462ccd4058b548057a1a22dfae" },
                { "szl", "6543a471a9a05076302d8417ece613818d2a7295644ab832fad01840cdb9486d578d5a040c8ae6578f7496af8e6d5bfcc1a416ead47bd2bab58c81063a4cdba6" },
                { "ta", "0d93a33da787c2b6737cd9af80e1b8b658d9bbbff1c8d140af7099b7a467d07f41d727ad9e20e6845138f53971736f5eb959449f20daa441599374552881e424" },
                { "te", "7be8313e1a408b1bfe894a24c59b423a78f2e5afb64ba238b65be76d03ea3d4deafa945f8468ac05314ce064f8f528978321ed97e017e5df4f0d57c40c164663" },
                { "tg", "fb9561657a3e145c416953522cc116ae7f7aa4f27e1497e47c6c9a3e4eb080cad250bddaa341cc0a36d35f490b9bf81785994bd45c25b3ecdf51401d65f8e8af" },
                { "th", "ba0b1b2bed82fa40c81688af6d5ccbaa020b05a981ddd5ba5ade9b5f34b8dd6186c88de09fb0e877e265a2d642b52b79c854815a68ed08c8ef953e51a5e54ee1" },
                { "tl", "f1293ddbfad6c3b1a6ce2f08ff12cf65aa95a65e46d19fff26721d63e62a0e4f1dc94b97c587739da021e245da947b5c7cd0361d18a273b6b195795fa63993f9" },
                { "tr", "2e0d6647ed8ec6d257e6937f97709e1c75a22afe6dfc5facf0ed991f9b02f360103456a977a61cf557a119d6c79b040fbd508f525ba1212701b87a381df056a4" },
                { "trs", "c781bb70ffd78972d194e7f240619c1d0898cc2381088040af19f6d14591cbc9da38cdeaa8ba836759f5ec7c7632eb514b9724eae094603c1546b509a3a115ec" },
                { "uk", "449fb163197c722e86856b0e32d4d20857386a1c8a1ced28b1a9d7a7ab44b02747ee986516e72ba97381c0e80696524ca08d6fb40d72ee314c24e63c14f901f5" },
                { "ur", "1ebab7b7c79d0111ed1704df273ad5239fafe9cb9dfbaafea94963a105681818f76b578ef97f63d5676bdd4f22d8afebc602dfa962125f88f92aba09ebfb3c4e" },
                { "uz", "236dfcc38ecd51fed7ad6651aacb65a1cd46192f835a49345627d9fa6e5bbcf78449ba0cfee5a87a7bf19ac370a2cf4792e8101bacaa997d7643604420e2fa10" },
                { "vi", "0884006409eb26a32779d5d0be6ea53ac916e5876dd408bb9bbf6d77df80a46c018963cb76c6a6dddc5b18aec527db5f95a01238a2a1f50935c4b2d9cb6f2e95" },
                { "xh", "73a5f935197545cf7f2ff00c7a4a352886942366ef5734b6b0f553fb6de9653b7f8dcfd4721495dcd326cb1cc3bea636e807310c5f5a2276eb79dbbe29b03043" },
                { "zh-CN", "c70f305162a126973d7b76be23708908ccea065d44f0c3a542e595a1a3e8ee22154fe50ab01498701c97153d1744d23b0c493727472a1e1e93de16ef05ed009b" },
                { "zh-TW", "de32cb7f7cb5d2e3d3caa66b62a88ff74b1867cbbaa83e5a621fbeca424395762f4be050fe6642e0c398bf32fe0d4bf31e35b438bf2dee10bbd1a2b2cbd7def8" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.11.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "a26c10f7cc47fd0d6e88668d6101d78d014259780380510d98bb5f1618002f3004f0ec9ff77fb2d0107e8b8601cbafc66357c7b54919ca2a811b758bcb1badaf" },
                { "af", "9425ef7b3ce5693554fc88a5e639a580731bcd7f4845ad4b46dea91455c53a2d6399fa5ba7a31cdde182d6e03d9895a2ba503b147a8480791521ae57949405bf" },
                { "an", "b48cacaeb186fe017f2b2cdf24ef1bfc1a8c62cf48adf37261c472e178cf9c28fda60b1812314812c4ba9627bb4b152d0740de5e280a225a8ed1f28b48994102" },
                { "ar", "3e2c87dfbf1e6e1074e36d8fdc8dce685815b666946c7d537e4a0ce730f63ff997ce6379964ddc594b64463222459ae51734a04cb414c2c3e80685c462cb9485" },
                { "ast", "656f3626adbcda5605ed74b22cbb9e4b42e33bb965848010ce6457d842f1aaad6d299af79e7dd90513cb1d1e605fa45f5d10ef83f866f0c720635cf77d58674e" },
                { "az", "5b602b9e3e4a56bc6f9ac7434f2eee515b82639e2e85d0fa4581878d48eb313b118467f186d8f3130b6390fe372154f551f2a1b972b5c21497aac6085ce424c2" },
                { "be", "0cfb58d9ae3e1070f158d1a02bfbaf5fda10a62634f84cc0efc930f7c063d6e9a657a4e1cd684930fb89197405cf23d65b1aeb513bc3b7f1cbb2a8c74e24f58e" },
                { "bg", "9623cce99875e03a6ccf996c790b3b78b97d17e1fb9e38d6155508d0612cf43b9469ad2f7a39b828f2be45454edbd1806ffe3d08cd55c5be993f947c5ad59fd6" },
                { "bn", "5e50b6d862a3b1ed9dc6052ef02d943e0ef7c7f7041ad814a9fd6b852a1a71efd4c13ffce420d7ee65aa994c8b800855226690d070cbcfad8530035648fafea4" },
                { "br", "342e642636ee64dd8647032f0c3cc8d7817b1eb8c1c292619ea5e24eba336366f6f426b3a9caf5cb5c9cfe19de22d91a505b3870e4248c5acb144312ab1dbf63" },
                { "bs", "460676085875a83c7980133105d3d57af78d3e8df72e27677301216f112eb46c506a5336085deb7d92fa722443aa12356a03242fedf921112df02a8eccd65358" },
                { "ca", "b4bf37b1592ee92430d8756f1bf277c6beb369128f0374fb8f8f86890123db399a8178f02e8c5f3d9272196637fc17ad952c5bba803bc38b20d3071e89623c9b" },
                { "cak", "1f66e44e50c5cc555fba366aa8ff5c4f7296ad5c5a9564d8aa7d323d1c512668250c32b586e1af2d2444ad4eb35d170056ba3a6fa17576b207fc2663d6633d34" },
                { "cs", "6c637f561523fc3f659b2fd0606bf3e4edd45c692e74ba8ee946c5969f9431a4645c2f781cf8120f32dc704368e99188819d38dd58ff068af6ad4dc8c407f3b7" },
                { "cy", "0d23236cc321327720933203b339ca592bc10e2d2d2fba1dadba00d64b4de659804b00b413f36ac4738772cc1892d6543d98813baa9fe0c0cb6a0b4f839e900a" },
                { "da", "5aad3b48e4092f1cc81ac5a4c993662794d7e43cbb4d889d76b440192d3f4d375817fab17aaf664c2aebeebfc9c257bf88c62f79eb3518034d3004927edc6ba4" },
                { "de", "0328a65061a42e8ea43f4e6f656c9e9dd8eb1600372216c419307fd7bc8409e039b1b1102aa0ac69163cab0fc079659881eaa0169f69141214d0b73e4c1c499d" },
                { "dsb", "6853171fe9c26abeb1e24d5694136837df829d00d8c03df3d7b8a770b7a1e678d0e975a2cdc4c666e235b29f82e0bf9fb4fffbf56d81ed8a547df3b8bc241755" },
                { "el", "c6d1a8f2cd6c148e2ebfc5ab67b48484b5069e3b836b23a1e990b04448240183c89281e202e0434362a5517232c7d7e3f3c4bfd37630f3d328f667e322753646" },
                { "en-CA", "fc5fe1b8fead73bcbdacce217d7c010310c3342ac425b2630efbba490af45c965d66015bfc3e0f13a84fe9da541863388caf23d2e57c6eebb314f17e5757f6fa" },
                { "en-GB", "ad2dd9b0cab4ff05e25d01ae5e3853b3472aba91ee9f5fded5557f851e259a65a21fdf8a3ff97c4f66ea8e5ed04722d91550ef835254c764a75104a6fb7766aa" },
                { "en-US", "44c81b89e59d93eaaecc82b73e703dc36ad28727e4b80c42f74d52345bfd4583526feac4ec896757a90419cb45eaeba47a168952ea01331cf65956296e09bee1" },
                { "eo", "e299436269fd6885f8e0a91681b4d9754996059d46092febb5810d69ccc88e500bcee2e937380ec4f6438dd13028f81010737f47b4549909bd42a04c7876d8d3" },
                { "es-AR", "99590aef1a6442b172d9de6777ec2782ba719675ff9b5ebcf93cefeb2deedef1e3e491ca931366766f81c8f76b15c8ca6ce1d13beabe46da3087465b0373c7a5" },
                { "es-CL", "4176e2a7dbc711973c6b70fd9995222313b6035246d0c94a76264deb9f4f653238ba9a33747fed81cba230967700dc7892614b6f9a743f0985c858ba9c1ce7ca" },
                { "es-ES", "29cc6352c7d0cb31197f0e742da397fc530edb9656350b2b43f03cd98206ad70fd79830ca50e28f27244ad35bf9e0b6ad414e98229be53005531e81dcaac1d8c" },
                { "es-MX", "3d4f432292fc83f7287699b601d2b90f71a3aeba74ca5a42dea4df1112ec81dd99475a681f6affe4b7522f255a64c2a395f7c5b8dc3346f3de13f8a120c2f2f5" },
                { "et", "3706fd5dfd04ca4068115e9e723b4448e13ff78d2e0e081a462cf2a152ab8a1e419b70f307cacfc17d6c68a822df8ee2f1878c908ca78a1384e85248663d6d6f" },
                { "eu", "eca5847d6e3979a7edb095ec493d5ad87f97ecdd58b31cbb78ae6d2c6b5b7fea7e0a7405de2399586b1bd8cdfbe915ef139650f979f164d89b51d49e8f3fa989" },
                { "fa", "262d325dfd4a4e1f3e187bba0e609afc25eab9ebf8874e62ab0327c9f140725cad126df602f259620b63ea01ab219f6342b6ee6200e65663e342ab0df1d1ef5d" },
                { "ff", "1db53313fc3a86ae5f4efd04511ae20cf3ac37a648be2bb8eadbefe3bc1c7bdda68dc0e6e77fe56f1f48de5b50a0ccf2b7cb62a266e0f41bd7863f25a4f9e270" },
                { "fi", "4d20475f1095994f5ccba82aa801195583f56a2341ec7cce0c4d27c9f37e998ea0ea472a0253ff871d50b150ce276e36db48120ea58b726a9908c4aa3d9eb3fa" },
                { "fr", "c10fe5905705d8d6ec57edfdf811f97a71f2f6ec841daf283b42bb373ec454f1c20736c60e75735d6c185ef1aae1680551e73a18c02a0f15d7de28c43892e12c" },
                { "fur", "10a21109fa89830be6fa7869511c10f85222b8c118a7c494ecb6f4391851767fa4405108105627949f7b149d948a80a3346261c095e3cd6f04944f2b40cfea98" },
                { "fy-NL", "788d6c6090fcd257b781a661f3325fb46cfe5c70aa4c07c04183aa28127fb16c9f2bd8c06ff8046f5b3cf487101b4af05520a7952b2773d659d3aa078ca48a16" },
                { "ga-IE", "9e8f4c803051ea9ba973a61664d4f6f76c2ee98c4b0fedccd60a7ce71e4848a56ddd399a82bfe2098d09edc4e97c63921d810a2fb298148ee43ba0de14fdabfd" },
                { "gd", "12e570c6976b72a3d459dec3ee43843f2878f4267f5163ce81d4dfc553a60b93edcd72675c50d7a56874fb25843aac4de54115a2f288092824f861d9b1966b48" },
                { "gl", "ef002564398c4cb192c4ff324504d272a5d1161d5698a1be059a96d61a233d96e8e86ba82b9d6481c033b9c5e38c828bc9217f91d5893b3e40952891359af9cb" },
                { "gn", "109ea60298e2a02051b93e9e64b8b224e77c117100bcfdf3e967523ea41838a19a6b6a6d6b31af64224cb80d7f708bbba1b58b783f5fb047c833516153b9b99c" },
                { "gu-IN", "a97afd2294e8cc7e03a6883a18d1f7fe121f0946962b55b8fdef9944fe143601fb8d96cac2546a8058b2f445ffd9d817d74bf7ad3822ad9ecbb5c48feb97dbb2" },
                { "he", "513200d8e34a29875086a66f2f78586ebdc376efdf410a4738951428031beac41b996c3545af919e40e7d89c071a048c1d4157e3bd8e31f4e92e046f267d8671" },
                { "hi-IN", "48a5a4f1f4f274ac591fa43a5a3f8b6b71395af85192226a93a25eec081c536909cca39fe0c62627afc6eb0b86fcc6d2544d51b881b03d630fef4ad13d23e549" },
                { "hr", "8994d0b801fd46f139e911c6b1a419ea61272d6858bda44fbda8a4e7b99c067a6f6800e9a5d966955250a2c57a28b28dff75832205628d48464d3ef0629bb008" },
                { "hsb", "0156bbc11e6029c8b851fe7d536764a84989879608c4ce93f2e016a723d627bf21372430fcf7cf2c92b44c0db33f827ead6cd852a07f690eea7080ef8311cb53" },
                { "hu", "e382eb3e630207876883171c14863c811e14686a6b8178b20cb37f1738662aa0107723404e6733d3e03ee7e4e1f300bd8e97a3b2a9ce062c4a77bfb771f2e9ad" },
                { "hy-AM", "6b467eca29ba05c424949a8c43a776779b8724953fbbdf8ba769cfe07cb858a1ed92b5403ea1e24aac7053d7c66642bda77d7cd2492009192f00f5827346a1a0" },
                { "ia", "abd1addf8eb4d59dc2c7a6945224914e14f10a44413059ed423cbe195d07941dff509a5c76022bde906869c1062f8032e85c9b954ab5883ac99ff67ee7befa4f" },
                { "id", "944c9c6e24ac105222e9b39cc72859c8536a30a778dd6fcf21ce7ed6db67e15d951b3d4ceb6ad95d9470b6520e7782795932e06bfd4c15aff5cec39a5d8bc30f" },
                { "is", "e503b2c19f21764d3e27d3c5d561d6bdcba182f646606307d41c2439203666246040370770e7e10d510ef09c089a0feed933cddb3d872e70d7c722d97b217003" },
                { "it", "a2670d9aa3eb1105af1e8b566bf987bad73bb5adb6fd143c46c69f7407681f0686a51f863bb1b2a70a0a98f3a5daeeb19b38ded041125e908ad97b73db369a4a" },
                { "ja", "72e9f436f73cadf13f61ecb84c5487c69bd657fc66c49c321335b379cedbe47c6631adac0991e8709e3d01503d741af5502df84263b58d62eefc4e326a841ee2" },
                { "ka", "39c0cdf611a6d29209a534cffbf5cc634cc8c3f659c669942eb2bdc60227b8f18e7554f18691303da5f018e9fcbda4b1a4292cfdd315756b0a6ecaa67ad753ff" },
                { "kab", "7601096d7465ebef0f5e81aa29083d5fbb75787eb4ccd720f0482f464a0bc555e5d76ebeac97fb992ba5c94961ad690a40ebd0934f65b1f4d2a58c1354e2e0eb" },
                { "kk", "41bcc63940d71768b476275d0c9e47b5cf879461cab7dbda5a6d349ff26ef54e0ac51dd44ebc7de707cd188f7eb2d89ea10bbc0ed5d56d5f84ba5cdfca91deb6" },
                { "km", "be8375972bd60d487e3b4f406eede310253f98ed41044d07abba73a9f915405085efe49f5a3966c82e57e3808b2876735bfc587d2405bd302b47a58fa5a8a3af" },
                { "kn", "04d86bcbef34c2484d5145d6bacee085c77b355b1969e51940d2395e29cd9cee03dbfe0042804acc6961e743fdb7b40e685f22ac3a32fc8e4c6eeecfeb2ab56a" },
                { "ko", "b7176fbc99e4830884fe1a30468eb1bb9830c77f0870d0e644be9f397b87fb91443ed1d3ac36213900ac793b66d0274c46afd053821b4ca1613e75a4affc4d33" },
                { "lij", "614fa0b876269de05af85d6e82661b9b649bef1e90fbc0100d6a33ca4d0fc00d4a790dc341e040531a137d5751f3ef188fb1a78b78e9e7fed1e27a5db5dea097" },
                { "lt", "02646075eab06974f80e527fd140b7c49ef4ca719f59f6c8880afd69875ad77adf48b10ba20c770c093d3ba734949be3f38ceea0aa339a8c9090bf9b41221c32" },
                { "lv", "b23a54e63137e8055f831ea873b92fe00d8425209b64f092c51ee5c8e523f8d81bbf16f34379ab527c0a6f4fd0191cd62b6ecde108c2289acafafd729c599a6f" },
                { "mk", "f53fe251360c6147a39916386cde9557bd10b33b59631361ed24e34e3284f1203005326662298be79734ed06c216dffa272357cfaaf1ee293b65483650a2a26d" },
                { "mr", "c1ed4e6db618cd5ae299a7c8a085c4f3fab5ddce44cf17d45d929b4dfe8d07f8db6e801542ab5cf202ac1c596befbc32364e2aa9870e684aa6052451bda2bfa2" },
                { "ms", "13ac4f348f2fad23d53ff00a923f0441c1bb35fcbd9c156a5d1b66b3ea28ddd0edae3d32d602191431686137fc6d9025fce1b1645930681e4d74804bc7beb500" },
                { "my", "fe4ace702d53bec1f621fab1569415524b79c35e7891d0232fd1edcec525a7704a0c708275bef803f2f21bcdfeaae3f5d5fc92617b7ddc8271a56ad4f7671025" },
                { "nb-NO", "8038e63eb71bae18e7714186c96bd5201f36af2f59d408ee6b6448fca431c144b0a5cd2ff39b82f8f979ff9310786aeebaa5d5b384ebfa7441e3ec0ee3c42e0d" },
                { "ne-NP", "c338806051ef9c7a2ff73b6a2011133fe7c8f91aee73d75550528f71e938c0bd856c7ca7b24f59bb3a84cbe532360131e1313cf60ded0180766c7cac9e1c33b8" },
                { "nl", "d05aabd0c762f94f8f0e9a6f848ea0b13b47665caf3369c542b288acda4741479755a81b611eb413bb34d23cfd15074db430baf73803de18e1e8edb3e27c4d71" },
                { "nn-NO", "9a9b3bbe6d3caf7c7032d30cde1e0e6c602578cf445fdbe117357a5e8ccaa1726136934c26e0c6582f8b1a6e93451d41448ce7844d28036ecc65d1c9d3258aec" },
                { "oc", "47f23f6c6d981df16a27e8d1e143efb62e869f4f3024ba2a0850caac15ac21ec3eedc4710213c66c308dbb0c9c175a12b49cc001edbd2a737f24348d3d32cabc" },
                { "pa-IN", "1cbbe67fef2e4fea26d06921c86371af94c35752891593e53aa626e47c2d0232aedf33437176537cab16d4fda1665675a30c17e54d11a50e8b2aeb7209d657ef" },
                { "pl", "c1d6065dc2e6ba0850c88217a3e7fb638b7351cf7de54fbc9c5c4016288e25a0e0a101dc401cf5592a5d467e9e3b300a87e0b895a4a521fde00a1b179c33e564" },
                { "pt-BR", "3384fc76f84e5490a12904fbbdeb942875c11ad45f67d0a46debb276bed0b9a3ef0e3efe750075042228628939af55293a3069a2d92330ce17ead53a0162632a" },
                { "pt-PT", "48ba874e4acaba9240175dbf933a3066bda67d67d45fc473abd90c879dadf1f9d3dee53638ed165142fd8238dc0ce0c13129ff2d0572dbf0ba78c1e8e546b76c" },
                { "rm", "6d853d9d7bd75c849db4e4517f98004f8e2ee4ec4cb62f8caae1833f63d9835b3b4652f71563feef31483ae93d6b197d035f2cf099bd1917cd850abe5c3cd30f" },
                { "ro", "6e0176c207689905d8b4005416010e068147e039d330364c000abd5c5becdc10f4cd9539500d734326b197597c9bcfae9f9b2b9bd4c644074a0f07943f34e8a2" },
                { "ru", "036b377893eda851bf206258aeb5f58103d445d627bb11d94bb8d8cd949b3035aeaa8565acc7a38db84a936a35da193f817251c66ba91fbf378c0a625708180c" },
                { "sat", "31c74df2d692c9197c51fd3465f993052b16764a1a9ad38ac5f377d5ae76b662c99abf5860234815645777afb2cf680677fbaef3fc25f8209900588df99a4487" },
                { "sc", "1f81a2b9af9a47ea2eaddfaae61ea23d81300352448473d24ff842b79b8e67330b622baf7e8c19924e2921f11b446caeb1f94d2ccd20e0b54059410d98433ea2" },
                { "sco", "dbba880042f8cc6b567605ff7db561b1a0471550f871255e61d36314ef8d97b838b68fb7ec1604d02a415cb5928e7ac7770dddc96a0526c9c8dd80d143186455" },
                { "si", "f73dd9a126a37cd9e00a3165a21f31c30335f2f085ba789c9df952166c9605fc4b1594a08d8e464ada2340ea979a2152e156acdbe809154855e15bfb5f665acf" },
                { "sk", "d02ac73dea2ce63806d72596ac9097ef612ad7f0f7cbccfbaac1f963408f8a0ad4dee5b908386b1864a769553f692066aa8e8e2a259c638ad5d79f0ace19a8fa" },
                { "skr", "64d37e8420ac7fb0cb76ce3d2f56a1e7713113edfded710658e40f2a65c366f27a170e69a4727eb10a07ea175af9533aa0dc7f3a6de5db8f5f8a30de4368f15e" },
                { "sl", "a9fc98c6b6b60f1b6ecbbe928635f8d24cdea31fef619cdd5e2c3c10b1e7bebe02d02fa7ccd74f4a57f8a451fecfa6bb0b0e4421ed2a5ee0ad5f20e9d077b378" },
                { "son", "380f9a60f701d4bd941475fb5ab91c3645d4c654cc40683d77f61008db78e6d1e4a2db8ea7401030a9b04e253ccb09462b1c766057cd69757890fcc90c239ec2" },
                { "sq", "cb22fd0d456f7c1bc00037425147f1cac45e8c1800a95185b427c9de4a32c0b9c5c07e6714b7219b5c2b7ff426c4e3996796d300e8c99cfb96f7460b9f0f9ed8" },
                { "sr", "549b8d9724c3aef753ab4a4eadee6e8663999f70782ac39f869ad70a3f39fa1248598033721523964816ff96215201f0eb035f2ff79736e3a8a71626ebe36f30" },
                { "sv-SE", "95e054438d1cf4c4577c55ba1f2ba87644f7c3f78291d12c3ef31f59e09f6be0ec42e38f166b290095d3f8939a26556fdb6c9b2cbc77e056270bfa4f02eb1252" },
                { "szl", "f8f32f7d34e7dd3eac28c80c3f0dadcef41d2545bb6b5186951ad41c56496162d07fe0ec341a60ee920e60f41cfa7b02b3f79d115cec4ef8faa80ea603e2ad66" },
                { "ta", "94585ace25cbd877ba85d904a7dd26e9dc7a2ef93fd614357a906cc61df84447e5f0d1af9cc7c14181faa4a14583b260b4926d9209302b318beb42d8f6030a0f" },
                { "te", "f5372b9ee645d67c3f5fc4ce6f49a66605caef0134ceb2d7eb4347a2f4f59cc8d8c70e910c8b75e536d80b9565c547140cb04547dbefb2e39134ab5787804f5d" },
                { "tg", "ac9e31f1c55ac32a292396d4b9a9004a6e3b71b1a5d833cee3831950e76669ad8c936d1946417df959634e6b4e03fca38bb977ad80415083fd99d79770dc7c46" },
                { "th", "10deea7d90250e74f6af092316bcbff0cbf1a711b5b9d1451137ccdb872ff2bbcb045fbc5a5f3e655625dd772f8e6e0b5f4bbb32654a38d177888e97d5f0269a" },
                { "tl", "b409a24676e32bfd2d8bd14e681afae86270fb62cc5f44262a78cbecae7d3bf76ab3fde038dc7726498330494fd9b98af184e8331b2d4e66ea295185d97c2f39" },
                { "tr", "5c529d6a31e5f96462d09cc6457bab8fa4f37918387c5dc2bfad519417c0eb1e78eacff016b2141db63ef0849684025ccf74dec45fb739da77e8f3867a1d24fd" },
                { "trs", "ff2951680df47d2c03087e867b6754849abc11da03290967abfbd36f49e0f0cc72730831bb57bdaa5864a4b5d89e117869141066771b9df8071c15dac24ba5ed" },
                { "uk", "502dd0758e50f73df39617881e94850b10804a454f979929c7c981ce2020f71df3f6fddc0c834b5f8d2d827ac2fdf8db869bd3aaa6b8d8277c1566b5509543c8" },
                { "ur", "43e6ac1f440387953c4985ca34ca93d1f711ed692619df17fd923182d8afd9888ab26838d3b9253816eb2c0c480f8e6597f5c688dd69d68f34d8acb13339ae36" },
                { "uz", "337078eac4a7e8ff7c98f6df38356b137c0372bcf834fd3c1f12e3b6eec611d510891a03f6336369f4a66d2a46f09a25ad86a584eab56b57e89503157cc53db9" },
                { "vi", "42ce481c0f0133f6a54e89391b1a7542707d092f8bdbd8e7026fb111300f2e1051c0ec602a0e275f0538ad0d1831f09332caa986a87e9b355206bb736bd014cc" },
                { "xh", "51e8fec388b36dacddf9874e3b6de7392121085715983c8116b3542f1b91c916890f38fd76fec0e6dc889527b5bafb3d93d4419710a572a0d7a8906643e90dbb" },
                { "zh-CN", "2b6b794987c08b583e594c017122ca9cc897d012c57cb265fddb9793862ee5afd62580376b5086f955466e681e52394a5fb2ab8073f95e06a4720da2d7727b96" },
                { "zh-TW", "71ebaff413b685b161175641b1bb184aa876751cbf932fd868470f2704075daf39d1fec4948d909ab8b6b24b48c46d2a323347bd6a61b31757e8c09125d313e5" }
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
            return ["firefox-esr", "firefox-esr-" + languageCode.ToLower()];
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
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            return [];
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
