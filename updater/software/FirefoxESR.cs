/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018  Dirk Stolle

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
using System.Text.RegularExpressions;
using updater.data;

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
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
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
            // https://ftp.mozilla.org/pub/firefox/releases/52.9.0esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "3c752bee60d217bcfaf47342493fada2422558026899633d796efbfc653d669d43a75ce63659f6ea1c6a862b3c385836bd3538a209b85cd09811ccfaf3228a08");
            result.Add("af", "64da4c9b4765c7e36d0fa7ed5566eea1a08a877f0e2a90b53f91fea86e9cdded99ea2ee092f1c7378beb93af01602545c083c1eeb5bb8f16c5f4c075defc668e");
            result.Add("an", "6a860001dc095444ef137904bfe376d952bc4e867de6049f71d22a79cd4c528f2fa8a8ac99d9dbde9fb9eef8395f47d988d418c7876cdc5f532a840a51148f49");
            result.Add("ar", "e0511cfb48d1617a24f131857b246067b265b1d721d72de41c4a80d77b4a1f50b1e09a87dfc74f1b4270f4bdd2b564c1381079677b01787aee70326da09722a2");
            result.Add("as", "089b8ee48fbb64008b7c4f887558ed3240dedfc913456535843f3745fdbc1b32690b9b819782c6931d8ea3169b4cec7c150368ffc3288ab85681c0fab8f2bccc");
            result.Add("ast", "6941595868dcd5ff1c391bb0b2493c1b1cf3c15680c0392dffb2a3ff5a4f387da020c625b8ab96bfb323214119e1db0a7d4c87fd7190c94f98e6ba05b28f652e");
            result.Add("az", "b056ae1a4133f4496ccb2d2530d55bdf531b299f2a779b34d4d0a189f3166712afd34dec5fea3d67bb7bc395a851a77c18b0c0a1b2ad7c03c736d8329bdda8b4");
            result.Add("bg", "0c2d49dfeb8aaa6bf614eccc418480c6e358278f2752f0e64ed7064f68318643d1e56b10c093557155490c8838bac048fc9cc78b3909fd093c8e2a3bccd6e3d5");
            result.Add("bn-BD", "12a56f6c5948c6edf289ecb94f26ea42a0882b8a8296840a39e177bb4d37cfae6df712a366284d1fc37419d0a31af72c995fcca0a27a220939743bfbc9613b9d");
            result.Add("bn-IN", "16da258e26a06046bc52506149af911c6537844ec2e7296fdb7aac227c5d4439991455efc808b674d76c34a06e1b46324ab53206c2b4b0c50349cca68d16a20b");
            result.Add("br", "cd99f030172c9ae75e7314e196e61037e0ff6d5a45fb930879688d13857b2243681349c939420c3ba5259fa0daf3fc2da1b3b758e0782d251db19c1f8e5f23d0");
            result.Add("bs", "e7d0cfb6d9d5bb7c59cb92832da73925ff8a3a3828d6de0bc6f86a62071f55d4e7ab7c2eaa84b19a1ac50bc9f8f6abfb005fb52707fc8efc6f750d3cdec9d58c");
            result.Add("ca", "0a9e9117dbf4d1c4c4cd6a1e4710e888cd6871de49464cc02fc14ec8f2570b2267b01d4f5f23b6a410c6254f135483b46808d350b92f26bfa56397a6860e6905");
            result.Add("cak", "874ba6ea47f4372da0b486e414bc63d97a8e593afe5d8c0ede6c2307763c385bfc4cec56ae1a986a7ccd80eba1d015af815b75f3a704bed537b922285d86fec3");
            result.Add("cs", "39cfdb9694a148526315f06d8831243822f4ae4c918c5bf6933df0800a6f23885ed072c69c145dd213fc5595ed18fd995d486d8db744a5f5ab1d76e0a8a63fc3");
            result.Add("cy", "6fa5a62dbdae9ae8a00653ec30eefcd5cbe4a8576b7c7addef08cc2853542fd47f470ec4f4cbc8bd57eae1256d0290dce360f33173e7580a8ed853ee67e5ff8e");
            result.Add("da", "5084a7f9b4f8712afa62942c6bd80b306d6f87d7143c622aeae4ddcdc6cd4fe51eb60c6dd3c91ebedd50e526f121140ef43be3d26f162ea78f5a2535b54d95e5");
            result.Add("de", "c83adc969f967fed18342d14657dfca3702e007bfe39076ec59c6da469ce90892bf0c0387f2555451015649ce8e18ae406ddebd48e3f7eb647037097d3c46cfd");
            result.Add("dsb", "a149d4eb95e24c661be25e0ad7badd9ea406f29b50e918e814d68558cfb80c475b140bd025f6f021cf41d7e242f53299dfa11a4a4ee23c6cadb7b3cf6e8a4ee4");
            result.Add("el", "472ad967313eb8069fbef4858d2f0cb3893b454626e3a45d74fa70f54e88e000d29483af5513f794253a11804292020e6a34c472e30ece2ae1dfa50f59ddeb6f");
            result.Add("en-GB", "787cda09db32c820882c2da3a9e60a3fc4bb26f12b05f436e627afecd67229eca6a3000a17eafdf1269a3db46f3bb9637094675b10f00793143b9837fe5d6fb3");
            result.Add("en-US", "bc56671388e21d3edbebe01ecb06b7c31181aefca5f9278cbfa38579445236118c2a32d53298eba3313bc7f99ac3f296d8bdfe7c389007a779788ec517fe50cf");
            result.Add("en-ZA", "d8345b8fca5bc4591e495d06a735c8d3e6a87c2db098012633390a13df15af3e0a294b843208f2ff42f5f890b3b85d0bd1821e54bcfc7890f666ac40c8b57c72");
            result.Add("eo", "527c2401decd5e7ceb38978246c6f9bb13cbb83bb28c9005a9a00bab0115c9f286cd9a6c01261097e472aba75c2e5bf46fde180048c28cd769f45d1b739616ea");
            result.Add("es-AR", "624799f0715d310307767dc9e6d76dff9fa5703be4d383a25d7bef4c328d53e2890089a29ba2a98b69ab3af4a4ed26a5197651ddabbebdd5265090f3aa7a9b45");
            result.Add("es-CL", "4e0d16e9a6eb2e16dd0d26bd0b38639a26025c4f7f8d8b0d3b1d476e17dfb28bdd3e968c7637766e1bb303bef11ace752a95dc485c74a0ef8784ce0a0d052c28");
            result.Add("es-ES", "4ddbd4620d4006f69a62b257efc0d849ffc8b086db9edcec4a0e75365bc1ea2128928c9d662719243165de42158ddc66114cd3f3f9846e8b097a056943bb05f2");
            result.Add("es-MX", "d2a715c3f65d06f7a4d57192f51db7b286bad4b1b2fa2a40f8d6b1b0628b062f00333eafa95099b6c071806e84c1f83d3b72cb9426d0d1ff164d9e801af6fd81");
            result.Add("et", "690c77cafac43d99014655b840cac50938971ce138b89e7233a46421c35a8cd4a2cd60c0bf4fc24fc0bf648864f2a45d8cf2b7b3f007d5b6963fa56922070b0b");
            result.Add("eu", "570d2719c3ffecb8e62ac5ee4225bfafe64c685d0f31d490a35e7c4f62278d61bdede8601c1bb50b23a2be19d27945929c613c8e1125ec9f21b5f4b513f078d8");
            result.Add("fa", "c9a9b64db50bd4190254bcaaf1ee81ee63b411cec758501f51eea1e600845fb8f80300692bcc017b96c70fa77be0137f532c779f5ee50b82f970ebd27e346aaa");
            result.Add("ff", "a413b18a1e2d798b42bf2daec99b22a04b293a2b0b03091280d3ad65b32134f2904127bb20fff7d3e2f833c5cd872a4173d5d5fb6dfa6edfc8bb9d5406e44bb0");
            result.Add("fi", "b0805123ed7be2e99dd1d1ab38e432b0f110cb488f92f947bce593e7a4fec46efbdcea8cd743146eb92377132371e10643233dda1b43110d613030392faca835");
            result.Add("fr", "fdf3c918ab64226ed6af24d505a5ec7e971bd7b88075f625d0d6ec8c1bc18fc63ee69caf94e00ed9e627300b9e87de02ddbcea7445e79f21fa3d984635f967c3");
            result.Add("fy-NL", "d413a9203f3716d20de570b1cf07f6489516278dba86b985525f7ce6837529b18c0dd928bb7ef4ec3dd53eaa22ed9b7461c293df149a56903c869898cee9d986");
            result.Add("ga-IE", "2c7c2a40a7d5ebd63956f231c73eaa68f38a35fe4b9fdfc96ed50595a83acdc491bd7a4d264df34006971266f295a7c68851f7b77b55c8c886e5f5c82cf52e96");
            result.Add("gd", "a86d9ba673286ba7cf7fb0ba95cdf59f7234a031a426ecd1b10fdb1ac48d9fd51f81666299d549d7d9abb55f294065feadbce7d56afce398cfce1232ea3ebbc0");
            result.Add("gl", "bf2afaf3bee15e241e3f8a604523f08486251d35da0375f76245980d98b041429973e1f9968708734378823353fbd9e5a03f664f6f2f9d318a765519d7c7598f");
            result.Add("gn", "acaef1697b43a7bf1ac194202a6cee5b1edd41f0578992fc61d558a855aee4ceb3e7a19c9a64e0b5d1bbefe629188cfea2e9c613f42faa2ec7ae5e746236d961");
            result.Add("gu-IN", "588920f51ccde7fdf929f9b210d83be6c1fd3d898826b5b7bb7242dfb5a128a73157e845f466b46888f386b2d6fb0ffe124346e94d26643de6b51b6d8aed1916");
            result.Add("he", "25b31329752ea13222a75e6b6c6e22a690b9d636206a59f7e30377ecf8180b22dc28c02c48ba46e47f203e497b4dc6c4d05f8bd8ad7310cec4a02ab4e05c58d0");
            result.Add("hi-IN", "ebf576b1d407ebe281a27ab11ab0e35d09a1ae6d500177f33c894d5f0cc2a74747b1a75dbb951ab5bc8f6a829fb8085a8ab4bbec7f6e282a4851937ce18f468a");
            result.Add("hr", "6e73f2a12a486f4b7a0436b541d5e6f652cc948321a74ca34933521e33e4ce461dc97b6da9d9550b32d48b16004587a58955ec81073e7a94234de45754be7099");
            result.Add("hsb", "b875f1117bab407f54f329fca414c6dfd33650e55f140183dc97b0df16ad81620732f10fe83e81e07031aff6850242ab86f54e3e3e12dd3ffda813c8553c9872");
            result.Add("hu", "060674535f06b3475d948e49c23f466e39b907d0c17c6f1a98d30823531cecd5000c1379df866d16209ef99c9d8096dd12373c80bb7e2f212d769e01e412ddd5");
            result.Add("hy-AM", "b5c9c4789e6bd3c649f7f2529579a934d09bdaf08d79568793a6a176f743a6cab10c9c6f7a8e11ddedbdc2b1b0a9a2bf3f5d328d1751d940efa1dafca6876474");
            result.Add("id", "d1e4a178549f811b936622236013ae291a215ed4b001204c039ef599f87c1c1a722654844455b434915ca39e8a7773c7ec638f4038a49568adcdbecc9806429e");
            result.Add("is", "babb8e01d2145821df8cb038d60e36ea2bbaf1e3aed134287b203cc9af3de1e5267587dc0d20449dc4da131e1cd7cb6e4c553064b7a15441a9c702ffffc9ab30");
            result.Add("it", "c1d4de017e4beaee8ca45f6b385e9253e560195b89650b544b92ad95f91e01778a1ed0b4c95292c3d5707a742058eb928a76d55891c32e24bd591b0b3c12ac02");
            result.Add("ja", "8a350bbad4523ee000a93c30d158c621f78c3d1e998ba8b3f9317ea5b98684789eb52c7c9f7b6b95bf04e8ecc96ef1ffd891c1d397f19daf3eb1cb00733454eb");
            result.Add("ka", "bc53ea07790c80108b0efee431d2dee9e881db64dab03f478bd52505e6563e2f69a61736eff1ff3885051f9f2a0d781e1aaa756702a2b20815d5d405e383f32f");
            result.Add("kab", "46764412e24a2086a7e825bff4bd60dce54822100b0a2527122df90ea432cc76ace4b8e591bb61fdacafeae184a648fe22b1a7a62cd4df02f50f538c3fafd9f1");
            result.Add("kk", "df2baafe508eb3c59b74ee660c0dff6db424e4e834cdece117518207c071124b6f88553f01f7fc26cdbd4cd53c516aaa87880a7d462a9d8914bc7d9e7e60e74e");
            result.Add("km", "ff42fca38843bc36eedbef7abcb4a27748a602ed367d9999fd2c8040fd90af7be87bee5552716318dc94b153c11d64263651c6ad36d01ca3afe904845176b9e1");
            result.Add("kn", "a74b595744e37f6da4466f80165d84e9db2bb914695efeba8176d2bcbb02febc264e04ba832202bfe6a267eebef622604c1b926db3ba97f6526cb5c910e49f78");
            result.Add("ko", "6fb4f191a0d881363307f4be9c3e5996859e9955098368e56e9e7d6150e5a27e93a4aeff651f072cbe289a3401280600a4150de1029f13d68e71de94da6c0a0f");
            result.Add("lij", "c2afd262719ad65e116c50fd287726042d00a40a3c8c5f2efa6f1684c00941a612ce9f3eebbe605ac01a7f5ba1cdc8ce256172f632f854e1dcd70503816b6f7b");
            result.Add("lt", "e72b7e88a70d85ab0f540876052d95395a2736af5218094fe8a172701435508ec8c9b7d679d6b04f81984129f515159564a1005fb8412122f6329aa9e5a2cfe7");
            result.Add("lv", "def358fe077a4aa9008edca9b505d5f8677fa2cc96e1606f762bf139305e24f964d20eef8ea0886047a780652130f16136014dfd1f70f8ac7b0a945c6c07f54e");
            result.Add("mai", "b78f812a693afe89770c671e9b3b35619d92b94fc403018fe77b325953d1bb1b29f574682734adc060a72df6f92d71d911c6cb4e8dccb381f74d4e2b7a9e9833");
            result.Add("mk", "894ab517ef2a218c5fcea4b9aeb86eb20b9dd3ba3b1dfb66f81161939f19a279f03d4b8a48f8de8f7999a080a2363ab2c86f46b37e3f81b6d10bb7ef439e8548");
            result.Add("ml", "183d2ea6846fcb5c76aadea254661657d870e1431d8b3082fd8028fce90d5376971ac27099ae639408779a8e9560c6fe3885db2acbc8fa9bbb4e996ea15b29f3");
            result.Add("mr", "495defb9aadee6aee81eb7b986adda90c176ddeefbbc1e0948b277780787ae6cd643a3a903074f4d2708cfd09e8953610cf0766eedbc3917379ffeb9b99b5aa1");
            result.Add("ms", "8f23fad9295d06f0e97e54f4edb7185df66e2db0e5c8a6914c11ced21d56f0492adfeb22802c8131fb45757f5489302764f230f375efb655c371649ec05fa38b");
            result.Add("nb-NO", "e5188b1dac492f862ac4ccb74c1126d6e1973887c003b05a04e98df8452aecc719b6037db7cf11f4596dbfc745ba757cc57b278d4f242e15e98dcbd6ecbfd133");
            result.Add("nl", "75d4b66294d65c186f479e8ccc11b9c6e8467049f07fccb40e82a069fa6386e437db2d545d8ed2eb4283b87a51f5ddea45cba5dbf61bade15bc5a61e4259919d");
            result.Add("nn-NO", "c348af07cf53d16333cfd9fad9d0f6ed14175270db3084b53fbccd3f391f32df0bdcc81eb7bfae1718ac12efd27d9dc65436c7b64d55a5b5bae5ab52319f6cd1");
            result.Add("or", "9d3c134a20ee610c5e0017d18c321152fd3f9ef95f9cb8d870a6809bfc39f9ecf5064ab1fb54add47d8bdef01efe861d4468692a3e515b0a93f0e13cf408358d");
            result.Add("pa-IN", "388158a05082bb7178d930f498b12e69ddf51a0371e46709ae27ed01f198abbefc1ad0e0d56a5e60b323ce4a51d19336921e21469530ee2a42382586dd869be5");
            result.Add("pl", "f2b57538c1b2cff2ec0ef85fe4a12694bf4d602469dc0921e7b5202650fe73c9341fb744ab5ef587d68f1fa650b9f68eff524ce9f21bcd54eb39e84bdaebbdef");
            result.Add("pt-BR", "6effec4e4f25186e4b0e120d4fdd10a540240fe168060f745f6b1639bbdb4e3f06ae93193a6d646c84254488a545a1733f66c0a9e984f2f5e5d67a8aa6792b94");
            result.Add("pt-PT", "16850007ba315598de7d0d8080407d5b430db0ec3c9eb2f8d60f718af2f55cce1473da5393780d944ede26815be8284f1f29524c9ba1a45a633058b3186487c3");
            result.Add("rm", "a28819e0845b35531614952dd6059b95e13edf0df1b3f6c835d076931a1ed773c6ce5456cfb3611e9bc9437e8b731f8277264a7aad926d9a9f6a581cc09897c5");
            result.Add("ro", "18a2f7134525e9cf9fe872b9db23985d064e24f3864a94bfc664d6d5bed849015ef030cadb522ca00ff6a0b7eba532c47bbe2b5924596d5438b53703b26a2817");
            result.Add("ru", "6b65d3f93b2cf60da6cb1c778b72cc4346dcf8e9b641df9437a32ebbe841ee526f634ba3373ebe62974d5e3500cb2bbee4396ee509b59f9155eec72a4e9f787a");
            result.Add("si", "5441695bbb6c3c4dafe4472318619051b9b563991886414e4cdfc37f0d081374168439968f386e50bd5cac55ab00e03d2857864d493664d2f5c7fc8439e30683");
            result.Add("sk", "85065dc3498de6f2087855ab65b4a0a21e7adef07a62ed0c540b89ecc4940c2fe9d3c3a535d9338c506a5ebf31758e8fdcce2f7d59388409abdfc8a4bfa92a4a");
            result.Add("sl", "1245030b72213c2b38f71d1d23c713c3fb38bd130154265c9d5f2a26aa3043f84a3a1a9c2c230776abee4142f77aa8c4825ca487a19278665fce5cbdefe161c3");
            result.Add("son", "58de812edc03c95761e67e39d80af70c7bc22b2f3ab7a4e97cdb06d066b732fb90ebf9526bdb1fbe920841ac39582a7e4f1e744a20f6e27640d2772f5709a9c6");
            result.Add("sq", "50f10a79a55dc986161d6e73a716e43783159db363f011efcbb3f35532aa5c40a095c3d5b2080cee6954faf2e0c3a089c993fecfd7301abee7a90021d06d8ea4");
            result.Add("sr", "5d1164b56a88f0583224e67a3e4b524fe2602bb2ca9bf614699272e30330a0600aaf794bee9d0992355f848c7d98d3cf7b3e02068f44b8f666135dbda0e00e89");
            result.Add("sv-SE", "714eae2e24506566399ce3a1d8476ecd6ed38f5fb6eb9653585ccfda44e41f2d3773538732d673f1dcb1103a1a26f290430f0fb0e99987c5cb24e00eec900ea7");
            result.Add("ta", "eb72948b2953d1f0a47a6502a30df3ae1dc514df5f9544be0244e528818f6fe4cf376ccb12752749d2e83481d1fa58a931907b1a5c176ff0708ba4ee06bb07b5");
            result.Add("te", "4700f8e67c2e3de7d1e03fc5cb82247ed8a2e528ff524e65ccb7d504a35c9f315fa539748806506c763792a02176d46bab8e2603d9d9c4e4f7d267012f8848a6");
            result.Add("th", "f004b76bd54f02a337b3137468b4b3c8f298343d132609f13a56f704ed03c1b3acb80b6fc63de6794c168162b030ebb24272156061b7c00115b7430d77b8daca");
            result.Add("tr", "20706a7041b9814c29e9e287b79f3d2aea0651b13093d24027ebb3b25dd6c3f26913d38f1f41fdc63a6aaeb3ed2b19a31d263cc80e077993dc17d0abbab46702");
            result.Add("uk", "4fc321035ff81e5b52ee5952c13c7048f40abc59c9f365de590c0602885d91885c0de8576ea6bfa4f4ce9772e0050acbd39be3217e64124cf8d2d8cca04e9a53");
            result.Add("uz", "228ba355254c4afe8658a4a7675d8b19536748895327c09d8902b31ba94da736bfdb2783c3569ce0491c8fff36f5147b8e78fea7484e4ed897d1dd5e06881bbd");
            result.Add("vi", "b84e185ba639b3489f78a173b0b11e62938e3688ea5dc6499137770d8c718bbb335214b9de1dd0726a6ba38340067c8f353f0fa53bebea04f22ba480fc1fc842");
            result.Add("xh", "c6c222f8283a9764120a0ed101888ceeea696b8134634874e1315fe35aa0e538edd8433f9efd8716b86a6c3739a5d389986e5bf2472ff5fcbe2444bf116065ea");
            result.Add("zh-CN", "acee81bf60f1f2a3b71cefbd44ee31444dc625b4056b8db3d2482e41b1df6b13b4d0f90174da40a4936549b4b55a8fa4edf1acc8e89278a0931a2c4236646c3f");
            result.Add("zh-TW", "816abd0ac5ca7439798a27789197d4f1e6553c7f742a6991b40185b31e2f2967b9a4f15617b99f0829a6c8083202fe593b91714ed67f1f7997c91823013dbcaa");

            return result;
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/52.9.0esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "9f570cce3567b19de7bec44b50e02f1a99370c5bfb36df5995735c8cc6004a051f8a1fdae597d8da44574f94fb72450c5eeea59be5ce3cd55f68d15249f5566f");
            result.Add("af", "7a0a6fe77c0c18d7b1730e2c72d6fc5a63e42e6621a08d9fccb20997c66b9a618f613905393fe11430f40cd82f44f659b35d2890c4b4064949f9d9b5f701d7e4");
            result.Add("an", "7387169babe943cd70167708f663fe5eadd7b9cd094953e1791487b9e0723245d0c53494c0703ea35fab56233e8a19d77ba76eaf18466df75c3fc157c2c38ac0");
            result.Add("ar", "8d40eda549342d152ca7b3c92162c8e5d0f78ad0117947730aa6166930fe2cadb3aa8e83e0532f3724a3c977b2bc8c5dde7557ff6b9f8a0ab620094ced5e9b46");
            result.Add("as", "6cefa79ececd6dcbdab7a6a38b6c82274df8cdf941c6d7bcb70bfdc13e78fb92a699d7542e3c28b848b19f5f93517a66e30cdbd685d7427dbbc2cd0780e7ec37");
            result.Add("ast", "f7793476fa81bdfa1c7f0a89b37a5418f874c68d60a0cd138213ebdd8123af10ce7d899008a3b648629947aa6c52f252d64b83fe925d7d09ff038bb05c88035d");
            result.Add("az", "bb1b5d2145472cdb13239089d82f44888c4eaa0402e6b70aa0d72da2da8705a07e31bd45e53f5c1d73b89d0e47a4428429faa9e611e569d27a54055be236f581");
            result.Add("bg", "9555e0d5c881a3e625d594e0b8597724451c9f127d5ce531f4d20063b062fe7096d79a4316861aae7de928ac7d64f579d85a26c0b2844ea5de27f26c63314baf");
            result.Add("bn-BD", "9e7d2416f527963e303cffe5b334594813c39e5f792452e9ad619881c0e6648a9122393f010b9dd290a18a84222bd61354617f374821b17dc348290fa75dd3b9");
            result.Add("bn-IN", "facf5e84f6c7f9ac5ccacdb9907ade933db479d5c3ea452b12819d80a97f1cfd59455761f444e0c85110e1045b096d5d666704afd97390ce4d65563d920f450f");
            result.Add("br", "c7e6f0c1f05bad2e47161dfcf9f6f079cd8977658d54dee0b62a468c9aa4cccadd024de8e51566bcc443ea8306b58fac410d885cca305e595b712f5a3cf38dc3");
            result.Add("bs", "68466d8778bbf9f7679ba2c63a483dcb9050ce67b912960aeb99d3ad0fc355d744a765a417f7f6b975a9e9ec2ae24d008967a01e0ad0cf4984c74f461dac9949");
            result.Add("ca", "b98af2a1285fe911089ac413d12da73808e5fc28fe78e4644de04b1dd9c95a029b6323639c31f5d3b9d991965ee953281587162431f294ec135bb43d2e5b95af");
            result.Add("cak", "4c0e310fd370c2c15a66675e1c0176a854acc3bb04c217563f9fb424c4b24fecdf5f422c59dc4a85fe135940cc556e3d1740e60ca60011003b42e0b5f62158c1");
            result.Add("cs", "0d0d4f539f216b536554449328bf04878c1a06a013fb050734890219edba3527411c88aaa24755a3a4d8b0c7ea48d78f99c3cfa0add712bb6f31456334fa6cda");
            result.Add("cy", "7145365daee34430438c7b1180f67b0cee2c19f2dd012bc94cc71bec4dc7124ffb6805f4ccc79e1d54930c89dcbbcfcab69cd78bbdeb753c0f7699b07d0b6adb");
            result.Add("da", "e5f1a8b4dfa7c53fcb09b0ca2e962c9edc3f8d8352dda9275e2ce7e869ec675d1b8b6ec5e95893ee2537e72aa5b15fbd80803aaa7f7ec38e14c47bc309228676");
            result.Add("de", "b46ad276f5130a5ba5174936db7c8455301a6a75694cacddb8d172640d8dcfe32cfe0912e6f10c5ea9f74bb6928d223f6b4795f0b741705790f8a4f68d58685e");
            result.Add("dsb", "57d47cd83203c65923d367b07c88d4b6cf9e25b9de7e1f0a14164379a4cc6196d56359f30debc040411b9f57a2e39f17d2f0775fb2d23a2e3ea93cda9368a93d");
            result.Add("el", "8f61308cafda46cb84ea9ef85731db110a01afae9f60cb845d34a2a22131fce84e414ca7940a6be446edc2d9b7403d3554d4f2fc45bc233a8f633ae1390afa85");
            result.Add("en-GB", "aebb8a56ba200c3dc2c247b7e7cd12babb3bc69adaffd41f33d326e7b1b2624a39424d73590f337194350cb50abc0e3d111d5eb00a8a036a84d871ce02b87ee4");
            result.Add("en-US", "48137a18ec406ab5b34eb28d66b063ff8f20e4d12cfc9825dcf0761819e5ba8c545eef9a1ce2a07eb46864212fd605c87378c6f353cc0c67d4ba89ca579e0b05");
            result.Add("en-ZA", "5aa7b9cf8cb21abee6df6fb2e758398901ac29b27bdc5f831ba9f958600757931ab3b9271531e818cc0f906f8a44cc95f2b7e16202ea6388c5889f6cf4d1e01e");
            result.Add("eo", "6785fd98d889cd59bc3d8141c61925bb162ad62a2d9f5aed1cf456424d3341e09722471b67f9c355b116204a381f90f8d4a60159c19accf4dc97a57ba9f2dff9");
            result.Add("es-AR", "6c24024119996e2bf2e36f87ead5d08cc8ca6a87b34172422d1bcff6ecc8e3614ed1724f703e3c64f5b1c034600014e6cf38de8dc40bfd11e787b1040d701313");
            result.Add("es-CL", "fbe84718d45a28db8203438b9a79b333f17cfc7ad9f56bb59914e643b2a183fb7d6c62736acffc598c15611c22ed33c42077468562fd1d45b186ffe22d6102a1");
            result.Add("es-ES", "358c6c564c6324f17e571c3221bee1522b2eb9f91eb91db057af27523644d96b218733ee1f94fa6ad96c2c4c27279656e1126661a494cf8729680481c39298f4");
            result.Add("es-MX", "e209aacbbe3174578e0b409423237465eb95346548eb0c93a2959c7f62225df45595b243e92a12376a627db21c0a3239e1963820aafde8c3ecd5ca0e01597af7");
            result.Add("et", "d10e54748564d5ae8780a45132402e957e63938aa5119241ce3b738709573f3c4309f05ea64a526173694bf8b86e7b9ca051216cc0ccc5a97a024bd4711fddb4");
            result.Add("eu", "e1a03bebe61c80d08070cac03c350674ed94c889b1572362bf2be268aa94b29944068a23bfee21f211c80fc4218166238977d6ee7bf76253c4ec3c1a3c990972");
            result.Add("fa", "368016356d639392fa36872c723937d52041976bd691e2968e3a8982c7ed1e5388ceb6b4f17e6af97b63231f8d6981ea14818525eed52e75ee84499b96a70a7a");
            result.Add("ff", "7b249860d493b5a893956d4c7e98905129dfc265eb8d7f2c1a1063c828ef27c6983f15b41c36cf3a34e85d6812983c0a879e2cea4932454229f32348dd4bf69d");
            result.Add("fi", "3fb96a0a36f2ee77347c480eb6be17c732a4fc52a4db0cdd919189a9473287854592fef5dd80ff81a88c716aef01670499a6dec1b0a15dc7af60b1ab5f97c380");
            result.Add("fr", "143c166e4af31a488b951426dd40c4c490d8fcee41f6ab9edf3c944cf11fc41efc45a817b6fca1111ffdf3a638c394dfbd5cf65e90218d62da2f209c8a0403e3");
            result.Add("fy-NL", "3251af2132dd0034bfa0baad4f8edf1e7a5a19f9fe0786b7c5361e68220f19038e0d02b4b9d17155740db2aa0674c81ef217c5aaf27538f2807921d4ed9b62d4");
            result.Add("ga-IE", "dc6defcb6a51341ea2d52e516603187fef0f962384e14fdd7399dcf774bdd2fe0d7da4d809db56a69bb1d3d2a3c0e761be1cb47f228460ca98e9949f7afe841f");
            result.Add("gd", "2ea17ef6b64dcbd76fe349906c55237643d84836721e51e31400e8644f9f1ec4f6f6278ea2440b6e322255a34adc14b98af2cb2da8a4db267982ffa648dadb09");
            result.Add("gl", "f82893c08b734359ede9cac8ffd4811062c75829e3a7f63942aaa04c546d2408bbe07a4638c573ff23913d686defa173a87ab791eb0c8c5c51b716558bbbb5df");
            result.Add("gn", "508f2965b0ac8aae7c9f033ff12d3bb8a6e79b9d871bb101405364214568ee5b81d1af5fcb03ea7ae0e51e89628ef9ca75649192cf39ead256b8b73b52f2e975");
            result.Add("gu-IN", "48a486057c639cc2f4ef8987b587c6ab6d89e0343d4e46b7d447b406ba493f3a38df06a234fc5d49707d56ec2148866335149374affeecc3806d8ac23e4f5b71");
            result.Add("he", "b237bd53ef08c55e734d3a3032eaa69ac0f339d56d26f7efebd3d332134c09287f88521ffa40fa29c8fe68baceeb990c6d2e287b1678f80c09a37e730673d39f");
            result.Add("hi-IN", "7300067cbcaeb479041cb6d9caa83cbce893a6d0c78d54f3b044eed4ba24afbceece222dbb90c9a5cf1d4ec76a5bb1cac3d624619fecd5c9fc301a83f960856c");
            result.Add("hr", "7bf5d3ce47f3303907c5a1853dff3afadba37adaa229d75c9c87ad23c01d4202a792ec5d4b48a357245ee072335685070db01374f0a3c7445cbe872e7ffb3f86");
            result.Add("hsb", "07772c4a2aa95c681b6ecb2f3cc2405d1647eaeaf2ed043a02bfdf0b179ea89ebef829e2d9ff4a93361c4949af07be366c27930bcdbdea2f33b96500e3cc1850");
            result.Add("hu", "dc2a7d36fd0798807145d6db13d51af54e70f0677dd03af0cf63d09be09e28c8473f903fe6bb60b65cefeed826d9545517a0fb4aac0d449db925759ccd9c943a");
            result.Add("hy-AM", "7ea1a256b25f580057a9b06a10a86e85fc284fc630564578394e187161aafaccc7b617c45dc15e50a5af583e4703d9b99584ebbd8f03b70f2fad483a60482796");
            result.Add("id", "81f3299e8e5ba1a8b6587c1ccce0c2321f879f1c4b51744b0a625dcb3a63b25d1b337e15ca77c6f453575df49694885df73989fcdf717f59db8a7a9f5188f0a4");
            result.Add("is", "085b6021d920f3f9ca7a6ea10bd789833acdae55fdbdc864d689e63d1157b3b07467ff316364ebc269863b65785149a29a6340b94c5aba87c3ddf1fbc246f962");
            result.Add("it", "d2db4699319dd48b9040b1703fb983c209653c532fe5d1c3329dc03cd6068bc1d6d6b8bb356667a82a12b36b388287ba5aafd4d1756f356e073bfa7fd785551e");
            result.Add("ja", "9b7639794b39d117b5b2c188a4c93d1c83756bd30f257fe226219a65e7ddf694125739c14f1d96784e70efa8cd29fa0662ea3fd4dd0b62ed42337f5135f5f625");
            result.Add("ka", "1c27c1020071f9fcfd9fca4786ab7f70321ac41bf5ae25d9c8b42e38b32118d13d3a448e120a2dc80b548fb1588ee24ff5a62520aef382a34aeac955e4b893a2");
            result.Add("kab", "30ed1584a532c861e7d20beac1e88c0cfd335410fa7fcaf9a606f3d8038a978d8028f5acb8913dc609aaaaa2f5f56de59ff8bdaeb7f0bc0709100b55aa803620");
            result.Add("kk", "f5ba4bafe5878c511873f0b072dab26d0a5910ff81e210848b2ed44c5b9b27b3ba96178179402eba593f8a0b4719ac74557576546ed34a5677e40691e9f0a716");
            result.Add("km", "d8b11a90b68e20bac024e6fae2fde74d528e52506be7bee38dc8baf1d5c20f2ada7c5e2d7c7d83d12729e8b64805f4c4164e04067e11eaa88583046d4c42f37c");
            result.Add("kn", "84adb99fe2fca8510b460ba656a09c3c1b03f7246f303bf86d509bcf0f79f95982d11775e0594e497ddd00182cccb843e4a8ca1220c19151e3b9907712b4fe0d");
            result.Add("ko", "6f3d4b06e1eae072ba9895eb3f99a8e8d5139be5ce0e97cae838ebb532de0ae5d78d8051111a25e8bb19deaba7b5fe9a1a838db409c6d18f31aad3a120c5a0e5");
            result.Add("lij", "9b6401edb22459ba56553047894c11dc55371d839bd7e6f0b8a70f84a36dea84abc7053b5045ef73b45b30c32627ff3e0c835188830f2497e9a65f77bd7e5520");
            result.Add("lt", "1f538b5c67493508aa29ac250fc1ba7077ee4a2bba746c9e492fa192e3f078f34b063ccbc9793b707c398e1c3e877a0010f978fd588dfd388870094a8d67d37b");
            result.Add("lv", "17bffd8775b9f608d93999f8e66013e72a326059f52bd0f747620cec9a529d35a3110f736cbdf9012d959dac2d2ee070878b916f5b26c516858eb463577778f6");
            result.Add("mai", "1c076375ea4759f504f0aa1a03ee98c2da709091b25d96abe3062a7515d99c445efcd2a346d7fc92a4ed8edf6438e5f8108fac7be1806b198fa53c2b0f9f4739");
            result.Add("mk", "00ae934c3328d5584ed64129beafb28c896dcb9b6b36de575662bf85b33334062289accfee17f6c10fe94f9c0c74d8f62acbdbd0cacaa656b3687d5a42f21d8f");
            result.Add("ml", "21a74497db4e35158432e02dcfabfebfb16cd6e91a6f3287d7abced6a0bdae41a79f5bf88efb8718e90076581244aba00359c735ffd755dbb20cfc92a0e61608");
            result.Add("mr", "f9f1acbf7a05802e48ad0c5cd4777a408e1b6b0e1ce81c6e3a4f5ac328607c98597520f3b5b089544dfc9d26d7788dad23db9e75394de716cf0d0873b3bda083");
            result.Add("ms", "4633c713809dd8e7741bb529994751be023fab1261d27e61390a28e2f26d67a8930860e4bf7081c39869d75c7d06bbe3c26457957a31de9edf3928baec492e21");
            result.Add("nb-NO", "353f19276283f07a4449eb41ffabd8643d44302d615af18c57748beaf52b4e300739011f4300e5e3b4bddd463c21b880330e71b44592900b9c291f7e8b9299cd");
            result.Add("nl", "e7b4dd0b4a710c98d79db81fab2e0a43ed9c81da6768da2d5509cac5a4169e4a81b9c41f764161c1423808021de34af93eab9020e24615899e941986cbb717bb");
            result.Add("nn-NO", "cc57a4329c116c5c75d49e1ede504989c4256d9e702cfeaecb7f78052aa7edbaaab8da047298efd8d840736acad79b610ff44e99d11575eb3ca0b704dd93eb71");
            result.Add("or", "a2ee3962254355df9ce7ca0ffaf9c1769df380cb1f42dc92239f40819ed4615bae7c4969d1c6b4c1d4740fc0d744c564c86b081ba05c7ff47baf9e76f36e1f40");
            result.Add("pa-IN", "42eb5396521cb240b7934225235988bb0a6b6d1ba8d4e9c88d4673bae6884093d23d5a9b671a8c417d169098e7e7bae1dc773f1043225a6ce8be38961ffdd123");
            result.Add("pl", "e77eafac4cb4f22071715918b1a5f66e50e564974b095850e50d55fe9de5307b5f69b79579671d65bc7c5098074043863269d588e7723be5a0ffa5ec759c45fa");
            result.Add("pt-BR", "3da74d9b52900ff07809dc97c8d3319d14d3191d23d8ccb88b408a690f2ac1bbb339d5a76271c73d5ec185ec01cda1edaf9f7bd9b42edcf1e11af8c4af963d83");
            result.Add("pt-PT", "c6b5dc42ba4b0d5632afc4b496dcaf06005ac9131c6249d0ed9309c959e1c2c63acac539fbad90944424de1332187b7039f6c0c151ea1d649a3508c6798a8e6c");
            result.Add("rm", "f7f4b3019893197f02e6eaad68f663ea44dcfb2f6bb01a87067b7d6bb2df0387c5af244c37f1a4404b437794d6c91156867bd733c71b17b5b9a8ae2239234c41");
            result.Add("ro", "c29520a518b44906334e1f24f3a49210cafda9f22397717789c43edc6c0a1a6f831d96d2dbdb6739c1f1ae5d052b8ef87a911f8c00414d29f09f09e9ac371468");
            result.Add("ru", "7bdefffd290e3d2fc9d941b0257b40c84ae1e154ab92e57f1c5058e6e3c0f23ae815d3699a7941629e2a5e715c9c83ad76a2a6694dbc6d2cff3728de6a24071d");
            result.Add("si", "a41b79b7ff56db3c5527acd1823c192cb1c2a03e541bf62dfada3ac871bf4fe2fd072e0ebcf42b4b3a11e6f70b751ffd717c92c8b618564421d4e8fb9eee5110");
            result.Add("sk", "41e0cdee59ba2fbf6fca04aae59df0ee6b58c2fd3b2f1afd58ea815068ce1a907195a0ca0558acda689b622d58b33c31a018330ede948c9be7d01e72a4a28f42");
            result.Add("sl", "3a367f203973ee1a6e56ebc7f88237e650e499e860886e93a5a61c4f7285a1478b5e1fbbdd20423d43f198eca83b673ac35b60d66e0d674c25dacc4ce1571e5a");
            result.Add("son", "84d5e2fb7c09b4461e2160cc443132e866a07ce90a3e71c88fe26bdddcfb223d7be898eddc33cd16f3ebf31773a203fae3b42771f6061c53d66a1171c64ea93b");
            result.Add("sq", "2c0fa9a5cd121b73469206a1d3a4d2cc59b4818c10ac39814c671294e2d6cf46bba38dc54a2ca8cb6cbff91655a030be19126c85e378e36b5abd179fd48533b6");
            result.Add("sr", "baea2e75c25ff08f3b367dec8cb4e2f558740efab1dfa83a3683fdcbd821d34a31fcc393c009d42f310044312cf709c0596542855eafc57897366136adbd0c72");
            result.Add("sv-SE", "42e4074441d4462111c57ff598ada42308140c9e827c4f9364d0b8c24929533f70af9472d281fa55ddf535df91f1be85b3e201f3391665225bc434266cf4e2b6");
            result.Add("ta", "f2e73ac9f177a7b771dce86783340bfaa99597fffcda932aa0ad808865ad951bdeb6305204296887a0c13a2d980d47ce237e5a9fbbcd28ff073b39135388eb5f");
            result.Add("te", "8f86caca9c794f6f3669890416ac4bdee404bae32c6abc70760178c247a4f330cf18a4ddc541389bb4e2d598024ae0230584664cff4e44ecd0436ebb2e62dec9");
            result.Add("th", "53463ef670558350f4619cfb2de7957298031c9d061b2198cb2513034ed182474c2c900d661f918867d5568724b475624ae9a2df6bcc21e03bcbb760c0f021b4");
            result.Add("tr", "aafd1f4395189c41640fb0610117cee24f83bc9c0a1a134e2284b5da61cf13c4a55af28a5b3cbd9a7a0524be08324be134f450cfad62a60b17479cab44e774c0");
            result.Add("uk", "3705ca21057b9943f3a18d7e455b27eafc8a9fa6dd3a2d2dfc6d2ec1c41fe9e67887184878a581e45d32afa05b45e28a6883869e4583ba818a38fb342d4fb525");
            result.Add("uz", "4800819ea2ef313175952208b4b6067e9da768b9b295504320c395e2073e93d24540a1549eb0f4ca21843969417111e7037a8392ceaa43abee233552831f4030");
            result.Add("vi", "44eb573deacb78f6820dd6b1ec49d58f145bbcc0642a6c632eb5816fe1a54ca4d96f87bf4bdec504bdbf18b9bdcc7714d14538df2bc145600b0d49a6b7ec4cdb");
            result.Add("xh", "67b55689fc41eb4de572e00b8f12acf8bebf822c75c42e8d7dd452cb883fe781ffc54412fc723623f2c7ddbc1e8ddc05bfce675a1ab8f65a7b090f4466063af5");
            result.Add("zh-CN", "db64d74c639126d65b0f7735dada8ec2624ed5cd240ba83baeca221dcd5c3d33be622fd276f87450d1cca39260ccbd13aeb7ccfda7c4236125625de660203723");
            result.Add("zh-TW", "1cf7e62500b6c8024ad374ff6a05ff2ef09646cd1fc32a86eea77ec002073b9c41e27855706912d557e5b0890a3927ed1ab7e2accab146d402c2954b5ed0897b");

            return result;
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
            const string knownVersion = "52.9.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    null,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    null,
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
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]{2}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
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
        /// <returns>Returns a string array containing the checksums for 32 bit an 64 bit (in that order), if successfull.
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
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using
            // look for line with the correct language code and version for 32 bit
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value.Substring(0, 128), matchChecksum64Bit.Value.Substring(0, 128) };
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be update while it is running.
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
            logger.Debug("Searching for newer version of Firefox ESR (" + languageCode + ")...");
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
        /// language code for the Firefox ESR version
        /// </summary>
        private string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private string checksum64Bit;
    } // class
} // namespace
