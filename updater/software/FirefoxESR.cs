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
        private const string knownVersion = "140.9.1";


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
            // https://ftp.mozilla.org/pub/firefox/releases/140.9.1esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "19b8b31048024d04f9430c1effe6cbc128c43371b3914c8e1847d4608dbba80df399da0534f7ff5a1c9b9b345afba5343652065a1439ab9381c5528afb08c560" },
                { "af", "79551ab66d0225d23a242ec0d1b4c7d3780a473064a43b5f34b4fc46a3da39d96bf0c91db0d3290251b2ac49e376ab10832616879e6ff148a090e41b32b41c2a" },
                { "an", "ca7ae58aee83cbabbd66d21e0b8cc5a09b2a3973bcd0a9a50be8c4929a1d579164df0fd26fad7bf70c395eeaf30cc5841f1f9f7cb92ff8769fd3e8b2fa730ba1" },
                { "ar", "600b1a05627ed7c6e0f7b9c86692f6de4e69db58c8725786cc758c735b82fbaa9daf1a145c0db28f7b826938e6749217f46bafa559628443d6d3abb92f99e13d" },
                { "ast", "62290a0a786f97e3cfd13f07165d9507ae840e9b77200eb17eaa22952b537723c3aa3ce0a81d6e8b292af84026b3d190d1d595c0d6dcf90d63aa047b5d6bff20" },
                { "az", "c2c73d3355bf6653bd952f3adc6e466c0a5dc24e944ac51d67e1d2bfd414fa24409649e41bac11b6b2348e88a670382f6a5cfe462a8290e4e8cf4d0055b6e911" },
                { "be", "fc2e704b16e8c975e00b802db6ba8ba1eaf2d43b892b966472edff024b0e9c88edbcae5c1b3c672752b6012de4123975a801844605aa5e358c643e6cb59c7cac" },
                { "bg", "a5af96dc6ae75e7418553b34add26434a51468cdaab64713182f45f94f7d3ed34a3539640b0f76c0dcb618c95830b8175e78deac8c0e9820a4b52fca75edd53f" },
                { "bn", "bb7990c781e8ace26722a2796fcc8bb186dd2e7b256614ec51b7fc1a972189abca18de683c732a95e7a7d008251564eaa64a15b7b5bb07e59deb3900f4cd19f3" },
                { "br", "8f5f5e52086f71f6f9409e15818c16c17cd2a2ec319d43c4c8bbbd9cd0882076ff01adc54d2124fab5829fe1b83c59625e9fc784e9aeb7965cf6cff76a793924" },
                { "bs", "f8f5918fe3a66f9ba14f0e52daeede6c8f2adc4531d4d131ac8f4f0ac7de75fbd6295706aec95870d3c7d41ad8c6cb904d70e65e5ad2da51fbac0147392fe00f" },
                { "ca", "cd78e1d06c6f067f730a0762e9b9e5df3cd0f5c893aeaa9b4c56f3c66fdb1329a418fd97de1276e7d009a8e0924fe7d7d4c55f65cef352cdd695cc5a52c04134" },
                { "cak", "782c52a1a5f0eafec0514c2432079e679efa6ac7cf4dc9df92a281d80d131522f10a46c6d6538d525b9778f00e8dbcaebd3a0a4ebb7226985034fe52bbd91d49" },
                { "cs", "365622691700380152b532ccbaa52e81ceeade8dcd95021b9499861ce01573bd0fa8e0b6d61af40b9343b0a7e790a87f72b1cd9c71f5197e4b6ebb38e2e21b57" },
                { "cy", "69960ef3d9ce1cda300a7549f903cc82a3a426dfbbc39c273bd703a58b86aead7d19debb5f77b874a08f17da9dc49c9281e9ba46ad7e8fa9bb13b7d0c59d1e5b" },
                { "da", "98ef717ff08c62559db36e4dfcc43f7e28cf03ae8e782403a6a0dafd26dd4a97453e576c0ce4224cbd0e94aff59e56fb7d8afa16abf0f145d66b46f24d7c08be" },
                { "de", "03aa8a59c78ba9e13800c5d0557b57e6df7a27527a45737ca6a019f6f004ac2639c2867180837825146eb2b5bc1c6dbbc6d0eadace8c7c995c18e9b1c8382deb" },
                { "dsb", "c971233a8789b5044593a6d3ebc0f8a3727794c557dcc818fc530f68e1101f85a0b564c4bdc015a5dad456aa5d0a58136dbc2c02c21b13d4c4d8e89aea259724" },
                { "el", "8fea49aa83d45fd7bfbe80098c5b5fac23ff780a6253f6f928a88682ffbf9fba217995985f7a7a6d1092a5aaebd3512cf079af972d9ac2b7eb11fcc9409df47e" },
                { "en-CA", "c58b7245c7f4f80f0eb1ae75f49d3e147b172c66f7b72e341550dd520dfba31ecd8885e6b6c1b466557ac49a3e31b3c31d4e87110367218d6e6c3b6f798e13a6" },
                { "en-GB", "01c2465d324925e44696625b3d05937d41cb4ceac203ee3a8b17ffab8156241ae4392f7334b935b0d2117e5041b322e5db70eece625f5c84a5244763841c9baf" },
                { "en-US", "c882e4a8dd0e7b6db6028a7868da5d67a9a0c737a0da03c8f16c026048395a7c663c194d8b713a8617b5efbbdec620db5b9af52917eba1975e7eb2d75499e3c4" },
                { "eo", "fbd94ab48ad23886e4f0fb47760f03631801c34e5753141a294bfbb144569a5c5d322a09b96bfd84517ba92d453e1277678578cb1f958d0cc4bd2c364ea9e360" },
                { "es-AR", "b25b0a1e1b6bb999c8f99f86073773e1a2eea539b824ff0417d1b2820ed6fbe6a030d35726eb9cafe409c310361203d154fe6690026f3e8a796a33b2e7f93bd2" },
                { "es-CL", "39a63e40ff327ef7b99aa88cc634e7ee48daac76f35e8f06f81a50328c45e098adba4c2a8cc140e6dfa1f48e8872554d75d0d5f2e7040834d81c5dc3eed063ed" },
                { "es-ES", "679733c1d5ec0067fe6920344a165032c5d6970a1f8c69ea64f0031deae987ad6343f5994f67b1c6474908b9c5b23e95c7e7ec8748c2b5f82c4363e4dba529e7" },
                { "es-MX", "d84ecb571b64e0298c28b84cb239c30f82e25a7d20ba6bcbbf3741e3d18a23e70479ff3007f1977ba50e9b166ef1029764001538f08e94798e0d5f4bd74146fd" },
                { "et", "2d3d61c33f00feffff683abdf5049b679e92167701bc3caef9db269050b2f841b59c11fc38dfabddd49046ef339d1457c8ea05e8cd6c61bd3bbacb185729e2e8" },
                { "eu", "5cbd08bc6d0a74ae91549d416584c49d6d6b2cfd1c3daa43976370a4246f00f1c53e4e52d6d4e5a1f3b8f9dacf2397ea81aa0d6bfdaf0b0a7dc497481bf8d107" },
                { "fa", "3ed9e121e1f09bf0b5b8cfc3654dd80e6dedadc7ff2fc72cafac4e2695dd015190f5607d9d02b67c6213c15ec7628643b65630aa0fcc725e2492e7a04770b149" },
                { "ff", "132f2496bfcc2b7d7e1e10e7e9751c8f1bed1a097d3828d9594035ea3e6454b24b7a34509f2a82bfbf92f8c6bddc42b1615794e8887dc247162716b218c5741e" },
                { "fi", "4b4507e306e53c3f354ddc918f3b9a462079d872f5babfb36dbb6d0793d54c365177640212bdc4b6b80b24ee17650968cdf0db684c5c73aebce5118dedf8a647" },
                { "fr", "4ab08eb239017d3c4e359cd59fcb6d0fd228e156da5ea33c3377ee277369a27ffe8e12c7a170093ef23f2e68b794fe999e8614ed6b7f8d1981be6c8c6d33db24" },
                { "fur", "38f3d62709217670cc0ddf2a6ceace859dc6855113d005b06d3c2125b10505a18b4f7daf31a004ae33848647c7ce5e1f9f345aca5155c1b4653035cdd7e789dc" },
                { "fy-NL", "f77c0e7313e225a342f98e1b3f21a529465ceed9c5f088e8f16873106b4ee15485bf16d531cf4f78cbb7031b0a87f491b41b448c4f886d5dedbcb163694b8ef5" },
                { "ga-IE", "84e471ae8d573bf40a96a752a2d9b704dbac89801f277c5b3fbbc47862cd00ac1ce65b2e369a70e52b4ea822e626cf3f492ad244100256b0b1aee8750124d755" },
                { "gd", "ba09ff901f081a71f798834b38392fa22863c79b780adc6a72d575d2566495a86a676208250769640df79e3bdeee494bf33f392aef1540fb371fe4c0a3d1b42a" },
                { "gl", "c7dc43d945adb1b837af52bea73f878b0dc7f212c66f95a22411b485e9cb9e07c2bbcc108698f520621e460c3203212046c073d05d43254ade4caf2eddcd2247" },
                { "gn", "2dc849f032083cbd051c3f36d52553c541761c43ee58f41719c183b3cc698fe0790c744a45be64c1ed899ed67f7f52e59e64b8e0862310e618c9da88ae2c7e4f" },
                { "gu-IN", "9adb9670bfdde8ee387c0fca04b9e5410e4064eeb29e7dc73055724e16eaf4dc4ec55e17eb71bb4cf1782ec0cddb07d59ae1f3a529ba49950987c25e58518a61" },
                { "he", "242af08d802691ecbcdf22b818530e3e1d4f48ee409a301378186912601c922eb62ccf623970b8b47c72064d91158d5fe1f577f9f0cf3d0379cecde1324eecf7" },
                { "hi-IN", "7cefd031be3e7465c8d513f6251862570524a78ddd8faee11bcc64aa44e460cd3eb5fd44059787e979bba8f922f6e2452b168fa25c044c33eb7d036041db584f" },
                { "hr", "14459a323381efda04235177ffef984e22aa48998b731ee21317ea6fcf1b94e10e9ec34025db9e9aaaf69ac9bb01cd6c5b49c2b638b600d27698b9282dba8fc0" },
                { "hsb", "8c1dec9d978cb7bcd23b301c08ca3b9e059ce0cdb7406c4c150943dfcf4aabed5657f3974d0e92a17c994291090e6a3bb746208437521ed54f27707b6ac17023" },
                { "hu", "2ec188900449801851a1f3358f39b52bb2c4d64a268e9394f937e5b1877aba26a70630f63c5059c212facbb207ec46e777a47623814aef124eebde368ac8a579" },
                { "hy-AM", "31fc3c8f6e9dfb0ab90e499e4f1bb53ee3cc2cc958aa638c696d8e6bcbde3702fdb5c08bc1bcfabe4d2afbb8cc9e37d287526f96b05ff4631b3fbd55e577ea27" },
                { "ia", "c2e955443b9d484e0696b3e377d14c21e1b34629852f5c736f92d4a84cf18c7b50834905ad758bba7f38ac3b8ee4c3b787e3ce310bb4785ff2c744b336fabcff" },
                { "id", "a00647e3d99b993c30bc7e28c546de06a7575316745b07b6215e3f3bc53444aa6d0650a4550275cb253bbb74f1da43e5d04ad9f78655b83cfa3b67d0571c0e3d" },
                { "is", "c50e1c0a4261b89a67257ba46153b51122bf2eb9097c6514bb5f1bfa59a888a60fd6586bc0221ab4b2509bfc947f9a8aca0839e2854a8a9ec7159719f12a8b7d" },
                { "it", "f81832a1249fd4d95f0400e7c2ef952faca7992afb0bf4ed0e3247eb30730f648fb24980f8b30647dd7548ce42b612567af4203bd7231c10e47ca448406a4e34" },
                { "ja", "49763f377e22cf9a2ddf97d179108f10f17b3b2f28bcf58d607741ce7e6cd9e3d621cc190ae4557d6b6ea8d0e1ea831eda8399dc4cd834cce7ca9464d884f496" },
                { "ka", "3427b482b49b98d851cf27bfbf98da04dee714aaff51a750a9c0fc6d9dfd087051362eced6509bc3d9135996d8983b625dbdf3e7c0430b86300e6997277bc438" },
                { "kab", "f978f35e76fce2c4135d5e8591d2759a407b555b8e4229f67b86964630f5bdbc4a990043196518b72e23aa4e65db7a5d05f00d6d7ec008879fbb48cea9e9d220" },
                { "kk", "ff533d9bf898c15f18d27690670cead037ce73601af330f867c78c348eb4d25cca6985c091284be8c589e9e94749ef02c829ed9d0e46cd794bb92d5a54c034ea" },
                { "km", "b537178e2fa2f7ac0be2b2f3bbd8125ff41f3631fcacc9ef6b1f39da98be6273751bfb7730a7e147e6464d293d2192db220ec99bfa35848d222d4e196ae231c7" },
                { "kn", "fbac60430780dc19ec6c479b2c1fa988c69852681b3a617d467673dc137bdf089a0f26b60b46ffabb40ece2049c434444dcc52add4166deac283357f5e972f35" },
                { "ko", "de41cb20070b51982c06c7ec811c05c74bd32fa56f8411a33ca2130d6aeee8889792dd409799c11c89d86b89ec05e03757237b159dbfb0e61c1b6fb469a4c566" },
                { "lij", "26ec71001ed9debcfb97de8302de64d29ed76d7b9ab834c5dffeafc7810a3d23e6b91ba6a86f4a41b9156e00c49ec1dd1efbedadf02ee2e02f99b2faa077cbb5" },
                { "lt", "fab5138821025623e00c23fe8bd63e5644be030e56f2c269c6976176d2c1b4811d8e66dfa5fbbff4b09c3e654ff3a6e51318df95060be075654d1126e0461401" },
                { "lv", "f2a59a6be0377cd27d562e65f77df5bcb73b9ec0bff5b6c52941f7eb45e45ccf630b9a6d8fa9f2db882356b93f5e68b2ddeca90a3908066a12ab9c40a423b1e0" },
                { "mk", "9c8a65043f03e8ef49fcd87bfc00345f315eb5f66b59c8253f8f3ac666412dc24b31ecbe9b517cbc9463b2f3a3da1fcfa67b71731e324dfdf1979614f67f240e" },
                { "mr", "7e5b092283c85e13f592e8f4cac6fee64fc964688acf053bb0dd66b6bc57f7189d18a6d02dff8617e889264f1e77fc63dd7cd20159492790ffd94485aae139e5" },
                { "ms", "2736712a1510e2a0dc27617364077fba196f8dafed89832aa2a8e1abbb63159842638100fb443d15894beaf8c104871a75e4b4f81f9b0df196404866c65a4f34" },
                { "my", "555a73e06d8a882b8ddfc8c1919576756e95190ecb9eda96ef82fe093b8abc442a45eeb484d5e131d4857401516adda8b8705ae410afdcaf030458e705de891c" },
                { "nb-NO", "24f88fc894f4ba6229ce09f4b289f1fc437e1c25ad79ef81649ed6643ea5951eea53801719ef95c700e62acddbbb2cbf87081ccbb91fbbc94adb4c09befdd6b6" },
                { "ne-NP", "d7ecfd25b157171630ba2b408e7fafcb99f51e160c5711a7b0a3d53f4daf34d273239169706e49b1a5d3d90d7c342b52ac63fbe740cd10d847a985f57cad73ad" },
                { "nl", "8c32e061a1f56de076226d5c2bf9b6ea5a5afea87a09761932b5ccad5b60cd9e35cba88169fea099d60517cc192a9eda9b593667c713432c17a75d9afc96804d" },
                { "nn-NO", "4f5bc62f5b76014ffab736d0c58f4bd4a9b84bd43094eb5b08efd44bdc1f2ecc65616fad02ef7e62becf901b414589e37f061cad89f6c996881e9dd2b637f56f" },
                { "oc", "cc88e317be6fe3a2cd4ceeb06c70a24aa9954cb76b2db00d84f9dd77221518f7ec4b17382ff42b4f68538970f6ea66008744ab39307451a834f2f37ccb376703" },
                { "pa-IN", "e0e7262ae1ff380d40bc65da6baa39d33bd3d430d8957010e561759ec8a5ce2dabd61b17dbd5b5abb8646bfe0f219688fd6c458c9486cafa900eec1cffc31f10" },
                { "pl", "5ffb36f7a2cefc960d016b9d74872b03f45c5d3dc7d5969b1379229b298aa178f214eb3506c720d9af60a6740f08a4a18c2cd0148a8dcaa1d8c7b0a851aafe0f" },
                { "pt-BR", "dcfd536882fbf35e8354f55436731ec04d278fadea3e9d061df12aed72afb7371b9d4a2b3add2b29a23f7022a2898d84eabcd6deb4a0bfe39b6b3614c2b848b2" },
                { "pt-PT", "72a6a2eddcc0214ebacc7e85935d5e6e088c1b3529ad96d4f87bb001bd906cc7d00f18b98e868a7b6394ed68b575fb9f37f6a4f140b2f0594225dc205e2c842a" },
                { "rm", "67129fbcab245fffe1ae3d32cad4fd8d7080b5498458cdcb367e8e39f1e72be01ffed638bf83bbf7bac3e6a5bd56a71e50192f2529063c20c4d0662aa605a1e1" },
                { "ro", "58b9c0f2014264b5644d53b871d453039c069734abf4cc6d27c4bc237c25f9f11579681e9749488f8f3f4b2d65f512b6a23f3254f6d642ce3809b8914dfd4d5f" },
                { "ru", "2632c9568d534c8640014ea12c6f483ead8f24f6da27157d1185ec7cbd13e9f0164cd50d5d6f154bcc6a213d4718c5bf45f2e0d04a0a6d3d163194923fac25e9" },
                { "sat", "2516f6c000a259cfa35a675963903595af6bb2c7d51b75996bc70f239f90832cb1eb514967565ed3041ba4db700c7465227d22f0ef4c9f9d48c99218250f554f" },
                { "sc", "504afe5aec92a175310f976eb9dad0e5fcae3fdabe8fc6b74980dd4effa7c411348102a93db27949d8af917aa45795bfb7e7b2794b118883743a575ef0ce6604" },
                { "sco", "582d23014616c59b43e1bebcb85f04f5702e7a6ef3f8d83a0bf9b3c486dfb0163b310fd0c7ecd2e0cedadac347fe32c41e4b113132af92c4415790294f8dfa28" },
                { "si", "5aa7e403ffb3c1c56e998fdc4184222dad27209f81e7f82e75b453516b41cd528e1cb2258b35cfbe1b8348cb298c6de5dbc7c6e105dfb7fcbb5bf2d56fdbfa82" },
                { "sk", "4f20b7aca12f5072fbf367af49dcf9f17416bfa79e9fdf7e32de3d2103cbdf5e19cff64aa9b212879377f861d81692765386143188cf55cb35c5b8aff46cc349" },
                { "skr", "cb583264d9cc3ae66cca211e329b4460992d7ba348b88f36eb5fd79fdbddd34303d4fae5c18b1c4574b055a066b64d722b5f0169d78071f6852415a0a940d28f" },
                { "sl", "ade99cac4308d82840412cb3c0656153ab0983c113787c2cbdad0ad397d818e4167c93ab99873d22e2a6d9c18c6b76ac0ecfe7ddfc97e9eec3d8dc5daa28f987" },
                { "son", "1c91b7934f8363afb0b2dc3c48cd357cb8b399c4d05f53bddc478dbb652893e936cd81d8ba37b1fb00224a1c187e0d7a95751b6e251a781a3e11d9a4e591e945" },
                { "sq", "e28ef24b719e2f7c2d2a0be09992209a6ddaaeba9b9519fa0a7748777f5089d4bf0c81487479091ea31a6c1a95742aba6810e706b0c32fb7d353d39bfd20702d" },
                { "sr", "d1eaba99c9e904a5088442d2ef8f6d08c37fc167ac42d2f8518a6b50a31ec11328c418dadf3b6e91c7a6cd4ef15f22301e3b56cd04afbe97b9aa911121d5e32e" },
                { "sv-SE", "ac63f5bd580e96bdb18c5534316810027dfb86741a3dc5a68ff558bf59aec78194716f72ea76ac7958b5391cbc2ebad21f11acc561c598020454775dec3cccaf" },
                { "szl", "fff0b76dad662b9ed355d99de5fcc06ebeb9c1a9973bc8188361f60b6124d07302d24d9f425a1ef8019e22698180a3a4e160cd1c2d62412e07599fd359d53b00" },
                { "ta", "c6f5e1cbe968c8403eff44454c6820464c94c1d9c13475925d4400a9bc55b155de0877030b599f45f0b0a31e65c7f9b26d48a5e32e5e02b7a16ad794d9169efa" },
                { "te", "b0b28035de213cb7bcd714dfb16f1d1fa163e263080da7fd4f907f1e89fa4d4550d46d05b3207e95a73e0ffe5b6d78bfcd152342dc24f877975cf0c63dbc4887" },
                { "tg", "0a47f3f485049496a5a0a94713596b881df2df1289b17cd29b3a732118e3e3b73ef19f7149433f7c1d71155926f953e2f0e63d4807e6cf6115b1826e8725345c" },
                { "th", "406513988530b085200e4a87788ac24ee29d53da2ba7270de9810f833108d1037f56a566da6ca3ef7751e694062c06893d7c5bea6aeb4904af7c22e90cf10f0c" },
                { "tl", "58838f2e4d0450d2945f2d4138e004c37361e38692e485fb4d1d94ef45792146a03ee22a7a40730cfc7fd179f470d39c86dc5ee0d99ae810caa7f1af0b4d5e87" },
                { "tr", "f68a4c358908f96bdf78f318f905f16c990c115679df818c14ff64d002a36464435da1c0ead917b56de40d2433c5699470f6e5dbe164def8b4725bc74e40bde6" },
                { "trs", "a7b737629b0cbed99463e2c92b07e4d08618e77b24018d9764994bc63274e3528f5d620da354abbd385bbc8dbbd7303069099676f0801192279dd5ce7aa9e544" },
                { "uk", "832af281484401d4afaa73514d2f875b4d78a0dbd81f53e86236b934b732906e80a282185b2326a74755f78bf5f2a6d32e78d527463f0cd4ed886331b256ec61" },
                { "ur", "a3ea3950a4a7b0cdef8926d867d015235bb865b3a52e437ac60b56b65a09b3d44d1e5f43bea4cc877e8d08a3b69870800ffcc25b83a49f794d41a1a978c81460" },
                { "uz", "a67f42368c6ffdf213d7aed32adb7b7150acf3449a78a85a8fb9a0b632c4e7c87c39ea458072ae703d404b4a9296616eddeb2192e891b4b825af653ebbb054ad" },
                { "vi", "21f87087ed6ca497a2ad81e204e0e213a63b71b81bf48e3b8b367e85b68a11c95b9c3285a93776dbc1aa7c9d495d678ab40ddb63f6b87d5ee564988c0f677900" },
                { "xh", "202694f5ebd79cfbaa7997c750ceae64e71f5d33356a8a4e230a4389676d342592a9b900542e07ba7ec65150ac7b1b377ccd61b15c6b508b6e3f2ff60fc0e5e8" },
                { "zh-CN", "6e802ed6cfc071ef7f66bb72b34097b37868b4af7afa997f83568add1f165b2b269061229f9d29675949cf4ea1a5cfec4990484b1db63a1197ba3bdd4d040cb8" },
                { "zh-TW", "01fadf2bee5ec4dc2cf1f60f153a28fff70558b7b4ada17d700bc289466fbefd2247e80c5b9aa0ea4351ddeb2aeed6cf1524ff4fd18023782b845704cc1f20d0" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.9.1esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "7b9167db75c769afcca19f51c8e7c49c5e8f28daf0f55452c3219a104b8dbfc732725125c974b4002e6abcd31fd5b5fd569d433190757ad4cf8b997fa4eaf820" },
                { "af", "d6a2a0a39d87fd676ae5af05c0fd54c449b4617bcbc181327df0c972311c3cd3e15574cc4117250e1d7e8121380a62a001276c6a8c190321d00bc703c0df491d" },
                { "an", "c66c37a6017beb4171909b74c81d0290dc16d476e136309aadfe756170df16b2db1d19e8766886ee0a2d365571836ed5595a28341a4f80b4a25a2c950d232b3a" },
                { "ar", "b51b1d7e41623f9010a9341d698c5defc4c9cecaaa9c06bd64527e331747561d866070319c8caf11bb236f987a83130a8927ff293a3a0f1209f993e8003c4804" },
                { "ast", "a69b8ba95d639b4afdfa21387223b1f20fe139776de426a5c3d445a3f597e9b4b6423c2ce38c13a2b0790db3d83c7367f5aaf07ca34c6f11864f2cc553f420f1" },
                { "az", "5d3e453ddbc9f07aec6b3ff4b98cb4738d2695524839f22e717af43d7fd0ae8ebda457a442c29e26ec762aed53c4cb356a004b22223c1c12bc5b759b1c446d3d" },
                { "be", "0be22599dd32bfbb25afb796cef95712904a81d20b228d4ec1ed81c5a91f9689f6349324ba0c56ff67f0354ef5a5dad184c6e23d9698fb140d66b4803321ab65" },
                { "bg", "f9e5133dbc9c6a2d7c9d6e2b518137374340970059819a75c45809f64c15c388b8db6f919f0ee5fc688430c775dca761085513eccbb20f75d9be9a7addb349a6" },
                { "bn", "7b21ed0af852cf6be82c82d31368f6ea0b6a1a1e414416f08755efe0f85134d77ac7491002a3b3fb898f28ecfa5cd1d685932d9a10d3e3fb40fcd3f2a15bc596" },
                { "br", "f5c361d0661724b6b4b13a19be0a63127ebc818c79fd9bf086b76405af91482e4e56f99acabacdcae9b99635cc0ceabddd3fbe26e6da7a3afe7c4890489bdf8f" },
                { "bs", "737b229acd548e6eab865a31110a0d3871d7fc5e394e8a12fe7ea11e8ace8bb1c1a4dd6dea93c880b0367791402318df5d4e3c97805a23cec82a1468ef4c28d1" },
                { "ca", "9552afdbeeda58614702c78945f1cb4609d37fa4db8c7a982ec5c5f7d965dd990c4144cc3fc25be022f6ed89dd0fee4b8060f8043e61b7abd54cdd91605b79cc" },
                { "cak", "62a3bd69ad57417d2688979460bb70e07f201be204d2e89bf7fab74c75830caf081189521779cf143330b077d4812518402b9f7c4e0906b37317b9b98e490de1" },
                { "cs", "e997d78bbe6d1fccc7e2abfd169712c2ada2be48b8726e9059687ca9fa265d111eca79dfd654219fd8da99d86f662b214ca177ba93d80fbaba3ac2e0b3c2492e" },
                { "cy", "05753dca3e880d06271bbcba4692ec791838ff689e0cb7f089c0a1c5809d071dc140454457442faacf5fcf36ab5883ce1b483750d41c7921c9ec0074ab1e3c73" },
                { "da", "0ecac111d51c42d0c541400a414780fe96d2434192424250add117caf6e9e8a89e429a719d3ec060cfacd69f38c758ee90350496a8cf900ca5ee5c3168c177f0" },
                { "de", "3cce8a5535d401bdda0744aaa2af4290fe96ae9f035e040f394e38268ef795dad6a109388c8e235fa3e8893e12c97fa363265d3434b530528609bba06ad422f5" },
                { "dsb", "86e3f110d957c66117d65b1d3c7826fc3807225c5f3b0c126b8e1f58c5b134e305bea98177952cdba148c0b848c1278f0f361f73a26dba9cbf464718609164be" },
                { "el", "79a30dd39837baf0a0b343522462fda62a084dbfc5a981cbb69d1dc34dd574b6648bc8649638c38849b45e7f5113ada812810933b868b24ff569fcf473e04a43" },
                { "en-CA", "08b715c812a881d29c6e06086bf677629815b97c167e95c6fd0d7584a25ccc1834eedf7b767d53d980a7cdddf644d9e4f90def27ac57ef29af5e9a2c333603c1" },
                { "en-GB", "0a2296aac39e0511e94aa76df3671d1236dd4b6b282be029a26a335c1ef5ad033bdd93562c598d2f8ea065822ecbd4a28214ed3950cc90f2728f8abc69d7f4a3" },
                { "en-US", "33adb4143bd02e28c85578d3331d6e8645cf38a790ec724eb3c94baea917dda9c074e74b86df132e67a3fcf152a0404bb3aef5c3ecb738b45bebde226275f8fe" },
                { "eo", "941a0309f581648d68158301dd99dfaca3dc0d522ca58783d80dbdd4c3cadbca79960fb4a04b4eaf4ae57aa54e5ff04087c4821bb751cf1fe996620ce1247d18" },
                { "es-AR", "c7f28d00e4d475669f6451d6700254156fd8d5bdaf868ff4c8ed73418f790eff0aef92d0322ba8cf5cc6f01ea965a8b9d491f82f3361c2c4fa2000878e096790" },
                { "es-CL", "d3a0ae8a8bfebad53a5cc2a9f314514dc061c35890aa02c40443fcd3b79fdbe8da9d31a8b6257d0fb104e97baf5cc3f5964c4895600b132ef4458177d96a7aef" },
                { "es-ES", "0bb499f090ad00851f9692189b863eecf33bfbb6a5fd23ecde0bd8e00dba47b496f18fd4dd2fa94f081edaae4a44bbe9a9d83cb4ad1724fb921af737d3ac37f0" },
                { "es-MX", "3926056ffd32f5a05d66b59f7bd7f4db28865d680a97bb340eec94441a88ea2059885012e749a1b86715ae2ca2e702273bbcd108efede60a95dd55115061319d" },
                { "et", "9df5245394e6dd88d38ae9598ba5a1f05ba5005d7e2b09a88d3dedc1a2f39ce02675a5728c098af8b5fee162c1c9b1b631b551c8504b17da5b2e6228f54e3fb5" },
                { "eu", "0abf31d2adb06a6e2edb5f86824fc089ed5e3c651f48c89bdc2d2a21fe3838490807560e4391491a1a347ff245e11c44ac1bc57b51fce6116b379593d3af63d9" },
                { "fa", "dcd738642218fffa7bb4d7bcfc6f2c0fcba997302525c14f053046e6a0dbe0a0208f728934e3aab9c032ff622d75b949bad52d27cdfe28dbe50bd06cc97e48e0" },
                { "ff", "cdea37eaf1cb8899a7388019b647c71a75ba806458d937ad1d53b2b0d49cdae077f59674100147946e5935defc50347d7c2dfac3e9437a7ae2cd15471221aa6a" },
                { "fi", "7c6f4ad6247b19e34a58220ce2bc645d591ec0497505a3cab1ff3b9c486455d0e03a9ce1baa2f66ffc9b8026bc640d01729dbff4a5e41e135d256d7b125ee19c" },
                { "fr", "e80f18939879a7c63f5a0a5576a248782bba8a6866cb06ac68d29e18cdba11e5cef4db2ea5928c7f30347148f3ac560b37322bde1d8438d61bb563ce47fd29f9" },
                { "fur", "2c99f88c88d71365c9b8596e9023cbda7b7b0da64a571f2940f72b2be44f9ce3c152c2ea0f22270f5725fcfa06e184ba8d74c923df6296b1d3371298dcd99c95" },
                { "fy-NL", "89bdb3450e6ff69e5e5b4336adae3a94b29185b82ece63507b3aa1998b16001b2f89f42eb9fd4f0c3b1152bb043c56646df07634bdff09629c5dfe5cb9cbba1c" },
                { "ga-IE", "a700cf30eda3d230b1cf056562915dc084ff9c47287756303de6bba6b9916e77109f71de2401eb8aa07e2b0060ec786c82235fcd577adbdbd371d2b71512a186" },
                { "gd", "f7eac2d4f9fd2e936756efc105fd1807e352e449fe9c889903e16e30b3ab8e8d0c2a8bbc0bb6c333d52995b22b8c5e461094f94fb6527614be3715342e641bf5" },
                { "gl", "0d630cd1de014bb0580b27df4b8a93537d9dba55d45c57ca8035da9cec1464027a2a520ba3407dca4022b026180a0237f1619634c6bbdfe6f565f8ace4f426d9" },
                { "gn", "0ae6a595aad7ce95b6fd7ba67e2fbce719cc0c46bdef44509a81af548c8be8d5b19dfbdb2d309a448b2edba68dfcef6f1d558b83ece5bb8c66884d9e22ab5ed3" },
                { "gu-IN", "1cf2653bff91486b105a78c997abe896b1648e77a2785ab14c0d346339d339ed87e1d9167dc93e0a7cde1b17fa3dd9e9ffaf45272c3deefc3eedbe88a3b7e305" },
                { "he", "61a99586da630005c0dbee9237dc6e9c7dceeea1451141c12535e33c504bca1e44192e13597ea7048b1dc5efee297b7e98eb3b410589de4abe0a7f193345e35e" },
                { "hi-IN", "19ef8fc5823be7c7e6fbfa85e0921a6e8d92196ca008929a1bb62e2c736e9547ef1ba49df6160aa04f408174073157dc52f3e186c949b43acfc40f7742e6822a" },
                { "hr", "290bfd46b7bc976c6c69c317f1f9b5268f258c715ef55d8c9612c71bd5e64fdbbfe04b9c370bf315834445932d2f23bb079a0b32cb5e9ade50284e283ec3ea71" },
                { "hsb", "d10cd76125a8ca202eb515b302861601e0725527c1b4a2a69af020245d7b84c66e01c4cb5d283d1d3071a762c7e6c60099357203c84563098dfaf804bd30f176" },
                { "hu", "188abee04c8e4343319df89410c381bf1867922f22a26c2deeb1c7403c0fae4441fa85510806a9a876eba784b91674cb5d847716ac4ccbc561a4ec4abc44501b" },
                { "hy-AM", "b8f52d932f49ba45ed00661d9cf8fc9f64c9698b296525ce0e6641648a401dee56b8770cd0485bc78f63e559f9d3ab6f6022f3b068800db8a50e8390a63b8ca5" },
                { "ia", "551c7f4d4e24ad33ee5f56494a749017e9898cde484773d2488ed02f870fab359e3ac20c10f4de091fe21cc1ccab3cace1227e6677c74602edbb284954acf246" },
                { "id", "4ffa255351045f87f4ef174a849e1c651871f4b01e2403f86b80c4e1405a65cf4b342b8e5f183dc2bd50b3e61294dc192b081de015c269f07de57143afc7c904" },
                { "is", "09199ccec0a2e0ec41f5058a0d74d2c26b460ce17e6bf827eabfe23baaacf17c82dc653d9ae617f97dcaf3c8532662672993bc2cd3bd67de8f404d4a96ac8ebc" },
                { "it", "f324e130245ecf6f744d75529761b772d755c44e9136ff72706e098b462e23ee1d464a2a3c5bf054936e234c2a171fc57c8aef0bc8213f4355d13966b886abd8" },
                { "ja", "a5bd4aed5edf8fa278531949c37a879cac66bbbb97f888cbc66b8988cdbf05fdd83b2e6ff15860f8f1c6d91f7a851dbf43b50ca93ac25321ed699f074137bc16" },
                { "ka", "604c20c70f8db9f3e089ab5d1eae46646c6ddff5e7e5c045270dc455b1897c4cedba9a429524daa6849189dc18c7f1a9e486f2e049c3a42358299f2a72533276" },
                { "kab", "c5e9481bacc91f44b918a8f3f72994ff66778d749095f2788b85cadfeef7dccb315521a9ced09553b447f9815dabbd80507f7a9bc8093e9c36979b2bfe748d2f" },
                { "kk", "086594c1d679243b5470401798cf6350f0307b0ffe6d9647391d37a3188fc2429f20981980484bae6066d397a430e8bf1b5399e7aa6b1175542fe2e7d2026ed6" },
                { "km", "8575bf942999fdd3750841db15b10a48e9f0877ff11df07c47de0e89235c4c689f2f0b4da418327ad17b2f2869072c53b78f07836c70ef8c9baff19853972906" },
                { "kn", "43090924f2cf5003da944c16a3d87a07c35462ae8012a69ff96ed263d295b8f26413073a6d3449b646bb03ad3ed9262ff311a1f645d5927cdb80d351c756601b" },
                { "ko", "497fb60f9518a41b4885a344fbfa8c3179fa1bfdfcf32f84a32cec30e8df34e8e77bdb724bb746d64f099ff93bf708f79c2c890ca5a72a97eb4e6c4e31205314" },
                { "lij", "98eea8c70e8a1a6601af27a0bde5be15b6f8f2a44f82f6b8e666193360277ec0cf9f0abca905aebd560e8c2655bd31f0aee44812abbb3d127adcb9601841376b" },
                { "lt", "f45e6b2d7a3d106ca92460ffe30340aced309edf4ff639d050b0d6d910027fdf9864a91446fc1ed1240413105a1928f238196c805b249bbea63156b7fd3d2905" },
                { "lv", "0379ab5e0c8d88934da336a4f01232f3cad8fa9cff6bf9633ad78deebb96c03e5a1a88632ece59b4cf7a14b105f6059b77945382090a405e7a08853a996a0715" },
                { "mk", "9dfbc8ad5e0d6a75669463c0ba58b5e5f545b8551237cce32d5654b1e4248799c3cd1411325fc27252b033f521070d8720b735bf9ec84419edbed98d2125897f" },
                { "mr", "86e6aab367fe60cfa8c6a0e7ca4e201a4b69f431d112afd6053347406f99c0d0ed5d38ba591f0998490b7f8bb434f976208bc6c77ed69470acbc91708e4d755a" },
                { "ms", "18fae16ca85b9e8f08b54f01156268e4e76aeb6cd4a157e47c9d011b96e5502c2573ef3237ece29e4718889c8faa588484b1035a22c043b040f0b180a90219e7" },
                { "my", "69464cfa0331fa512ecd010c425d10fae5b143f08d8e6bca0fece58b72cb821ecd70f8f620ed345d883d1c5582d2d68d69dde1aa747cc17ed798f8bb027ce2da" },
                { "nb-NO", "bf27e9dc1a665169b0fc126a6369068ff8d3741827cce588a5ce781fc16012712f3f6725beae8c1abe72979c4b8a67a9aaa22efaafa681a4004f54e77385bf06" },
                { "ne-NP", "2f7238ee395c87dafdb49b8cf4dca84b2adbdc86ceeedf17e9a696009a14a50a53e1b5c5bd75cb6d8676225b99fe1338f2924a116b99359864f3cda1e7d087b9" },
                { "nl", "52bd2ebf498049f35f5631e91acab33e65710c2bc99fdee9e13c5849039279efb799e1c3ed2a9a7b0dbb192d449f680fe5a9b1b86e443b399026cf35df6769f0" },
                { "nn-NO", "5991fdf057db9d68efe72c17f8a21d47f14393027329c90d26f1f2820c81a0f5fcd500820b05448ac1d4ff97b205541509f40f64b219f90b4bc0b707ecd9528c" },
                { "oc", "76d42bf4abaf0ce8a03b52e84be00d65ad64871fca5bcc876297d78ae3925b2bc7f9aebc3ff25726cbd713f93cd1bf48f2f696a256b3d05ed403f9a4e20463ee" },
                { "pa-IN", "4e2b11723b9576ce79be4773d731f158b11817b81ea546836f98e0a34c11dc810adef8a543ea54c3dec01ea60bad0caa184d1728f26d3ca2fb953c6749eaca2b" },
                { "pl", "6d7e5831ab12f13bb11b99b361f64c79e2f9afdcfca768315deb9a945979cb87c421938cd45b6648542f8ecd7b875fab8ee01b18e9ee5f80af760780c61bab19" },
                { "pt-BR", "db02b6990c703ee91d250319f30ebd7a88c15f983598d3efb1debfcef33b8b32eb8353bc44627d8ea767c9b5719ffca0ce505b45f36e34cc26db8ccc835aa680" },
                { "pt-PT", "78acc0c0ffe2397a63779c6871bbe1015a9987835259de5d758fe9ff7595274dc74c41561126648ef43b3a6bb3117b7298ece4339666675546f6063b88fd30ae" },
                { "rm", "1ac790589d4b273fc296cdffb35c7951b362aa6b5a5d04dddce681440c30d810e3998b22c942e8c4866f91617b2fb6a61ee947783b14e8d0d242d48f0d8977f3" },
                { "ro", "809b7b221673342781bc820aec6abe0268764cf88a999633a072b8be6c7a558a9881a0d62bb1f5303eaa3260f0a58b285266a27192d4a8da8d1976783a1dd65d" },
                { "ru", "0ea684f886babef1e0d2829813acde57734509d9f14fa5d00f6c970d1480a8dc96a0401f00caa7c37c00ea159547b7eecac5dba0df4c83f0f3b7a31086949ef1" },
                { "sat", "62558f23b7162e5982552287879306dbaaae6f2f4f0ddf71cbf6ca20077b0b60da3264cfe97146a189c88e2ac28228c1183c6ff0ebc52654c5cd695dcd1cc347" },
                { "sc", "b947a0f284d4eef1e4f6930234f5a551dc3fb177162f32c28f2a4d68519700d2a837e9fd6f525a98fa45149dbd0999192b6313ad688633baada2d7fcf459959c" },
                { "sco", "06c0a8c38e6e2973f67e28b382807dcb6bc5f116b16745dbb6e9a3319f0533d36279360f9fd227fa46245b0e4925437ec386b396e4f85519a940eab5f41a7520" },
                { "si", "43564ed5b5c525a60f1b0e24203449d9606ce9628f3d3df09375315ee00df96d27881c522396a3c4fdb660230eae11f63b73f4e2df27eb45dcc3839f06310085" },
                { "sk", "9c689ac74e54f965577851aec7b05153665acca59a3b95922ae2eceb6cc043c67f3e897a6786fabc1f81d560ef28bda8495a7b054f6193430a691ded98d54780" },
                { "skr", "10d88a7afbb4004ab4c467636234f9619dc27b2d3861e71593574988cb864bdb24113eb70998af6e0f64d0e9d74ccf82c2b5f41a71fc1dee7b0c9b5e292e89a5" },
                { "sl", "62c9234593513544e2d173ae81fa60d5c71488d36da1d5b79166a5097e2bd3ff8b5ccd1cfbf8d562bb9cf2ceb2411310020e3efe77500c56955fffb64b305c19" },
                { "son", "758f694480dfa19e22e9fb9f7df07228e14b7f43ca496f50e30c8f744e37667ca7104791ccb6797d22d53ca05e713a5254f505c154a0278fe63d6914ec0f8ddd" },
                { "sq", "c8888f9a498d6b1749346ded3bed9edf662aa41548b5adfa561993cf44a76ade6aa4efebf887c48453d609c7dfa3610e9d014785ff87259b3faf0626345bff5b" },
                { "sr", "a3ee9e44832e0cffa8bbed70f59e47b6cc25a1d4c803915ddbad2a9bfa257bc5fb6d0ae69005ddcc1c63618644d6aec191e0746cf7796ea5d72572b4bfc071d3" },
                { "sv-SE", "75e627ae3fc8f2685fc9af400a23e4df88bf1f23bf552ff2f96cb4c0f90d5c6e15252063e533d7e6274dbe438f2b1985764a12c16a932ba381e4d3f6ea2e3ec6" },
                { "szl", "bf08348325ed14dd623dc7dba6e341a4d46b4899782fca39a10611d0bba6b387286e2d2906cb237b0d344639c54e172e906e447ce9002a5d3b8f4bd886529c85" },
                { "ta", "b61ec653d8f0ad7a80f17a003e09485939702c8f9350c3dba6f58af2316f7afc1c34f968e4edfc873ebb3b4b5ec9133f5075a13c3c12f0dac4379634a7855a57" },
                { "te", "c928b6bc551f87e7c5e55838c975160b0d81c9c7eb69346e9c483d0b684df3f7ff0b3a1d0edf30bba7ee60bd9b5a85d993e7284d68206bf00bc0d319c84a9a08" },
                { "tg", "2cf4f180930de1dbb9dacec1c0f474d56f28f4631df4e6fbdea690748a4befb98b92274b475c0327319ad6ba085d1583c5ade7ed132412d6fd2c8653b6a04b67" },
                { "th", "eec94d38fa19430ff66cab949bf1d392d7e10325342d379b4e3a271ddc67cd7639d356b517e107a5c87f6040bfbe3daf68905eafc7df3d82783c9bb165647e76" },
                { "tl", "60d89a7e287c5c17ef40e0030bff3cfa17d86228b16ccb5b4ab44dfea3c91206658c19f1149ace6c89d03317ea74374d82ae14ed1f6f34ff29878db4fb3868c5" },
                { "tr", "6d606f9e483e03b8ce2a6c6456b18df57e4d5650f43ea72ba7f5b3c4b3caf351563e10f21f65f4a33f89e6563bf41119acbd5dcc99a154198968439298fc72ed" },
                { "trs", "d47622d41bc0584ea1703a11523a647e66ef28d07bf9bff0afabea7b88dee51387d27105c426f0d15d3cf415a42182e47ead11f8424bd9284dd7d81a20d47485" },
                { "uk", "001953f144c69bd40de5eb20b22de0553c56282522c298c011fdf43d359ec3517347f5f137fa390d180233276bd72e3f8104942deb7ce8510f2cf7d9a446ba5a" },
                { "ur", "fede703608b229c0303e4c307bc01f5286ec6679aa5abc8e032745263dce0c2bef2a1dd74decd23d56a7924ca387b347241a05fa9946637653cb00f75f66eef7" },
                { "uz", "e79e3ab3c0314fb445ccdfe8f75360aacd4688229beda14100bdbe300b9d010313b54c69948caf19d47902e53f5be3c4156bc3a80375be66a3b8a7f1c817937d" },
                { "vi", "ffe659c6620c26eaaf86ee9b24e678288746163032b6c05c1457c77a42e4c0a50e9eeb8c6d3908d072abd41a15b763658225ec530e18493b5a4b740c74cc8886" },
                { "xh", "8c893c2f87f03ce254ce7b34c952e874253976e29cd159ec3e75d86dab7497a06cbb329bc6995370698ae708c55fdfb30a32b0c14f74e209fdb1645be9e8de78" },
                { "zh-CN", "7ed7846f08b5cd56d1c4a8a67c1a4f2916b173466dd30a9aef7cbc31e403ebebbc100be84f242b7d88a76f4f2cda02ba452f85add27aec72d5bc61f1c0893e1b" },
                { "zh-TW", "4416cd197d54cce7add0bfdc3d1f9b8e40f017d3b879d33479aba4bc38b88c7a3e5e13a4ac8283dd34b8902cbe4fceb8329b039c5f77b22514b4e8ad0586614c" }
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
